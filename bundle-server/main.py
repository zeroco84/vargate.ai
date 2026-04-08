"""
Vargate OPA Bundle Server
Serves policy bundles to OPA over HTTP with ETag-based polling.
Reads .rego files from the /policies directory (mounted from repo).
"""

import hashlib
import io
import json
import os
import tarfile
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, Response, HTTPException
from pydantic import BaseModel

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Bundle Server", version="0.3.0")

# ── Policy source directory ──────────────────────────────────────────────────

POLICY_DIR = os.environ.get("POLICY_DIR", "/policies")

# ── Bundle state ─────────────────────────────────────────────────────────────

class BundleState:
    def __init__(self):
        self.revision: str = f"v1.0.0-{int(time.time())}"
        self.etag: str = ""
        self.last_updated: str = datetime.now(timezone.utc).isoformat()
        self.bundle_bytes: bytes = b""
        self.archive_dir: str = os.environ.get("BUNDLE_ARCHIVE_DIR", "/data/archive")
        self.rego_files: dict[str, str] = {}  # relative path -> content
        os.makedirs(self.archive_dir, exist_ok=True)
        self._rebuild()

    def _read_rego_files(self) -> dict[str, str]:
        """Read all .rego files from the policy source directory."""
        files = {}
        if not os.path.isdir(POLICY_DIR):
            print(f"[BUNDLE] WARNING: Policy directory {POLICY_DIR} not found", flush=True)
            return files

        for root, dirs, filenames in os.walk(POLICY_DIR):
            for fname in sorted(filenames):
                if fname.endswith(".rego"):
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, POLICY_DIR)
                    try:
                        with open(full_path, "r") as f:
                            files[rel_path] = f.read()
                        print(f"[BUNDLE] Loaded {rel_path} ({len(files[rel_path])} bytes)", flush=True)
                    except Exception as e:
                        print(f"[BUNDLE] ERROR reading {full_path}: {e}", flush=True)
        return files

    def _generate_manifest(self) -> str:
        """Generate the .manifest JSON."""
        return json.dumps({
            "revision": self.revision,
            "roots": ["vargate"],
        }, indent=2)

    def _rebuild(self):
        """Rebuild the tar.gz bundle from .rego files on disk."""
        self.rego_files = self._read_rego_files()

        if not self.rego_files:
            print("[BUNDLE] WARNING: No .rego files found — bundle will be empty", flush=True)

        manifest_content = self._generate_manifest()

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Add each .rego file
            for rel_path, content in sorted(self.rego_files.items()):
                rego_bytes = content.encode("utf-8")
                info = tarfile.TarInfo(name=rel_path)
                info.size = len(rego_bytes)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(rego_bytes))

            # Add .manifest
            manifest_bytes = manifest_content.encode("utf-8")
            info = tarfile.TarInfo(name=".manifest")
            info.size = len(manifest_bytes)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(manifest_bytes))

        self.bundle_bytes = buf.getvalue()
        self.etag = hashlib.sha256(self.bundle_bytes).hexdigest()[:16]
        self.last_updated = datetime.now(timezone.utc).isoformat()

        # Archive the bundle by revision
        archive_path = os.path.join(self.archive_dir, f"{self.revision}.tar.gz")
        with open(archive_path, "wb") as f:
            f.write(self.bundle_bytes)

        # Count rules for status reporting
        rule_count = 0
        for content in self.rego_files.values():
            rule_count += content.count("violations contains msg if")
            rule_count += content.count("requires_human_approval if")

        print(
            f"[BUNDLE] Rebuilt bundle: revision={self.revision} "
            f"etag={self.etag} files={list(self.rego_files.keys())} "
            f"rules={rule_count} archived={archive_path}",
            flush=True,
        )

    def update(self):
        """Increment revision and rebuild the bundle from disk."""
        self.revision = f"v1.0.0-{int(time.time())}"
        self._rebuild()

    @property
    def rule_count(self) -> int:
        count = 0
        for content in self.rego_files.values():
            count += content.count("violations contains msg if")
            count += content.count("requires_human_approval if")
        return count


# Global bundle state
bundle = BundleState()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/bundles/vargate")
async def get_bundle(
    response: Response,
    if_none_match: Optional[str] = Header(None),
):
    """Serve the policy bundle to OPA. Supports ETag polling."""
    current_etag = f'"{bundle.etag}"'

    if if_none_match and if_none_match.strip('"') == bundle.etag:
        return Response(status_code=304)

    return Response(
        content=bundle.bundle_bytes,
        media_type="application/gzip",
        headers={
            "ETag": current_etag,
            "Content-Disposition": "attachment; filename=bundle.tar.gz",
        },
    )


@app.get("/bundles/vargate/status")
async def bundle_status():
    """Return current bundle status."""
    return {
        "revision": bundle.revision,
        "etag": bundle.etag,
        "rule_count": bundle.rule_count,
        "last_updated": bundle.last_updated,
        "files": list(bundle.rego_files.keys()),
    }


@app.post("/bundles/vargate/reload")
async def reload_bundle():
    """Reload the bundle from disk (re-read .rego files)."""
    old_revision = bundle.revision
    bundle.update()
    return {
        "status": "reloaded",
        "old_revision": old_revision,
        "new_revision": bundle.revision,
        "files": list(bundle.rego_files.keys()),
        "rule_count": bundle.rule_count,
    }


@app.get("/bundles/vargate/archive/list")
async def archive_list():
    """List all archived bundle revisions."""
    revisions = []
    for fname in sorted(os.listdir(bundle.archive_dir)):
        if fname.endswith(".tar.gz"):
            revisions.append(fname.replace(".tar.gz", ""))
    return {"revisions": revisions, "count": len(revisions)}


@app.get("/bundles/vargate/archive/{revision}")
async def archive_get(revision: str):
    """Retrieve an archived bundle by revision string."""
    archive_path = os.path.join(bundle.archive_dir, f"{revision}.tar.gz")
    if not os.path.exists(archive_path):
        raise HTTPException(404, f"Bundle revision {revision} not found in archive")
    with open(archive_path, "rb") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={revision}.tar.gz"},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vargate-bundle-server"}
