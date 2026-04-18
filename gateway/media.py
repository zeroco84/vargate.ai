"""
Vargate Media Hosting (Sprint 15)

Public image hosting for agent-generated content that needs a public URL
(e.g. Instagram's Content Publishing API fetches images from a URL).

  POST /api/v1/media/upload — authenticated multipart upload
  Host nginx serves /media/<tenant>/<YYYY-MM>/<uuid>.jpg publicly.

Files are auto-deleted after MEDIA_RETENTION_HOURS (default 48h) by a
background task. That's enough for the approval-to-publish window — once
Instagram fetches the image, it lives on Meta's CDN and our copy is
no longer needed.

Validation:
  - requires tenant auth (Bearer token or X-API-Key)
  - max 8 MB (Instagram's published limit)
  - JPEG only (Meta rejects PNG/WebP for feed posts); verified by magic
    bytes, not just Content-Type
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Header, HTTPException, UploadFile

MEDIA_ROOT = Path(os.environ.get("MEDIA_ROOT", "/app/media_uploads"))
MEDIA_RETENTION_HOURS = int(os.environ.get("MEDIA_RETENTION_HOURS", "48"))
MEDIA_MAX_BYTES = 8 * 1024 * 1024  # 8 MB — Instagram feed-post limit
MEDIA_PUBLIC_BASE = os.environ.get(
    "MEDIA_PUBLIC_BASE", "https://vargate.ai/media"
).rstrip("/")

# Magic bytes for image format detection
_JPEG_MAGIC = b"\xff\xd8\xff"

# Router prefix is gateway-internal; host nginx strips /api/ before proxying,
# so the externally-visible path is https://vargate.ai/api/v1/media/upload.
router = APIRouter(prefix="/v1/media", tags=["Media"])


def _ensure_media_root():
    MEDIA_ROOT.mkdir(parents=True, exist_ok=True)


def _tenant_dir(tenant_id: str) -> Path:
    # tenant_id is already a UUID-like string; use it directly as a
    # path component. Month buckets keep directories scannable.
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    d = MEDIA_ROOT / tenant_id / month
    d.mkdir(parents=True, exist_ok=True)
    return d


@router.post("/upload")
async def upload_media(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
):
    """Store a JPEG on disk and return a public URL.

    The public URL is served by host nginx; this endpoint only writes the
    file and records the upload in the audit trail.
    """
    # Late import to avoid circular dependency with main.py
    import main

    tenant = await main.get_session_tenant(authorization, x_api_key, None)
    if tenant.get("is_public_viewer"):
        raise HTTPException(403, "Public viewers cannot upload media")

    # Read with cap — bail as soon as we exceed the limit
    data = bytearray()
    chunk_size = 64 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MEDIA_MAX_BYTES:
            raise HTTPException(
                413,
                f"File exceeds {MEDIA_MAX_BYTES // (1024 * 1024)} MB limit",
            )

    if len(data) < len(_JPEG_MAGIC):
        raise HTTPException(400, "Empty or truncated file")

    if not bytes(data[: len(_JPEG_MAGIC)]) == _JPEG_MAGIC:
        raise HTTPException(
            400,
            "Only JPEG is accepted. Instagram rejects PNG/WebP for feed posts.",
        )

    _ensure_media_root()
    tenant_id = tenant["tenant_id"]
    target_dir = _tenant_dir(tenant_id)
    filename = f"{uuid.uuid4().hex}.jpg"
    target_path = target_dir / filename
    target_path.write_bytes(bytes(data))

    # Build the public URL
    month = target_dir.name
    public_url = f"{MEDIA_PUBLIC_BASE}/{tenant_id}/{month}/{filename}"

    # Record in audit trail for traceability
    try:
        conn = main.get_db()
        main.write_audit_record(
            conn,
            action_id=f"media-{filename.rsplit('.', 1)[0]}",
            agent_id="media-upload",
            tool="vargate_media",
            method="upload",
            params={
                "size_bytes": len(data),
                "content_type": "image/jpeg",
                "public_url": public_url,
            },
            requested_at=datetime.now(timezone.utc).isoformat(),
            decision="allow",
            violations=[],
            severity="none",
            alert_tier="none",
            tenant_id=tenant_id,
        )
        conn.close()
    except Exception as e:
        # Don't fail the upload if audit write has a hiccup — log and move on
        print(f"[MEDIA] audit write failed: {e}", flush=True)

    return {
        "url": public_url,
        "size_bytes": len(data),
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=MEDIA_RETENTION_HOURS)
        ).isoformat(),
    }


# ── Cleanup background task ───────────────────────────────────────────────


async def _cleanup_loop():
    """Delete files older than MEDIA_RETENTION_HOURS. Runs forever."""
    interval_seconds = 3600  # hourly
    while True:
        try:
            _run_cleanup_once()
        except Exception as e:
            print(f"[MEDIA-CLEANUP] error: {e}", flush=True)
        await asyncio.sleep(interval_seconds)


def _run_cleanup_once():
    if not MEDIA_ROOT.exists():
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (MEDIA_RETENTION_HOURS * 3600)
    deleted = 0
    for path in MEDIA_ROOT.rglob("*.jpg"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                deleted += 1
        except FileNotFoundError:
            continue
    # Prune empty month directories
    for month_dir in MEDIA_ROOT.glob("*/*"):
        if month_dir.is_dir() and not any(month_dir.iterdir()):
            month_dir.rmdir()
    if deleted:
        print(
            f"[MEDIA-CLEANUP] deleted {deleted} files older than "
            f"{MEDIA_RETENTION_HOURS}h",
            flush=True,
        )


def start_cleanup_task(loop=None):
    """Kick off the cleanup task — call once from main.py startup."""
    _ensure_media_root()
    asyncio.create_task(_cleanup_loop())
