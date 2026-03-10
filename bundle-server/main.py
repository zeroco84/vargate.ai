"""
Vargate OPA Bundle Server
Serves policy bundles to OPA over HTTP with ETag-based polling.
Supports live policy hot-swap via update endpoint.
"""

import hashlib
import io
import json
import os
import tarfile
import time
import copy
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, Response, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Bundle Server", version="0.2.0")

# ── Default policy template ─────────────────────────────────────────────────

DEFAULT_COMPETITOR_DOMAINS = ["rival.com", "competitor.com", "acmecorp.com"]
DEFAULT_HIGH_VALUE_THRESHOLD = 5000
DEFAULT_HIGH_VALUE_OOH_THRESHOLD = 1000

# ── Bundle state ─────────────────────────────────────────────────────────────

class BundleState:
    def __init__(self):
        self.competitor_domains: list[str] = list(DEFAULT_COMPETITOR_DOMAINS)
        self.high_value_threshold: int = DEFAULT_HIGH_VALUE_THRESHOLD
        self.high_value_ooh_threshold: int = DEFAULT_HIGH_VALUE_OOH_THRESHOLD
        self.revision: str = f"v1.0.0-{int(time.time())}"
        self.etag: str = ""
        self.last_updated: str = datetime.now(timezone.utc).isoformat()
        self.bundle_bytes: bytes = b""
        self._rebuild()

    def _generate_rego(self) -> str:
        """Generate the Rego policy file from current state."""
        # Build the competitor domains set literal
        domains_str = ", ".join(f'"{d}"' for d in sorted(self.competitor_domains))

        return f'''package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── Structured decision object returned to the gateway ──────────────────────

decision := {{
    "allow":           allow,
    "violations":      violations,
    "severity":        severity,
    "requires_human":  requires_human_approval,
    "alert_tier":      alert_tier,
}}

default allow := false
allow if {{ count(violations) == 0 }}

default requires_human_approval := false

# ── Violation rules ──────────────────────────────────────────────────────────

# Block high-value transactions without approval
violations contains msg if {{
    input.action.params.amount >= {self.high_value_threshold}
    not input.context.approval.granted
    msg := "high_value_transaction_unapproved"
}}

# Block emails to competitor domains
violations contains msg if {{
    input.action.tool == "gmail"
    input.action.method == "send_email"
    competitor_domains := {{{domains_str}}}
    some domain in competitor_domains
    endswith(input.action.params.to, domain)
    msg := "competitor_contact_attempt"
}}

# Block unmasked PII leaving EU
violations contains msg if {{
    input.agent.jurisdiction == "EU"
    input.data.contains_pii == true
    input.data.pii_types[_] == "email"
    input.data.residency_required == "EU"
    input.action.params.destination_region != "eu-west-1"
    msg := "gdpr_pii_residency_violation"
}}

# Block anomalous behaviour
violations contains msg if {{
    input.history.anomaly_score > 0.7
    msg := "anomaly_score_threshold_exceeded"
}}

# Block out-of-hours high-risk actions
violations contains msg if {{
    input.context.is_business_hours == false
    input.action.params.amount >= {self.high_value_ooh_threshold}
    msg := "high_value_out_of_hours"
}}

# ── Severity derivation (else chain to avoid recursion) ──────────────────────

is_critical if {{ "competitor_contact_attempt" in violations }}
is_critical if {{ "gdpr_pii_residency_violation" in violations }}

is_high if {{
    "high_value_transaction_unapproved" in violations
    not is_critical
}}

severity := "critical" if {{
    is_critical
}} else := "high" if {{
    is_high
}} else := "medium" if {{
    count(violations) > 0
}} else := "none"

# ── Alert routing ────────────────────────────────────────────────────────────

alert_tier := "soc_page" if {{
    severity == "critical"
}} else := "soc_ticket" if {{
    severity == "high"
}} else := "slack_alert" if {{
    severity == "medium"
}} else := "none"

# ── Human approval requirement ───────────────────────────────────────────────

requires_human_approval if {{ input.action.params.amount >= {self.high_value_threshold} }}
'''

    def _generate_manifest(self) -> str:
        """Generate the .manifest JSON."""
        return json.dumps({
            "revision": self.revision,
            "roots": ["vargate"],
        }, indent=2)

    def _rebuild(self):
        """Rebuild the tar.gz bundle from current state."""
        rego_content = self._generate_rego()
        manifest_content = self._generate_manifest()

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Add vargate/policy.rego
            rego_bytes = rego_content.encode("utf-8")
            info = tarfile.TarInfo(name="vargate/policy.rego")
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

        print(
            f"[BUNDLE] Rebuilt bundle: revision={self.revision} "
            f"etag={self.etag} domains={self.competitor_domains} "
            f"threshold={self.high_value_threshold}",
            flush=True,
        )

    def update(self):
        """Increment revision and rebuild the bundle."""
        self.revision = f"v1.0.0-{int(time.time())}"
        self._rebuild()

    @property
    def rule_count(self) -> int:
        return 5   # 5 violation rules


# Global bundle state
bundle = BundleState()


# ── Request models ───────────────────────────────────────────────────────────

class UpdateRequest(BaseModel):
    operation: str
    domain: Optional[str] = None
    threshold: Optional[int] = None


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
        "competitor_domains": bundle.competitor_domains,
        "high_value_threshold": bundle.high_value_threshold,
    }


@app.post("/bundles/vargate/update")
async def update_bundle(req: UpdateRequest):
    """Apply an incremental policy update and regenerate the bundle."""
    old_revision = bundle.revision

    if req.operation == "add_competitor_domain":
        if not req.domain:
            raise HTTPException(400, "domain is required for add_competitor_domain")
        if req.domain in bundle.competitor_domains:
            raise HTTPException(409, f"{req.domain} already in blocklist")
        bundle.competitor_domains.append(req.domain)
        bundle.update()
        return {
            "status": "updated",
            "operation": req.operation,
            "domain": req.domain,
            "old_revision": old_revision,
            "new_revision": bundle.revision,
        }

    elif req.operation == "remove_competitor_domain":
        if not req.domain:
            raise HTTPException(400, "domain is required for remove_competitor_domain")
        if req.domain not in bundle.competitor_domains:
            raise HTTPException(404, f"{req.domain} not in blocklist")
        bundle.competitor_domains.remove(req.domain)
        bundle.update()
        return {
            "status": "updated",
            "operation": req.operation,
            "domain": req.domain,
            "old_revision": old_revision,
            "new_revision": bundle.revision,
        }

    elif req.operation == "set_high_value_threshold":
        if req.threshold is None:
            raise HTTPException(400, "threshold is required for set_high_value_threshold")
        bundle.high_value_threshold = req.threshold
        bundle.update()
        return {
            "status": "updated",
            "operation": req.operation,
            "threshold": req.threshold,
            "old_revision": old_revision,
            "new_revision": bundle.revision,
        }

    elif req.operation == "restore_defaults":
        bundle.competitor_domains = list(DEFAULT_COMPETITOR_DOMAINS)
        bundle.high_value_threshold = DEFAULT_HIGH_VALUE_THRESHOLD
        bundle.high_value_ooh_threshold = DEFAULT_HIGH_VALUE_OOH_THRESHOLD
        bundle.update()
        return {
            "status": "restored",
            "operation": req.operation,
            "old_revision": old_revision,
            "new_revision": bundle.revision,
        }

    else:
        raise HTTPException(400, f"Unknown operation: {req.operation}")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vargate-bundle-server"}
