"""
Audit routes: audit log, chain verification, tamper simulation, erasure,
subjects, policy replay, HSM proxy, and credential vault endpoints.
Extracted from main.py for maintainability (Audit Item 14).

NOTE: Uses late imports of `main` module inside handlers to avoid circular
imports. main.py includes this router at the bottom, after all helpers
are defined.
"""

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel

router = APIRouter()


# ── Pydantic models ──────────────────────────────────────────────────────────


class TamperRequest(BaseModel):
    record_number: int


class RegisterCredentialRequest(BaseModel):
    tool_id: str
    name: str
    value: str  # SECURITY: passes through to HSM, never stored in gateway


class ReplayRequest(BaseModel):
    action_id: Optional[str] = None
    record_number: Optional[int] = None
    last_block: bool = False


class BulkReplayRequest(BaseModel):
    count: int = 10


# ── Audit log & verification ────────────────────────────────────────────────


@router.get("/audit/verify", tags=["Audit"])
async def audit_verify(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Verify the hash chain integrity of the tenant's audit log."""
    import main

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        result = main.verify_chain_integrity(conn, tenant_id=tenant["tenant_id"])
    finally:
        conn.close()
    return result


@router.get("/audit/log", tags=["Audit"])
async def audit_log(
    limit: int = Query(default=200, le=1000),
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Retrieve recent audit log records for the authenticated tenant."""
    import main

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
            (tenant["tenant_id"], limit),
        ).fetchall()
    finally:
        conn.close()

    records = []
    for r in rows:
        rec = {
            "id": r["id"],
            "action_id": r["action_id"],
            "agent_id": r["agent_id"],
            "tool": r["tool"],
            "method": r["method"],
            "params": json.loads(r["params"]),
            "requested_at": (
                r["requested_at"] if "requested_at" in r.keys() else r["created_at"]
            ),
            "decision": r["decision"],
            "violations": json.loads(r["violations"]),
            "severity": r["severity"],
            "alert_tier": r["alert_tier"],
            "bundle_revision": r["bundle_revision"],
            "prev_hash": r["prev_hash"],
            "record_hash": r["record_hash"],
            "created_at": r["created_at"],
            "evaluation_pass": r["evaluation_pass"],
            "anomaly_score_at_eval": r["anomaly_score_at_eval"],
            "contains_pii": bool(r["contains_pii"]),
            "pii_subject_id": r["pii_subject_id"],
            "pii_fields": json.loads(r["pii_fields"]) if r["pii_fields"] else None,
            "erasure_status": r["erasure_status"],
            "execution_mode": r["execution_mode"],
            "source": r["source"] if "source" in r.keys() else "direct",
            "managed_session_id": (
                r["managed_session_id"] if "managed_session_id" in r.keys() else None
            ),
        }
        records.append(rec)

    return {"records": records, "count": len(records), "tenant_id": tenant["tenant_id"]}


# ── Tamper simulation endpoints (DEMO ONLY) ─────────────────────────────────


@router.post("/audit/tamper-simulate", tags=["Audit"])  # DEMO ONLY
async def tamper_simulate(
    req: TamperRequest,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """DEMO ONLY: Simulate tampering with an audit record to demonstrate chain verification."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        row = conn.execute(
            "SELECT id, action_id, record_hash FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET ?",
            (req.record_number - 1,),
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Record #{req.record_number} not found")

        record_id = row["id"]
        original_hash = row["record_hash"]
        main._tamper_store[record_id] = original_hash

        fake_hash = secrets.token_hex(32)
        conn.execute(
            "UPDATE audit_log SET record_hash = ? WHERE id = ?",
            (fake_hash, record_id),
        )
        conn.commit()

        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        affected = total - req.record_number + 1

        return {
            "tampered_record_number": req.record_number,
            "tampered_action_id": row["action_id"],
            "records_affected": affected,
            "message": f"Record corrupted. Chain broken from record {req.record_number} onward.",
        }
    finally:
        conn.close()


@router.post("/audit/tamper-restore", tags=["Audit"])  # DEMO ONLY
async def tamper_restore(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """DEMO ONLY: Restore tampered records to their original hashes."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        for record_id, original_hash in main._tamper_store.items():
            conn.execute(
                "UPDATE audit_log SET record_hash = ? WHERE id = ?",
                (original_hash, record_id),
            )
        conn.commit()
        main._tamper_store.clear()

        result = main.verify_chain_integrity(conn)
        return {
            "restored": True,
            "chain_valid": result.get("valid", False),
            "record_count": result.get("record_count", 0),
        }
    finally:
        conn.close()


# ── Crypto-shredding / Erasure endpoints ────────────────────────────────────


@router.post("/audit/erase/{subject_id}", tags=["Audit"])
async def erase_subject(
    subject_id: str,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """GDPR right-to-erasure: delete the subject's HSM key, making encrypted PII irrecoverable."""
    import main
    from rate_limit import enforce_ip_rate_limit

    await enforce_ip_rate_limit(
        main.redis_pool, request, "erasure", max_requests=5, window_seconds=60
    )
    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    # GDPR right-to-erasure: delete the subject's HSM key and mark records.
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{main.HSM_URL}/keys/{subject_id}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No key found for subject {subject_id}")
        hsm_result = resp.json()

    erasure_certificate = hsm_result.get("erasure_certificate", "")
    erased_at = hsm_result.get("erased_at", datetime.now(timezone.utc).isoformat())

    conn = main.get_db()
    try:
        cursor = conn.execute(
            "UPDATE audit_log SET erasure_status = 'erased' WHERE pii_subject_id = ?",
            (subject_id,),
        )
        records_affected = cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    print(
        f"[ERASURE] Subject {subject_id}: key deleted, "
        f"{records_affected} records marked erased. "
        f"Certificate: {erasure_certificate[:16]}...",
        flush=True,
    )

    return {
        "subject_id": subject_id,
        "records_affected": records_affected,
        "erasure_certificate": erasure_certificate,
        "erased_at": erased_at,
        "interpretation": (
            f"Key deleted. {records_affected} audit records contain encrypted PII "
            f"for this subject. The ciphertext fields are now irrecoverable. "
            f"Record count and hash chain integrity are preserved."
        ),
    }


@router.get("/audit/erase/{subject_id}/verify", tags=["Audit"])
async def verify_erasure(
    subject_id: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Verify that crypto-shredding was successful for a given subject."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    # Attempt to decrypt PII after erasure — should fail.
    conn = main.get_db()
    try:
        row = conn.execute(
            "SELECT params, pii_fields FROM audit_log WHERE pii_subject_id = ? LIMIT 1",
            (subject_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(404, f"No records found for subject {subject_id}")

    pii_fields = json.loads(row["pii_fields"]) if row["pii_fields"] else []
    params = json.loads(row["params"])

    results = {}
    for field in pii_fields:
        value = params.get(field, "")
        if value.startswith("[ENCRYPTED:"):
            result = await main.decrypt_field_value(value)
            erasure_ok = "error" in result
            results[field] = {
                "encrypted_value": value[:30] + "...",
                "result": result,
                "erasure_verified": erasure_ok,
            }

    all_verified = (
        all(r["erasure_verified"] for r in results.values()) if results else False
    )

    return {
        "subject_id": subject_id,
        "fields_tested": len(results),
        "results": results,
        "erasure_verified": all_verified,
        "decryption_result": "failed" if all_verified else "succeeded",
        "interpretation": (
            "All encrypted fields are now irrecoverable — the HSM key has been deleted."
            if all_verified
            else "WARNING: Some fields could still be decrypted. "
            "Erasure may not be complete."
        ),
    }


@router.get("/audit/subjects", tags=["Audit"])
async def list_subjects(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List all PII subjects with encrypted records in the audit log."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        rows = conn.execute("""SELECT pii_subject_id, COUNT(*) as record_count,
                      erasure_status, MAX(created_at) as last_seen
               FROM audit_log
               WHERE pii_subject_id IS NOT NULL
               GROUP BY pii_subject_id""").fetchall()
    finally:
        conn.close()

    subjects = []
    for row in rows:
        subjects.append(
            {
                "subject_id": row["pii_subject_id"],
                "record_count": row["record_count"],
                "erasure_status": row["erasure_status"],
                "last_seen": row["last_seen"],
            }
        )

    return {"subjects": subjects}


# ── HSM proxy endpoints ─────────────────────────────────────────────────────


@router.post("/hsm/keys", tags=["Credentials"])
async def proxy_hsm_create_key(
    req: dict,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Create an HSM encryption key for a data subject."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{main.HSM_URL}/keys", json=req)
        return resp.json()


@router.post("/hsm/encrypt", tags=["Credentials"])
async def proxy_hsm_encrypt(
    req: dict,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Encrypt data using an HSM-managed key."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{main.HSM_URL}/encrypt", json=req)
        return resp.json()


@router.post("/hsm/decrypt", tags=["Credentials"])
async def proxy_hsm_decrypt(
    req: dict,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Decrypt data using an HSM-managed key."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{main.HSM_URL}/decrypt", json=req)
        return resp.json()


@router.get("/hsm/keys/{subject_id}/status", tags=["Credentials"])
async def proxy_hsm_key_status(
    subject_id: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Check the status of an HSM key for a data subject."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{main.HSM_URL}/keys/{subject_id}/status")
        return resp.json()


@router.get("/hsm/keys", tags=["Credentials"])
async def proxy_hsm_list_keys(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List all HSM keys."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{main.HSM_URL}/keys")
        return resp.json()


@router.delete("/hsm/keys/{subject_id}", tags=["Credentials"])
async def proxy_hsm_delete_key(
    subject_id: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Delete an HSM key (crypto-shredding)."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{main.HSM_URL}/keys/{subject_id}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No key found for subject {subject_id}")
        return resp.json()


# ── Credential vault proxy endpoints ────────────────────────────────────────


@router.post("/credentials/register", tags=["Credentials"])
async def register_credential(
    req: RegisterCredentialRequest,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Register a tool credential in the HSM vault for brokered execution."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    # SECURITY: value passes through to HSM immediately, never logged by gateway
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{main.HSM_URL}/credentials",
            json={"tool_id": req.tool_id, "name": req.name, "value": req.value},
        )
        return resp.json()


@router.get("/credentials", tags=["Credentials"])
async def list_credentials(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List registered tool credentials (metadata only, not values)."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{main.HSM_URL}/credentials")
        return resp.json()


@router.delete("/credentials/{tool_id}/{name}", tags=["Credentials"])
async def delete_credential(
    tool_id: str,
    name: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Remove a tool credential from the vault."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{main.HSM_URL}/credentials/{tool_id}/{name}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No credential found for {tool_id}/{name}")
        return resp.json()


@router.get("/credentials/{tool_id}/status", tags=["Credentials"])
async def credential_status(
    tool_id: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Check registration status of a tool credential."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{main.HSM_URL}/credentials/{tool_id}/status")
        return resp.json()


@router.get("/credentials/access-log", tags=["Credentials"])
async def credential_access_log(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """View the credential access log (which credentials were used and when)."""
    import main

    await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{main.HSM_URL}/credentials/access-log")
        return resp.json()


# ── Policy replay endpoints ─────────────────────────────────────────────────


async def _replay_with_opa(opa_input: dict, bundle_revision: str) -> dict:
    """Fetch the archived bundle and evaluate opa_input against it using a temp OPA."""
    import main

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{main.BUNDLE_SERVER_URL}/bundles/vargate/archive/{bundle_revision}"
            )
            if resp.status_code != 200:
                return {
                    "error": f"Archived bundle {bundle_revision} not found (HTTP {resp.status_code})"
                }
            bundle_bytes = resp.content
    except Exception as e:
        return {"error": f"Failed to fetch archived bundle: {e}"}

    tmpdir = tempfile.mkdtemp(prefix="vargate_replay_")
    try:
        bundle_path = os.path.join(tmpdir, "bundle.tar.gz")
        with open(bundle_path, "wb") as f:
            f.write(bundle_bytes)

        import asyncio
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        proc = subprocess.Popen(
            [
                "/usr/local/bin/opa",
                "run",
                "--server",
                f"--addr=127.0.0.1:{port}",
                "--log-level=error",
                "-b",
                bundle_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for _ in range(30):
            try:
                async with httpx.AsyncClient(timeout=1.0) as client:
                    r = await client.get(f"http://127.0.0.1:{port}/health")
                    if r.status_code == 200:
                        break
            except Exception:
                pass
            await asyncio.sleep(0.1)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"http://127.0.0.1:{port}/v1/data/vargate/policy/decision",
                    json={"input": opa_input},
                )
                r.raise_for_status()
                return r.json().get("result", {})
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_replay_response(row, replayed_result: dict) -> dict:
    """Build the structured comparison response."""
    original_decision = row["decision"]
    original_violations = json.loads(row["violations"])
    original_severity = row["severity"]
    original_bundle = row["bundle_revision"]

    replayed_decision = "allow" if replayed_result.get("allow", False) else "deny"
    replayed_violations = sorted(replayed_result.get("violations", []))
    replayed_severity = replayed_result.get("severity", "none")

    match_decision = original_decision == replayed_decision
    match_violations = sorted(original_violations) == replayed_violations
    match_severity = original_severity == replayed_severity

    all_match = match_decision and match_violations and match_severity
    status = "MATCH" if all_match else "MISMATCH"

    if all_match:
        viols_str = (
            ", ".join(original_violations) if original_violations else "no violations"
        )
        interpretation = (
            "The recorded decision is verified. Under policy {}, "
            "this action was correctly {}. "
            "This decision is reproducible and tamper-evident.".format(
                original_bundle,
                "denied for " + viols_str if original_decision == "deny" else "allowed",
            )
        )
    else:
        interpretation = (
            "MISMATCH detected. The replayed decision differs from the original record. "
            "This indicates either: (a) the stored input document was modified, or "
            "(b) the policy bundle archive does not match what was deployed at the time. "
            "Recommend forensic investigation."
        )

    return {
        "action_id": row["action_id"],
        "replay_status": status,
        "original": {
            "decision": original_decision,
            "violations": original_violations,
            "severity": original_severity,
            "bundle_revision": original_bundle,
            "recorded_at": row["created_at"],
        },
        "replayed": {
            "decision": replayed_decision,
            "violations": replayed_violations,
            "severity": replayed_severity,
            "bundle_revision": original_bundle,
            "replayed_at": datetime.now(timezone.utc).isoformat(),
        },
        "match": {
            "decision": match_decision,
            "violations": match_violations,
            "severity": match_severity,
            "bundle_revision": True,
        },
        "opa_input_used": json.loads(row["opa_input"]) if row["opa_input"] else None,
        "interpretation": interpretation,
    }


@router.post("/audit/replay", tags=["Audit"])
async def audit_replay(req: ReplayRequest):
    """Replay a single audit record against current OPA policy to check decision consistency."""
    import main

    conn = main.get_db()
    try:
        if req.action_id:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE action_id = ?", (req.action_id,)
            ).fetchone()
        elif req.record_number:
            row = conn.execute(
                "SELECT * FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET ?",
                (req.record_number - 1,),
            ).fetchone()
        elif req.last_block:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE decision = 'deny' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        else:
            raise HTTPException(
                400, "Provide action_id, record_number, or last_block=true"
            )

        if not row:
            raise HTTPException(404, "Record not found")

        if not row["opa_input"]:
            raise HTTPException(
                422,
                f"Record {row['action_id']} predates Session 5 — no opa_input stored. "
                f"Only records created after the replay feature can be replayed.",
            )

        opa_input = json.loads(row["opa_input"])
        bundle_revision = row["bundle_revision"]

        replayed_result = await _replay_with_opa(opa_input, bundle_revision)
        if "error" in replayed_result:
            raise HTTPException(502, replayed_result["error"])

        return _build_replay_response(row, replayed_result)
    finally:
        conn.close()


@router.post("/audit/replay-bulk", tags=["Audit"])
async def audit_replay_bulk(req: BulkReplayRequest):
    """Replay multiple recent records against current policy for bulk verification."""
    import main

    conn = main.get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE opa_input IS NOT NULL ORDER BY id DESC LIMIT ?",
            (req.count,),
        ).fetchall()
    finally:
        conn.close()

    results = []
    match_count = 0
    mismatch_count = 0
    skip_count = 0

    for row in reversed(rows):
        opa_input = json.loads(row["opa_input"])
        replayed_result = await _replay_with_opa(opa_input, row["bundle_revision"])

        if "error" in replayed_result:
            results.append(
                {
                    "action_id": row["action_id"],
                    "replay_status": "ERROR",
                    "error": replayed_result["error"],
                }
            )
            skip_count += 1
            continue

        resp = _build_replay_response(row, replayed_result)
        results.append(resp)
        if resp["replay_status"] == "MATCH":
            match_count += 1
        else:
            mismatch_count += 1

    return {
        "results": results,
        "summary": {
            "total": len(results),
            "matched": match_count,
            "mismatched": mismatch_count,
            "errors": skip_count,
        },
    }
