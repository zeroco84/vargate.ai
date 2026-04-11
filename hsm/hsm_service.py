"""
Vargate HSM Service — REST API over SoftHSM2 (PKCS#11)

Manages per-subject AES-256 encryption keys for crypto-shredding.
Manages tool credential secrets for agent-blind brokered execution.
Keys never leave the HSM boundary.
"""

import base64
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone

import pkcs11
import uvicorn
from fastapi import FastAPI, HTTPException
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pydantic import BaseModel

# ── Configuration ────────────────────────────────────────────────────────────

PKCS11_LIB = os.environ.get("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")
TOKEN_LABEL = os.environ.get("HSM_TOKEN_LABEL", "vargate-prototype")
TOKEN_PIN = os.environ.get("HSM_TOKEN_PIN", "1234")  # nosec B105
if TOKEN_PIN == "1234":  # nosec B105
    import warnings

    warnings.warn(
        "HSM_TOKEN_PIN is using the default development value '1234'. "
        "Set HSM_TOKEN_PIN environment variable for production use.",
        stacklevel=1,
    )
CRED_DB_PATH = os.environ.get("CRED_DB_PATH", "/data/credentials.db")

app = FastAPI(title="Vargate HSM Service", version="2.0.0")

# ── Track key metadata and erasures in memory ───────────────────────────────

_key_metadata: dict[str, dict] = {}
_erased_keys: dict[str, dict] = {}
_lib = None
_token = None


def get_lib():
    global _lib
    if _lib is None:
        _lib = pkcs11.lib(PKCS11_LIB)
    return _lib


def get_token():
    global _token
    if _token is None:
        _token = get_lib().get_token(token_label=TOKEN_LABEL)
    return _token


def get_session():
    return get_token().open(rw=True, user_pin=TOKEN_PIN)


def _key_label(subject_id: str) -> str:
    return f"subject:{subject_id}"


def _key_id(subject_id: str) -> str:
    return f"key-{subject_id}-v1"


# ── PKCS#11 padding helpers (PKCS7) ─────────────────────────────────────────


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def _find_key(session, label):
    """Find a single key by label, handling NoSuchKey and MultipleObjectsReturned."""
    try:
        return session.get_key(object_class=ObjectClass.SECRET_KEY, label=label)
    except pkcs11.NoSuchKey:
        return None
    except pkcs11.MultipleObjectsReturned:
        keys = list(
            session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.LABEL: label,
                }
            )
        )
        return keys[0] if keys else None


# ── Request / Response models ────────────────────────────────────────────────


class CreateKeyRequest(BaseModel):
    subject_id: str


class EncryptRequest(BaseModel):
    subject_id: str
    plaintext: str


class DecryptRequest(BaseModel):
    subject_id: str
    ciphertext_b64: str


class StoreCredentialRequest(BaseModel):
    tool_id: str
    name: str
    value: str  # SECURITY: value is encrypted immediately, never logged


# ── Credential SQLite setup ─────────────────────────────────────────────────


def _get_cred_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(CRED_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CRED_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_cred_db():
    conn = _get_cred_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id     TEXT NOT NULL,
            name        TEXT NOT NULL,
            encrypted   TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            UNIQUE(tool_id, name)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credential_access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id     TEXT NOT NULL,
            name        TEXT NOT NULL,
            action_id   TEXT NOT NULL,
            agent_id    TEXT NOT NULL,
            accessed_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ── Credential master key ───────────────────────────────────────────────────

CRED_MASTER_LABEL = "cred-master"


def _ensure_cred_master_key(session):
    """Ensure the credential master AES-256 key exists in the HSM."""
    existing = _find_key(session, CRED_MASTER_LABEL)
    if existing:
        return existing
    key = session.generate_key(
        KeyType.AES,
        256,
        label=CRED_MASTER_LABEL,
        store=True,
        template={
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.EXTRACTABLE: False,
            Attribute.SENSITIVE: True,
            Attribute.TOKEN: True,
        },
    )
    print(f"[HSM] Generated credential master key: {CRED_MASTER_LABEL}", flush=True)
    return key


def _encrypt_credential(value: str) -> str:
    """Encrypt a credential value using the master key. Returns base64."""
    # SECURITY: credential value is encrypted here and never logged
    with get_session() as session:
        key = _ensure_cred_master_key(session)
        iv = secrets.token_bytes(16)
        plaintext_padded = _pkcs7_pad(value.encode("utf-8"))
        ciphertext = key.encrypt(
            plaintext_padded, mechanism_param=iv, mechanism=Mechanism.AES_CBC
        )
        combined = iv + ciphertext
        return base64.b64encode(combined).decode("ascii")


def _decrypt_credential(encrypted_b64: str) -> str:
    """Decrypt a credential value using the master key. Returns plaintext string."""
    # SECURITY: returned value must only be used for tool execution, never logged
    with get_session() as session:
        key = _ensure_cred_master_key(session)
        combined = base64.b64decode(encrypted_b64)
        iv = combined[:16]
        ciphertext = combined[16:]
        plaintext_padded = key.decrypt(
            ciphertext, mechanism_param=iv, mechanism=Mechanism.AES_CBC
        )
        plaintext_bytes = _pkcs7_unpad(plaintext_padded)
        return plaintext_bytes.decode("utf-8")


# ── PII Key Endpoints (existing) ────────────────────────────────────────────


@app.post("/keys")
async def create_key(req: CreateKeyRequest):
    """Generate (or return existing) AES-256 key for a data subject."""
    label = _key_label(req.subject_id)
    kid = _key_id(req.subject_id)

    if req.subject_id in _erased_keys:
        raise HTTPException(410, f"Subject {req.subject_id} has been erased.")

    if req.subject_id in _key_metadata:
        return _key_metadata[req.subject_id]

    with get_session() as session:
        existing = _find_key(session, label)
        if existing:
            meta = {
                "key_id": kid,
                "subject_id": req.subject_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            _key_metadata[req.subject_id] = meta
            print(f"[HSM] Key already exists for {req.subject_id}", flush=True)
            return meta

        # Generate new AES-256 key
        session.generate_key(
            KeyType.AES,
            256,
            label=label,
            store=True,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SENSITIVE: True,
                Attribute.TOKEN: True,
            },
        )

    meta = {
        "key_id": kid,
        "subject_id": req.subject_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _key_metadata[req.subject_id] = meta
    print(f"[HSM] Generated AES-256 key for {req.subject_id}: {kid}", flush=True)
    return meta


@app.post("/encrypt")
async def encrypt(req: EncryptRequest):
    """Encrypt plaintext using a subject's AES-256 key (AES-CBC + PKCS7)."""
    label = _key_label(req.subject_id)
    kid = _key_id(req.subject_id)

    if req.subject_id in _erased_keys:
        raise HTTPException(
            410,
            {
                "error": "key_not_found",
                "subject_id": req.subject_id,
                "erased": True,
            },
        )

    with get_session() as session:
        key = _find_key(session, label)
        if not key:
            raise HTTPException(404, f"No key found for subject {req.subject_id}")

        iv = secrets.token_bytes(16)
        plaintext_padded = _pkcs7_pad(req.plaintext.encode("utf-8"))

        # Use AES-CBC mechanism with IV
        ciphertext = key.encrypt(
            plaintext_padded, mechanism_param=iv, mechanism=Mechanism.AES_CBC
        )

        combined = iv + ciphertext
        ciphertext_b64 = base64.b64encode(combined).decode("ascii")

    return {"ciphertext_b64": ciphertext_b64, "key_id": kid}


@app.post("/decrypt")
async def decrypt(req: DecryptRequest):
    """Decrypt ciphertext using a subject's AES-256 key."""
    label = _key_label(req.subject_id)

    if req.subject_id in _erased_keys:
        return {"error": "key_not_found", "subject_id": req.subject_id, "erased": True}

    with get_session() as session:
        key = _find_key(session, label)
        if not key:
            return {
                "error": "key_not_found",
                "subject_id": req.subject_id,
                "erased": False,
            }

        combined = base64.b64decode(req.ciphertext_b64)
        iv = combined[:16]
        ciphertext = combined[16:]

        plaintext_padded = key.decrypt(
            ciphertext, mechanism_param=iv, mechanism=Mechanism.AES_CBC
        )
        plaintext_bytes = _pkcs7_unpad(plaintext_padded)

    return {"plaintext": plaintext_bytes.decode("utf-8")}


@app.delete("/keys/{subject_id}")
async def delete_key(subject_id: str):
    """Delete a subject's key — GDPR erasure. Irreversible."""
    label = _key_label(subject_id)
    kid = _key_id(subject_id)

    if subject_id in _erased_keys:
        return _erased_keys[subject_id]

    with get_session() as session:
        destroyed = 0
        keys = list(
            session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.LABEL: label,
                }
            )
        )
        for key in keys:
            key.destroy()
            destroyed += 1

        if destroyed == 0 and subject_id not in _key_metadata:
            raise HTTPException(404, f"No key found for subject {subject_id}")

    erased_at = datetime.now(timezone.utc).isoformat()
    cert_input = f"{subject_id}:{kid}:{erased_at}"
    erasure_certificate = hashlib.sha256(cert_input.encode()).hexdigest()

    result = {
        "subject_id": subject_id,
        "key_id": kid,
        "erased_at": erased_at,
        "erasure_certificate": erasure_certificate,
        "keys_destroyed": destroyed,
    }
    _erased_keys[subject_id] = result
    _key_metadata.pop(subject_id, None)

    print(
        f"[HSM] ERASURE: Key destroyed for {subject_id}. "
        f"Certificate: {erasure_certificate[:16]}...",
        flush=True,
    )
    return result


@app.get("/keys/{subject_id}/status")
async def key_status(subject_id: str):
    if subject_id in _erased_keys:
        info = _erased_keys[subject_id]
        return {
            "subject_id": subject_id,
            "key_exists": False,
            "key_id": info.get("key_id"),
            "erased_at": info.get("erased_at"),
        }
    if subject_id in _key_metadata:
        meta = _key_metadata[subject_id]
        return {
            "subject_id": subject_id,
            "key_exists": True,
            "key_id": meta["key_id"],
            "created_at": meta["created_at"],
            "erased_at": None,
        }
    return {"subject_id": subject_id, "key_exists": False, "erased_at": None}


@app.get("/keys")
async def list_keys():
    subjects = []
    for sid, meta in _key_metadata.items():
        subjects.append(
            {
                "subject_id": sid,
                "key_exists": True,
                "key_id": meta["key_id"],
                "created_at": meta.get("created_at"),
                "erased_at": None,
            }
        )
    for sid, info in _erased_keys.items():
        subjects.append(
            {
                "subject_id": sid,
                "key_exists": False,
                "key_id": info.get("key_id"),
                "erased_at": info.get("erased_at"),
            }
        )
    return {"subjects": subjects}


# ── Credential Vault Endpoints (Stage 8) ────────────────────────────────────


@app.post("/credentials")
async def store_credential(req: StoreCredentialRequest):
    """Store a tool credential. Value is encrypted immediately, never logged."""
    # SECURITY: req.value must not be logged or stored in plaintext anywhere
    encrypted = _encrypt_credential(req.value)
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_cred_db()
    try:
        # Upsert: replace if exists
        conn.execute(
            "INSERT OR REPLACE INTO credentials (tool_id, name, encrypted, created_at) VALUES (?, ?, ?, ?)",
            (req.tool_id, req.name, encrypted, now),
        )
        conn.commit()
    finally:
        conn.close()

    # SECURITY: log the registration event but NOT the credential value
    print(f"[HSM] Credential stored: {req.tool_id}/{req.name}", flush=True)
    return {"tool_id": req.tool_id, "name": req.name, "registered": True}


@app.get("/credentials")
async def list_credentials():
    """List registered tools and credential names. Values never returned."""
    conn = _get_cred_db()
    try:
        rows = conn.execute(
            "SELECT tool_id, name, created_at FROM credentials ORDER BY tool_id, name"
        ).fetchall()
    finally:
        conn.close()

    credentials = [
        {"tool_id": r["tool_id"], "name": r["name"], "created_at": r["created_at"]}
        for r in rows
    ]
    return {"credentials": credentials}


@app.delete("/credentials/{tool_id}/{name}")
async def delete_credential(tool_id: str, name: str):
    """Delete a stored credential."""
    conn = _get_cred_db()
    try:
        result = conn.execute(
            "DELETE FROM credentials WHERE tool_id = ? AND name = ?", (tool_id, name)
        )
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(404, f"No credential found for {tool_id}/{name}")
    finally:
        conn.close()

    print(f"[HSM] Credential deleted: {tool_id}/{name}", flush=True)
    return {"tool_id": tool_id, "name": name, "deleted": True}


@app.get("/credentials/{tool_id}/status")
async def credential_status(tool_id: str):
    """Check whether credentials exist for a tool."""
    conn = _get_cred_db()
    try:
        rows = conn.execute(
            "SELECT name, created_at FROM credentials WHERE tool_id = ?", (tool_id,)
        ).fetchall()
    finally:
        conn.close()

    names = [{"name": r["name"], "created_at": r["created_at"]} for r in rows]
    return {"tool_id": tool_id, "registered": len(names) > 0, "credentials": names}


@app.get("/credentials/access-log")
async def credential_access_log():
    """Return the credential access log. Values never included."""
    conn = _get_cred_db()
    try:
        rows = conn.execute(
            "SELECT tool_id, name, action_id, agent_id, accessed_at FROM credential_access_log ORDER BY id DESC LIMIT 100"
        ).fetchall()
    finally:
        conn.close()

    entries = [dict(r) for r in rows]
    return {"entries": entries}


class FetchCredentialRequest(BaseModel):
    tool_id: str
    name: str
    action_id: str
    agent_id: str


@app.post("/credentials/fetch-for-execution")
async def http_fetch_credential_for_execution(req: FetchCredentialRequest):
    """
    HTTP endpoint for gateway to fetch a credential for brokered execution.
    SECURITY: Returns the credential value ONLY to be used as a Bearer token.
    The value is NOT logged by this endpoint.
    """
    credential = await fetch_credential_for_execution(
        tool_id=req.tool_id,
        name=req.name,
        action_id=req.action_id,
        agent_id=req.agent_id,
    )
    # SECURITY: credential returned here is used by gateway for execution only
    return {"credential": credential}


async def fetch_credential_for_execution(
    tool_id: str, name: str, action_id: str, agent_id: str
) -> str:
    """
    Decrypt and return a credential value for use in an approved execution.
    Logs the access event (tool, name, action_id, agent_id, timestamp).
    SECURITY: Does NOT log the credential value. Returns plaintext string.
    Raises HTTPException(404) if no credential is registered for tool_id/name.
    """
    conn = _get_cred_db()
    try:
        row = conn.execute(
            "SELECT encrypted FROM credentials WHERE tool_id = ? AND name = ?",
            (tool_id, name),
        ).fetchone()

        if not row:
            raise HTTPException(404, f"No credential registered for {tool_id}/{name}")

        # Log the access event — SECURITY: no credential value in the log
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO credential_access_log (tool_id, name, action_id, agent_id, accessed_at) VALUES (?, ?, ?, ?, ?)",
            (tool_id, name, action_id, agent_id, now),
        )
        conn.commit()
    finally:
        conn.close()

    # SECURITY: decrypt and return — value used only for execution, never logged
    plaintext = _decrypt_credential(row["encrypted"])
    print(
        f"[HSM] Credential accessed: {tool_id}/{name} for action={action_id} agent={agent_id}",
        flush=True,
    )
    return plaintext


# ── Health ───────────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    try:
        get_lib()
        return {"status": "ok", "service": "vargate-hsm", "pkcs11": "connected"}
    except Exception as e:
        return {"status": "degraded", "service": "vargate-hsm", "error": str(e)}


# ── Startup ──────────────────────────────────────────────────────────────────


@app.on_event("startup")
async def startup():
    _init_cred_db()
    # Pre-create the credential master key
    with get_session() as session:
        _ensure_cred_master_key(session)
    print("[HSM] Credential vault initialized.", flush=True)


if __name__ == "__main__":
    print("[HSM] Starting Vargate HSM Service on port 8300", flush=True)
    print(f"[HSM] PKCS#11 lib: {PKCS11_LIB}", flush=True)
    print(f"[HSM] Token label: {TOKEN_LABEL}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8300, log_level="info")  # nosec B104
