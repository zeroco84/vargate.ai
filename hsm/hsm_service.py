"""
Vargate HSM Service — REST API over SoftHSM2 (PKCS#11)

Manages per-subject AES-256 encryption keys for crypto-shredding.
Keys never leave the HSM boundary.
"""

import base64
import hashlib
import os
import secrets
import struct
from datetime import datetime, timezone

import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism, Attribute
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn


# ── Configuration ────────────────────────────────────────────────────────────

PKCS11_LIB = os.environ.get("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")
TOKEN_LABEL = os.environ.get("HSM_TOKEN_LABEL", "vargate-prototype")
TOKEN_PIN = os.environ.get("HSM_TOKEN_PIN", "1234")

app = FastAPI(title="Vargate HSM Service", version="1.0.0")

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
        keys = list(session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.LABEL: label,
        }))
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


# ── Endpoints ────────────────────────────────────────────────────────────────

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
        raise HTTPException(410, {
            "error": "key_not_found",
            "subject_id": req.subject_id,
            "erased": True,
        })

    with get_session() as session:
        key = _find_key(session, label)
        if not key:
            raise HTTPException(404, f"No key found for subject {req.subject_id}")

        iv = secrets.token_bytes(16)
        plaintext_padded = _pkcs7_pad(req.plaintext.encode("utf-8"))

        # Use AES-CBC mechanism with IV
        ciphertext = key.encrypt(plaintext_padded, mechanism_param=iv, mechanism=Mechanism.AES_CBC)

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
            return {"error": "key_not_found", "subject_id": req.subject_id, "erased": False}

        combined = base64.b64decode(req.ciphertext_b64)
        iv = combined[:16]
        ciphertext = combined[16:]

        plaintext_padded = key.decrypt(ciphertext, mechanism_param=iv, mechanism=Mechanism.AES_CBC)
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
        keys = list(session.get_objects({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.LABEL: label,
        }))
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
        subjects.append({
            "subject_id": sid,
            "key_exists": True,
            "key_id": meta["key_id"],
            "created_at": meta.get("created_at"),
            "erased_at": None,
        })
    for sid, info in _erased_keys.items():
        subjects.append({
            "subject_id": sid,
            "key_exists": False,
            "key_id": info.get("key_id"),
            "erased_at": info.get("erased_at"),
        })
    return {"subjects": subjects}


@app.get("/health")
async def health():
    try:
        get_lib()
        return {"status": "ok", "service": "vargate-hsm", "pkcs11": "connected"}
    except Exception as e:
        return {"status": "degraded", "service": "vargate-hsm", "error": str(e)}


if __name__ == "__main__":
    print("[HSM] Starting Vargate HSM Service on port 8300", flush=True)
    print(f"[HSM] PKCS#11 lib: {PKCS11_LIB}", flush=True)
    print(f"[HSM] Token label: {TOKEN_LABEL}", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=8300, log_level="info")
