"""
Vargate Auth Module (Sprint 3)
GitHub OAuth, email signup, JWT sessions, API key rotation.
"""

import hashlib
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import jwt

# ── Configuration ──────────────────────────────────────────────────────────

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv(
    "GITHUB_REDIRECT_URI", "https://vargate.ai/api/auth/github/callback"
)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "Vargate <no-reply@vargate.ai>")
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 86400 * 7  # 7 days
VARGATE_BASE_URL = os.getenv("VARGATE_BASE_URL", "https://vargate.ai")

# Blocked email domains for abuse filtering
_BLOCKED_DOMAINS = {
    "mailinator.com",
    "tempmail.com",
    "guerrillamail.com",
    "throwaway.email",
}
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _ensure_jwt_secret():
    """Ensure JWT_SECRET is set; raise if missing in production."""
    if not JWT_SECRET:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set. "
            "Set a stable secret in .env to prevent session invalidation on restart."
        )


# ── JWT helpers ────────────────────────────────────────────────────────────


def create_session_token(tenant_id: str, email: str) -> str:
    """Create a JWT session token for dashboard access."""
    _ensure_jwt_secret()
    payload = {
        "tenant_id": tenant_id,
        "email": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_session_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT session token. Returns payload or None."""
    _ensure_jwt_secret()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ── Email verification ─────────────────────────────────────────────────────


def _generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


def _hash_verification_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def send_verification_email(email: str, token: str):
    """Send email verification via Resend API."""
    if not RESEND_API_KEY:
        print(
            f"[AUTH] Resend not configured — verification link for {email}: {VARGATE_BASE_URL}/api/auth/verify-email?token={token}",
            flush=True,
        )
        return True

    verify_url = f"{VARGATE_BASE_URL}/api/auth/verify-email?token={token}"
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [email],
        "subject": "Verify your Vargate account",
        "html": f"""
        <div style="font-family: Inter, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 20px;">
            <h2 style="color: #0f172a;">Welcome to Vargate</h2>
            <p style="color: #334155;">Click below to verify your email and activate your account:</p>
            <a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background: #10b981; color: white; text-decoration: none; border-radius: 6px; font-weight: 600;">Verify Email</a>
            <p style="color: #94a3b8; font-size: 13px; margin-top: 24px;">If you didn't sign up for Vargate, ignore this email.</p>
        </div>
        """,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                json=payload,
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            )
            if resp.status_code in (200, 201):
                print(f"[AUTH] Verification email sent to {email}", flush=True)
                return True
            print(f"[AUTH] Resend error: {resp.status_code} {resp.text}", flush=True)
            return False
    except Exception as e:
        print(f"[AUTH] Failed to send verification email: {e}", flush=True)
        return False


# ── GitHub OAuth ───────────────────────────────────────────────────────────


def get_github_authorize_url(state: str) -> str:
    """Build GitHub OAuth authorization URL."""
    return (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=read:user user:email"
        f"&state={state}"
    )


async def exchange_github_code(code: str) -> Optional[dict]:
    """Exchange authorization code for GitHub access token + user profile."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Exchange code for token
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            return None

        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return None

        # Fetch user profile
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_resp.status_code != 200:
            return None

        user = user_resp.json()

        # Fetch primary email
        email_resp = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        email = None
        if email_resp.status_code == 200:
            for e in email_resp.json():
                if e.get("primary") and e.get("verified"):
                    email = e["email"]
                    break

        return {
            "github_id": user["id"],
            "login": user["login"],
            "name": user.get("name") or user["login"],
            "email": email or f"{user['login']}@github.com",
            "avatar_url": user.get("avatar_url"),
        }


# ── Tenant provisioning ───────────────────────────────────────────────────


def provision_tenant(
    conn: sqlite3.Connection,
    tenant_id: str,
    name: str,
    email: str,
    github_login: Optional[str] = None,
    github_id: Optional[int] = None,
) -> dict:
    """Create a new tenant and user record. Returns tenant info with API key."""
    api_key = f"vg-{secrets.token_hex(24)}"
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO tenants (tenant_id, api_key, name, created_at, rate_limit_rps, rate_limit_burst)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (tenant_id, api_key, name, now, 10, 20),
    )

    # Create user record
    conn.execute(
        """INSERT INTO users (email, tenant_id, github_login, github_id, created_at, email_verified)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (email, tenant_id, github_login, github_id, now, 1 if github_id else 0),
    )
    conn.commit()

    return {
        "tenant_id": tenant_id,
        "api_key": api_key,
        "name": name,
        "email": email,
        "created_at": now,
    }


def generate_tenant_slug(name: str) -> str:
    """Generate a URL-safe slug from a name."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:48] if slug else f"tenant-{secrets.token_hex(4)}"


# ── API key rotation ──────────────────────────────────────────────────────


def rotate_api_key(conn: sqlite3.Connection, tenant_id: str) -> dict:
    """Generate a new API key for a tenant. Invalidates the old one immediately."""
    new_key = f"vg-{secrets.token_hex(24)}"
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE tenants SET api_key = ? WHERE tenant_id = ?",
        (new_key, tenant_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Tenant not found: {tenant_id}")
    conn.commit()
    return {"api_key": new_key, "rotated_at": now}


# ── Validation ─────────────────────────────────────────────────────────────


def validate_email(email: str) -> Optional[str]:
    """Validate email format and check for blocked domains. Returns error or None."""
    if not email or not _EMAIL_RE.match(email):
        return "Invalid email format"
    domain = email.split("@")[1].lower()
    if domain in _BLOCKED_DOMAINS:
        return "Disposable email addresses are not allowed"
    return None


# ── DB schema for users and pending signups ────────────────────────────────


def init_auth_db(conn: sqlite3.Connection):
    """Create auth-related tables."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT NOT NULL UNIQUE,
            tenant_id       TEXT NOT NULL REFERENCES tenants(tenant_id),
            github_login    TEXT,
            github_id       INTEGER,
            created_at      TEXT NOT NULL,
            email_verified  INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_signups (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT NOT NULL UNIQUE,
            token_hash      TEXT NOT NULL,
            tenant_name     TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL
        )
    """)
    # Track public dashboard toggle per tenant
    for col_sql in [
        "ALTER TABLE tenants ADD COLUMN public_dashboard INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE tenants ADD COLUMN slug TEXT",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass
    conn.commit()
