"""
Auth routes: email signup, verify-email, GitHub OAuth, sessions,
API key rotation, tenant switching.
Extracted from main.py for maintainability (Audit Item 14).
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

router = APIRouter(tags=["Auth"])


# ── Pydantic models ──────────────────────────────────────────────────────────


class EmailSignupRequest(BaseModel):
    email: str
    name: str


# ── Auth & Signup endpoints (Sprint 3) ──────────────────────────────────────


@router.post("/auth/signup")
async def email_signup(req: EmailSignupRequest, request: Request):
    """Sign up with email. Sends a verification link. On verification, a tenant and API key are provisioned."""
    import main
    from rate_limit import enforce_ip_rate_limit

    await enforce_ip_rate_limit(
        main.redis_pool, request, "signup", max_requests=5, window_seconds=60
    )
    import auth as auth_module

    error = auth_module.validate_email(req.email)
    if error:
        raise HTTPException(400, error)

    conn = main.get_db()
    try:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ?", (req.email,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Email already registered")

        conn.execute("DELETE FROM pending_signups WHERE email = ?", (req.email,))

        token = auth_module._generate_verification_token()
        token_hash = auth_module._hash_verification_token(token)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=1)

        conn.execute(
            """INSERT INTO pending_signups (email, token_hash, tenant_name, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (req.email, token_hash, req.name, now.isoformat(), expires.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    await auth_module.send_verification_email(req.email, token)
    return {"status": "verification_sent", "email": req.email}


@router.get("/auth/verify-email")
async def verify_email(request: Request, token: str = Query(...)):
    """Verify email address from signup link. Provisions tenant, user, and API key on success."""
    import main
    from rate_limit import enforce_ip_rate_limit

    await enforce_ip_rate_limit(
        main.redis_pool, request, "verify-email", max_requests=10, window_seconds=60
    )
    import auth as auth_module

    token_hash = auth_module._hash_verification_token(token)
    conn = main.get_db()
    try:
        row = conn.execute(
            "SELECT * FROM pending_signups WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not row:
            raise HTTPException(400, "Invalid or expired verification token")

        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at < now:
            conn.execute("DELETE FROM pending_signups WHERE id = ?", (row["id"],))
            conn.commit()
            raise HTTPException(400, "Verification token expired")

        email = row["email"]
        name = row["tenant_name"]
        slug = auth_module.generate_tenant_slug(name)

        existing_slug = conn.execute(
            "SELECT 1 FROM tenants WHERE slug = ?", (slug,)
        ).fetchone()
        if existing_slug:
            slug = f"{slug}-{secrets.token_hex(3)}"

        result = auth_module.provision_tenant(
            conn=conn,
            tenant_id=slug,
            name=name,
            email=email,
        )

        conn.execute("UPDATE tenants SET slug = ? WHERE tenant_id = ?", (slug, slug))
        conn.execute("DELETE FROM pending_signups WHERE id = ?", (row["id"],))
        conn.commit()

        main._refresh_tenant_cache()

        session_token = auth_module.create_session_token(slug, email)

        return {
            "status": "verified",
            "tenant_id": result["tenant_id"],
            "api_key": result["api_key"],
            "session_token": session_token,
            "dashboard_url": f"/dashboard/{slug}",
        }
    finally:
        conn.close()


@router.get("/auth/github")
async def github_login():
    """Redirect to GitHub OAuth authorization page."""
    import auth as auth_module

    if not auth_module.GITHUB_CLIENT_ID:
        raise HTTPException(501, "GitHub OAuth not configured")
    state = secrets.token_urlsafe(16)
    url = auth_module.get_github_authorize_url(state)
    return {"redirect_url": url, "state": state}


@router.get("/auth/github/callback")
async def github_callback(
    request: Request, code: str = Query(...), state: str = Query(default="")
):
    """GitHub OAuth callback. Exchanges code for token, provisions or links user account."""
    import main
    from rate_limit import enforce_ip_rate_limit

    await enforce_ip_rate_limit(
        main.redis_pool, request, "github-callback", max_requests=10, window_seconds=60
    )
    import auth as auth_module

    if not auth_module.GITHUB_CLIENT_ID:
        raise HTTPException(501, "GitHub OAuth not configured")

    profile = await auth_module.exchange_github_code(code)
    if not profile:
        raise HTTPException(400, "Failed to authenticate with GitHub")

    conn = main.get_db()
    try:
        existing = conn.execute(
            "SELECT tenant_id FROM users WHERE github_id = ?", (profile["github_id"],)
        ).fetchone()

        if existing:
            tenant_id = existing["tenant_id"]
            session_token = auth_module.create_session_token(
                tenant_id, profile["email"]
            )
            from urllib.parse import urlencode

            params = urlencode(
                {"token": session_token, "tenant_id": tenant_id, "new_user": "false"}
            )
            return RedirectResponse(url=f"/dashboard/?{params}", status_code=302)

        slug = auth_module.generate_tenant_slug(profile["name"])
        existing_slug = conn.execute(
            "SELECT 1 FROM tenants WHERE slug = ?", (slug,)
        ).fetchone()
        if existing_slug:
            slug = f"{slug}-{secrets.token_hex(3)}"

        existing_tenant = conn.execute(
            "SELECT 1 FROM tenants WHERE tenant_id = ?", (slug,)
        ).fetchone()
        if existing_tenant:
            slug = f"{slug}-{secrets.token_hex(3)}"

        result = auth_module.provision_tenant(
            conn=conn,
            tenant_id=slug,
            name=profile["name"],
            email=profile["email"],
            github_login=profile["login"],
            github_id=profile["github_id"],
        )

        conn.execute("UPDATE tenants SET slug = ? WHERE tenant_id = ?", (slug, slug))
        conn.commit()
        main._refresh_tenant_cache()

        session_token = auth_module.create_session_token(slug, profile["email"])
        from urllib.parse import urlencode

        params = urlencode(
            {
                "token": session_token,
                "tenant_id": result["tenant_id"],
                "new_user": "true",
            }
        )
        return RedirectResponse(url=f"/dashboard/?{params}", status_code=302)
    finally:
        conn.close()


@router.post("/auth/session")
async def create_session(x_api_key: str = Header(...)):
    """Exchange API key for a JWT session token."""
    import auth as auth_module
    import main

    tenant = main.resolve_tenant(x_api_key)
    if not tenant:
        raise HTTPException(401, "Invalid API key")

    conn = main.get_db()
    try:
        user = conn.execute(
            "SELECT email FROM users WHERE tenant_id = ?", (tenant["tenant_id"],)
        ).fetchone()
        email = user["email"] if user else "unknown"
    finally:
        conn.close()

    session_token = auth_module.create_session_token(tenant["tenant_id"], email)
    return {"session_token": session_token, "tenant_id": tenant["tenant_id"]}


# ── API key rotation (Sprint 3) ─────────────────────────────────────────────


@router.post("/api-keys/rotate")
async def rotate_api_key(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Rotate the current API key. Returns a new key; the old one is invalidated."""
    import auth as auth_module
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        result = auth_module.rotate_api_key(conn, tenant["tenant_id"])
    except ValueError as e:
        raise HTTPException(404, str(e))
    finally:
        conn.close()

    main._refresh_tenant_cache()
    return {"tenant_id": tenant["tenant_id"], **result}


# ── Tenant switching ────────────────────────────────────────────────────────


@router.get("/auth/my-tenants")
async def list_my_tenants(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List all tenants the authenticated user belongs to."""
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        current_user = conn.execute(
            "SELECT github_id FROM users WHERE tenant_id = ?",
            (tenant["tenant_id"],),
        ).fetchone()

        if not current_user or not current_user["github_id"]:
            return {
                "tenants": [
                    {
                        "tenant_id": tenant["tenant_id"],
                        "name": tenant["name"],
                        "current": True,
                    }
                ]
            }

        user_rows = conn.execute(
            "SELECT u.tenant_id, t.name, t.slug FROM users u JOIN tenants t ON u.tenant_id = t.tenant_id WHERE u.github_id = ?",
            (current_user["github_id"],),
        ).fetchall()

        tenants = [
            {
                "tenant_id": r["tenant_id"],
                "name": r["name"],
                "slug": r["slug"],
                "current": r["tenant_id"] == tenant["tenant_id"],
            }
            for r in user_rows
        ]
    finally:
        conn.close()

    return {"tenants": tenants}


@router.post("/auth/switch-tenant")
async def switch_tenant(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Switch active tenant context. Returns a new session token scoped to the target tenant."""
    import auth as auth_module
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    body = await request.json()
    target_tenant_id = body.get("tenant_id")
    if not target_tenant_id:
        raise HTTPException(400, "tenant_id required")

    conn = main.get_db()
    try:
        current_user = conn.execute(
            "SELECT github_id, email FROM users WHERE tenant_id = ?",
            (tenant["tenant_id"],),
        ).fetchone()

        if not current_user or not current_user["github_id"]:
            raise HTTPException(
                403, "Cannot switch tenants without GitHub authentication"
            )

        target_user = conn.execute(
            "SELECT email FROM users WHERE tenant_id = ? AND github_id = ?",
            (target_tenant_id, current_user["github_id"]),
        ).fetchone()

        if not target_user:
            raise HTTPException(403, "You don't have access to that tenant")

        new_token = auth_module.create_session_token(
            target_tenant_id, target_user["email"]
        )
    finally:
        conn.close()

    return {"session_token": new_token, "tenant_id": target_tenant_id}
