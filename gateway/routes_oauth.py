"""
OAuth callback routes for platform integrations.

Currently handles Twitter / X OAuth 2.0 (PKCE). The flow:

  1. Tenant POSTs /oauth/twitter/start with their Twitter app's
     client_id + client_secret. Gateway generates a PKCE verifier,
     state token, and authorize URL; stashes the verifier+secret in
     Redis keyed by state; returns the URL for the user's browser.
  2. User browses to the URL, authorizes on twitter.com, is redirected
     back to /oauth/twitter/callback?code=...&state=...
  3. Gateway validates state, pulls the stashed verifier+secret, calls
     Twitter's token endpoint, and registers the resulting tokens in
     the HSM vault as tool_id=twitter, name=oauth2.

State is held in Redis for 10 minutes with a single-use delete-on-read
pattern. If Redis is unavailable, the flow falls back to an in-memory
dict (fine for single-replica; if we ever multi-replicate the gateway
this needs to go through Redis exclusively).
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

router = APIRouter(prefix="/oauth", tags=["OAuth"])

# In-memory fallback when Redis isn't available (dev / single-replica).
_local_state: dict[str, dict] = {}

# How long we hold onto a pending OAuth state before rejecting the callback.
STATE_TTL_SECONDS = 600

# Where the callback lands. Must match what's registered on Twitter's side.
TWITTER_REDIRECT_URI = os.environ.get(
    "TWITTER_OAUTH_REDIRECT_URI", "https://vargate.ai/api/oauth/twitter/callback"
)


class TwitterOAuthStartRequest(BaseModel):
    client_id: str
    client_secret: str


@router.post("/twitter/start")
async def twitter_oauth_start(
    req: TwitterOAuthStartRequest,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
):
    """Kick off a Twitter OAuth 2.0 flow.

    Returns ``authorize_url`` for the browser to visit. The tenant's
    client_id + client_secret are stashed against a random state token
    for validation on the callback.
    """
    import main
    import oauth_twitter

    tenant = await main.get_session_tenant(authorization, x_api_key, None)
    if tenant.get("is_public_viewer"):
        raise HTTPException(403, "Public viewers cannot start an OAuth flow")

    verifier, challenge = oauth_twitter.generate_pkce_pair()
    state = oauth_twitter.generate_state()
    url = oauth_twitter.build_authorize_url(
        client_id=req.client_id,
        redirect_uri=TWITTER_REDIRECT_URI,
        state=state,
        code_challenge=challenge,
    )

    await _store_state(
        state,
        {
            "tenant_id": tenant["tenant_id"],
            "client_id": req.client_id,
            "client_secret": req.client_secret,
            "verifier": verifier,
            "created_at": time.time(),
        },
    )

    return {
        "authorize_url": url,
        "state": state,
        "redirect_uri": TWITTER_REDIRECT_URI,
    }


@router.get("/twitter/callback")
async def twitter_oauth_callback(
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    error_description: Optional[str] = Query(default=None),
):
    """Handle the browser redirect back from twitter.com.

    Returns an HTML page — users are bounced here by their browser, so
    a plain JSON response would be confusing. Success and failure pages
    are minimal but surface enough info for the user to know what
    happened.
    """
    import httpx
    import main
    import oauth_twitter

    if error:
        return _render_page(
            "Twitter connection failed",
            f"Twitter returned an error: <code>{error}</code>"
            + (f" — {error_description}" if error_description else ""),
            ok=False,
        )

    if not code or not state:
        return _render_page(
            "Twitter connection failed",
            "Missing code or state parameter on the callback URL.",
            ok=False,
        )

    pending = await _consume_state(state)
    if not pending:
        return _render_page(
            "Twitter connection failed",
            "State token is invalid or expired. Please start the flow again.",
            ok=False,
        )

    try:
        tokens = await oauth_twitter.exchange_code(
            client_id=pending["client_id"],
            client_secret=pending["client_secret"],
            code=code,
            code_verifier=pending["verifier"],
            redirect_uri=TWITTER_REDIRECT_URI,
        )
    except httpx.HTTPStatusError as e:
        body = e.response.text
        try:
            body = json.dumps(e.response.json())
        except Exception:
            pass
        return _render_page(
            "Twitter connection failed",
            f"Token exchange failed (HTTP {e.response.status_code}): "
            f"<pre>{body[:600]}</pre>",
            ok=False,
        )
    except Exception as e:
        return _render_page(
            "Twitter connection failed",
            f"Unexpected error during token exchange: {e}",
            ok=False,
        )

    # Build the vault credential value. Cache access_token + expiry
    # alongside refresh_token so the execution engine can skip a refresh
    # when the cached token is still valid.
    expires_at = int(time.time()) + int(tokens.get("expires_in", 7200))
    cred_value = {
        "client_id": pending["client_id"],
        "client_secret": pending["client_secret"],
        "refresh_token": tokens["refresh_token"],
        "access_token": tokens["access_token"],
        "access_token_expires_at": expires_at,
        "scope": tokens.get("scope", ""),
    }

    # Register in the HSM vault as twitter/oauth2. If an OAuth 1.0a
    # credential exists at twitter/api_key, leave it alone — the
    # execution engine picks oauth2 first when both are present.
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{main.HSM_URL}/credentials",
            json={
                "tool_id": "twitter",
                "name": "oauth2",
                "value": json.dumps(cred_value),
            },
        )
        if resp.status_code != 200:
            return _render_page(
                "Twitter connection failed",
                f"Could not store tokens in vault: HTTP {resp.status_code} "
                f"<pre>{resp.text[:400]}</pre>",
                ok=False,
            )

    return _render_page(
        "Twitter connected",
        "Sera's Twitter credentials have been stored in the Vargate vault. "
        "OAuth 2.0 scope grants follow, DM, and tweet operations. "
        "You can close this tab.",
        ok=True,
    )


# ── State storage (Redis-preferred, in-memory fallback) ────────────────────


async def _store_state(state: str, payload: dict) -> None:
    import main

    if main.redis_pool is not None:
        try:
            await main.redis_pool.set(
                f"oauth:twitter:state:{state}",
                json.dumps(payload),
                ex=STATE_TTL_SECONDS,
            )
            return
        except Exception as e:
            print(
                f"[OAUTH] Redis store failed, falling back to memory: {e}", flush=True
            )

    _local_state[state] = payload


async def _consume_state(state: str) -> Optional[dict]:
    """Fetch and delete the pending state. Returns None if missing/expired."""
    import main

    if main.redis_pool is not None:
        try:
            key = f"oauth:twitter:state:{state}"
            raw = await main.redis_pool.get(key)
            if raw:
                await main.redis_pool.delete(key)
                return json.loads(raw)
        except Exception as e:
            print(f"[OAUTH] Redis consume failed: {e}", flush=True)

    # Fallback path (or Redis miss)
    payload = _local_state.pop(state, None)
    if not payload:
        return None
    if time.time() - payload.get("created_at", 0) > STATE_TTL_SECONDS:
        return None
    return payload


# ── Rendering ──────────────────────────────────────────────────────────────


def _render_page(title: str, body_html: str, ok: bool) -> HTMLResponse:
    colour = "#10b981" if ok else "#ef4444"
    icon = "✓" if ok else "✗"
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0b0d10; color: #e2e8f0; margin: 0; padding: 48px 24px; }}
  .card {{ max-width: 480px; margin: 0 auto; background: rgba(255,255,255,.03);
          border: 1px solid rgba(255,255,255,.06); border-radius: 12px;
          padding: 32px; }}
  h1 {{ margin: 0 0 16px; font-size: 20px; color: {colour}; }}
  .icon {{ font-size: 32px; margin-right: 8px; }}
  p, pre {{ font-size: 14px; color: rgba(255,255,255,.72); line-height: 1.5; }}
  pre {{ background: rgba(0,0,0,.3); padding: 8px; border-radius: 6px;
         overflow-x: auto; }}
  code {{ background: rgba(0,0,0,.3); padding: 2px 6px; border-radius: 4px; }}
</style></head><body>
<div class="card">
  <h1><span class="icon">{icon}</span>{title}</h1>
  <p>{body_html}</p>
</div></body></html>"""
    status = 200 if ok else 400
    return HTMLResponse(content=html, status_code=status)
