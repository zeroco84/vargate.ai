"""
Twitter / X OAuth 2.0 (PKCE) helpers.

Twitter's v2 API requires OAuth 2.0 User Context for DMs and prefers it
for writes going forward. This module handles the three pieces:

  1. Building the authorize URL (with PKCE challenge)
  2. Exchanging the callback code for an access_token + refresh_token
  3. Refreshing an expired access_token using a refresh_token

Important behaviour notes:
  - Refresh tokens are **single-use** and rotated on every refresh.
    Callers MUST persist the new refresh_token before using the new
    access_token, otherwise a crash between refresh and persist leaves
    the credential permanently broken.
  - Access tokens expire in ~2 hours. Callers should refresh
    proactively (e.g. when <60s of life remains) rather than retrying
    on 401.
  - ``offline.access`` must be in the requested scopes for Twitter to
    return a refresh_token. Without it, only the short-lived access
    token is issued and the credential becomes unusable after 2 hours.

All requests are synchronous HTTPS to api.x.com / api.twitter.com.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

import httpx

AUTHORIZE_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"

# Default scopes cover everything Sera might ever want. Callers can narrow.
# ``offline.access`` is required to get a refresh_token back.
DEFAULT_SCOPES = [
    "tweet.read",
    "tweet.write",
    "users.read",
    "follows.read",
    "follows.write",
    "dm.read",
    "dm.write",
    "like.read",
    "like.write",
    "mute.read",
    "mute.write",
    "media.write",
    "offline.access",
]


def generate_pkce_pair() -> tuple[str, str]:
    """Return (verifier, challenge) for PKCE.

    Verifier: 43–128 character URL-safe random string (we use 64 bytes
    base64 → ~86 chars). Challenge: base64-url(SHA256(verifier)).
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def generate_state() -> str:
    """Random state token for CSRF protection on the callback."""
    return secrets.token_urlsafe(32)


def build_authorize_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scopes: Optional[list[str]] = None,
) -> str:
    """Build the Twitter authorize URL a user's browser should visit."""
    from urllib.parse import urlencode

    if scopes is None:
        scopes = DEFAULT_SCOPES

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


async def exchange_code(
    client_id: str,
    client_secret: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict:
    """Exchange the one-time authorization code for tokens.

    Returns the Twitter token response as a dict containing
    ``access_token``, ``refresh_token``, ``expires_in``, ``scope``,
    ``token_type``. Raises httpx.HTTPStatusError on non-200.
    """
    auth_header = _basic_auth(client_id, client_secret)
    body = {
        "code": code,
        "grant_type": "authorization_code",
        "client_id": client_id,  # Twitter wants this in body too
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            TOKEN_URL,
            data=body,
            headers={
                "Authorization": auth_header,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def refresh_access_token(
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> dict:
    """Use a refresh_token to get a new access_token.

    Twitter rotates the refresh_token on every refresh — the response
    will include a new refresh_token that REPLACES the one used here.
    Persist it before using the returned access_token.
    """
    auth_header = _basic_auth(client_id, client_secret)
    body = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "client_id": client_id,
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            TOKEN_URL,
            data=body,
            headers={
                "Authorization": auth_header,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        resp.raise_for_status()
        return resp.json()


def _basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")
