"""
Vargate Execution Engine — Agent-Blind Tool Execution

Executes approved tool calls on behalf of agents using HSM-stored credentials.
Supports both mock tools (via mock server) and real APIs (Resend, etc.).
Credential values are used for Authorization headers but never logged or stored.
"""

import asyncio
import json
import os
import time
from typing import Optional

import httpx

MOCK_TOOLS_URL = None  # Set during gateway startup
RESEND_FROM_EMAIL = os.environ.get(
    "RESEND_FROM_EMAIL", "Sera (Vargate.ai) <sera@vargate.ai>"
)
SUBSTACK_BASE_URL = os.environ.get("SUBSTACK_BASE_URL", "")
HSM_URL = os.environ.get("HSM_URL", "http://hsm:8300")
# User-Agent required for Substack API — Cloudflare blocks requests without one
_BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


def init(mock_tools_url: str):
    """Initialize the execution engine with the mock tools URL."""
    global MOCK_TOOLS_URL
    MOCK_TOOLS_URL = mock_tools_url


# ── Mock tool dispatch ──────────────────────────────────────────────────────

TOOL_ENDPOINTS = {
    "gmail": {
        "send_email": "/gmail/send",
    },
    "salesforce": {
        "read_record": "/salesforce/read",
        "update_record": "/salesforce/update",
    },
    "stripe": {
        "create_charge": "/stripe/charge",
    },
    "slack": {
        "post_message": "/slack/post",
    },
}

# Tools with real API execution (not mock)
REAL_API_TOOLS = {"resend", "substack", "twitter", "instagram"}


async def execute_tool_call(
    # SECURITY NOTE: The credential value passes through gateway process memory.
    # It is used only for the outbound HTTP Authorization header and is never
    # logged, stored, or returned to the caller. However, a memory dump would
    # expose it. For AGCS Tier 3 (AG-3.4), the HSM should make the outbound
    # call directly. Current architecture is acceptable for Tier 1/2.
    tool: str,
    method: str,
    params: dict,
    credential: str,
) -> dict:
    """
    Execute a tool call using the provided credential.
    Routes to real API for known real tools, or to mock server otherwise.
    SECURITY: credential is used as Bearer/API token but NEVER logged.
    Returns: { "result": {...}, "execution_ms": int, "simulated": bool }
    """
    if tool in REAL_API_TOOLS:
        return await _execute_real_api(tool, method, params, credential)

    return await _execute_mock(tool, method, params, credential)


# ── Real API execution ──────────────────────────────────────────────────────


async def _execute_real_api(
    tool: str, method: str, params: dict, credential: str
) -> dict:
    """Execute a real API call (Resend, etc.)."""
    start = time.monotonic()

    if tool == "resend" and method == "send":
        return await _resend_send_email(params, credential, start)

    if tool == "substack" and method == "create_post":
        return await _substack_create_post(params, credential, start)

    if tool == "substack" and method == "create_note":
        return await _substack_create_note(params, credential, start)

    if tool == "substack" and method == "get_notes":
        return await _substack_get_notes(params, credential, start)

    if tool == "substack" and method == "delete_note":
        return await _substack_delete_note(params, credential, start)

    if tool == "twitter" and method == "create_tweet":
        return await _twitter_create_tweet(params, credential, start)

    if tool == "twitter" and method == "delete_tweet":
        return await _twitter_delete_tweet(params, credential, start)

    if tool == "twitter" and method == "get_user_tweets":
        return await _twitter_get_user_tweets(params, credential, start)

    if tool == "twitter" and method == "search_recent":
        return await _twitter_search_recent(params, credential, start)

    if tool == "twitter" and method == "follow_user":
        return await _twitter_follow_user(params, credential, start)

    if tool == "twitter" and method == "unfollow_user":
        return await _twitter_unfollow_user(params, credential, start)

    if tool == "twitter" and method == "send_dm":
        return await _twitter_send_dm(params, credential, start)

    if tool == "twitter" and method == "list_dm_conversations":
        return await _twitter_list_dm_conversations(params, credential, start)

    if tool == "instagram" and method == "create_post":
        return await _instagram_create_post(params, credential, start)

    return {
        "result": {"error": f"unknown_real_method: {tool}/{method}"},
        "execution_ms": 0,
        "simulated": False,
    }


_HTML_STRUCTURAL_TAGS = (
    "<p>",
    "<p ",
    "<br>",
    "<br/>",
    "<br />",
    "<div>",
    "<div ",
    "<html",
    "<body",
    "<table",
    "<ul>",
    "<ol>",
    "<li>",
    "<h1",
    "<h2",
    "<h3",
    "<a ",
)


def _looks_like_html(body: str) -> bool:
    """Detect whether a body string is HTML or plain text.

    Stray angle brackets in plain text (URLs in ``<brackets>``, placeholders
    like ``<TBD>``, ``<9am>``, etc.) should NOT trigger HTML treatment —
    only actual structural tags do.
    """
    lowered = body.lower()
    return any(tag in lowered for tag in _HTML_STRUCTURAL_TAGS)


def _plain_text_to_html(body: str) -> str:
    """Convert plain-text email body to valid HTML preserving line breaks.

    Escapes HTML special characters so stray ``<`` / ``>`` in the body
    render as literal text. Separates paragraphs on blank lines and
    converts single newlines to ``<br>`` so formatting survives HTML
    rendering in Gmail, Outlook, Apple Mail, etc.
    """
    import html as _html

    escaped = _html.escape(body, quote=False)
    paragraphs = [p for p in escaped.split("\n\n") if p.strip() != ""]
    if not paragraphs:
        return ""
    rendered = "\n".join("<p>" + p.replace("\n", "<br>") + "</p>" for p in paragraphs)
    return rendered


async def _resend_send_email(params: dict, api_key: str, start: float) -> dict:
    """Send an email via the Resend API (https://resend.com/docs/api-reference/emails/send-email)."""
    to_addr = params.get("to", "")
    subject = params.get("subject", "(no subject)")
    body = params.get("body", "")

    # Build Resend API payload
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [to_addr] if isinstance(to_addr, str) else to_addr,
        "subject": subject,
        "text": body,
    }

    # Always send an HTML view alongside the plain text — most modern mail
    # clients prefer HTML, and without one they'd render the plain text
    # with inconsistent line-break handling.
    #
    # If the body is actually HTML (contains structural tags), pass it
    # through unchanged. Otherwise treat it as plain text and convert
    # newlines to paragraph/line breaks so formatting survives.
    payload["html"] = body if _looks_like_html(body) else _plain_text_to_html(body)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200 or resp.status_code == 201:
                result = resp.json()
                return {
                    "result": {
                        "status": "sent",
                        "email_id": result.get("id", "unknown"),
                        "to": to_addr,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "resend_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"resend_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _substack_create_post(
    params: dict, session_cookie: str, start: float
) -> dict:
    """Create a draft post on Substack via its internal API.

    Uses the substack.sid session cookie for authentication.
    Creates the post as a draft — publishing requires a separate step.
    """
    if not SUBSTACK_BASE_URL:
        return {
            "result": {"error": "SUBSTACK_BASE_URL not configured"},
            "execution_ms": 0,
            "simulated": False,
        }

    title = params.get("title", "(untitled)")
    body = params.get("body", "")
    is_newsletter = params.get("is_newsletter", False)

    # Substack internal API: create draft
    # Body uses ProseMirror document format (Substack's editor format)
    body_content = []
    for para in body.split("\n\n"):
        para = para.strip()
        if not para:
            continue
        body_content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": para}],
            }
        )

    api_url = f"{SUBSTACK_BASE_URL}/api/v1/drafts"
    payload = {
        "draft_title": title,
        "draft_subtitle": "",
        "draft_body": json.dumps({"type": "doc", "content": body_content}),
        "audience": "everyone",
        "type": "newsletter" if is_newsletter else "thread",
        "draft_bylines": [],
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                api_url,
                json=payload,
                cookies={"substack.sid": session_cookie},
                headers={
                    "Content-Type": "application/json",
                    "Origin": SUBSTACK_BASE_URL,
                    "Referer": f"{SUBSTACK_BASE_URL}/publish",
                    "User-Agent": _BROWSER_UA,
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 201):
                result = resp.json()
                return {
                    "result": {
                        "status": "draft_created",
                        "draft_id": result.get("id"),
                        "slug": result.get("slug", ""),
                        "title": title,
                        "edit_url": f"{SUBSTACK_BASE_URL}/publish/post/{result.get('id', '')}",
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "substack_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"substack_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


# ── Substack Notes ─────────────────────────────────────────────────────────
# Substack Notes are short-form content stored as comments with type="feed".
# Confirmed endpoints (undocumented API, verified 2026-04-12):
#   Create: POST /api/v1/comment/feed   (requires Origin header for CSRF)
#   List:   GET  /api/v1/notes
#   Delete: DELETE /api/v1/comment/{id}  (requires Origin header for CSRF)


async def _substack_create_note(
    params: dict, session_cookie: str, start: float
) -> dict:
    """Create a new Substack Note (short-form content).

    Notes are Substack's short-form format (similar to tweets).
    Internally stored as comments with type="feed".
    Auth via substack.sid session cookie. Requires Origin header for CSRF.
    """
    if not SUBSTACK_BASE_URL:
        return {
            "result": {"error": "SUBSTACK_BASE_URL not configured"},
            "execution_ms": 0,
            "simulated": False,
        }

    body = params.get("body", "")
    attachment_url = params.get("attachment_url")
    attachment_image = params.get("attachment_image")

    # Build ProseMirror body content (Substack's editor format)
    body_content = []
    for para in body.split("\n\n"):
        para = para.strip()
        if not para:
            continue
        body_content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": para}],
            }
        )

    body_json = {
        "type": "doc",
        "attrs": {"schemaVersion": "v1"},
        "content": body_content,
    }

    payload = {
        "bodyJson": body_json,
        "body": body,
        "type": "feed",
    }

    # Optional attachments
    attachments = []
    if attachment_url:
        attachments.append({"type": "link", "url": attachment_url})
    if attachment_image:
        attachments.append({"type": "image", "url": attachment_image})
    if attachments:
        payload["attachments"] = attachments

    api_url = f"{SUBSTACK_BASE_URL}/api/v1/comment/feed"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                api_url,
                json=payload,
                cookies={"substack.sid": session_cookie},
                headers={
                    "Content-Type": "application/json",
                    "Origin": SUBSTACK_BASE_URL,
                    "Referer": f"{SUBSTACK_BASE_URL}/notes",
                    "User-Agent": _BROWSER_UA,
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 201):
                result = resp.json()
                return {
                    "result": {
                        "status": "note_created",
                        "note_id": result.get("id"),
                        "body_preview": body[:140],
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "substack_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"substack_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _substack_get_notes(params: dict, session_cookie: str, start: float) -> dict:
    """List recent Substack Notes with optional pagination.

    Auth via substack.sid session cookie.
    """
    if not SUBSTACK_BASE_URL:
        return {
            "result": {"error": "SUBSTACK_BASE_URL not configured"},
            "execution_ms": 0,
            "simulated": False,
        }

    limit = params.get("limit", 20)
    offset = params.get("offset", 0)
    api_url = f"{SUBSTACK_BASE_URL}/api/v1/notes?limit={limit}&offset={offset}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                api_url,
                cookies={"substack.sid": session_cookie},
                headers={"User-Agent": _BROWSER_UA},
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                result = resp.json()
                # Response is {items: [...]} where each item has a .comment field
                items = result.get("items", [])
                notes = []
                for item in items:
                    comment = item.get("comment", {})
                    notes.append(
                        {
                            "note_id": comment.get("id"),
                            "body": comment.get("body", ""),
                            "date": comment.get("date"),
                            "reaction_count": comment.get("reaction_count", 0),
                            "restacks": comment.get("restacks", 0),
                            "children_count": comment.get("children_count", 0),
                        }
                    )
                return {
                    "result": {
                        "status": "ok",
                        "notes": notes,
                        "count": len(notes),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "substack_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"substack_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _substack_delete_note(
    params: dict, session_cookie: str, start: float
) -> dict:
    """Delete a Substack Note by ID.

    Auth via substack.sid session cookie. Requires Origin header for CSRF.
    """
    if not SUBSTACK_BASE_URL:
        return {
            "result": {"error": "SUBSTACK_BASE_URL not configured"},
            "execution_ms": 0,
            "simulated": False,
        }

    note_id = params.get("note_id")
    if not note_id:
        return {
            "result": {"error": "note_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    api_url = f"{SUBSTACK_BASE_URL}/api/v1/comment/{note_id}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(
                api_url,
                cookies={"substack.sid": session_cookie},
                headers={
                    "Origin": SUBSTACK_BASE_URL,
                    "Referer": f"{SUBSTACK_BASE_URL}/notes",
                    "User-Agent": _BROWSER_UA,
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 204):
                return {
                    "result": {
                        "status": "note_deleted",
                        "note_id": note_id,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "substack_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"substack_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


# ── Twitter / X ────────────────────────────────────────────────────────────
# Twitter API v2 (https://developer.x.com/en/docs/twitter-api)
# Write endpoints (create/delete tweet) require OAuth 1.0a User Context.
# Read endpoints (get tweets) can use App-Only Bearer token.
#
# Credential format (stored as JSON in HSM vault):
#   {"api_key": "...", "api_secret": "...", "access_token": "...", "access_secret": "..."}

TWITTER_API_BASE = "https://api.twitter.com/2"


def _parse_twitter_credential(credential: str) -> dict:
    """Parse a Twitter credential.

    Recognises three shapes and tags them with ``_vargate_auth``:

      - OAuth 2.0 (User Context):
          {"client_id", "client_secret", "refresh_token", ...}
          → ``_vargate_auth`` = ``"oauth2"``.
      - OAuth 1.0a (User Context):
          {"api_key", "api_secret", "access_token", "access_secret"}
          → ``_vargate_auth`` = ``"oauth1a"``.
      - Bearer (App-Only, read-only):
          raw string → {"bearer_token": ...}
          → ``_vargate_auth`` = ``"bearer"``.

    The tag lets downstream handlers pick the right request builder
    without re-sniffing fields.
    """
    try:
        cred = json.loads(credential)
        if isinstance(cred, dict):
            if "client_id" in cred and "refresh_token" in cred:
                return {**cred, "_vargate_auth": "oauth2"}
            if "api_key" in cred:
                return {**cred, "_vargate_auth": "oauth1a"}
    except (json.JSONDecodeError, TypeError):
        pass
    return {"bearer_token": credential, "_vargate_auth": "bearer"}


# ── OAuth 2.0 access-token management ──────────────────────────────────────
# Access tokens are short-lived (~2h). We cache them alongside the
# refresh_token in the vault and proactively refresh when <60s remains.
# Refreshed tokens MUST be persisted back to the vault BEFORE being used,
# because Twitter rotates the refresh_token on every refresh and the old
# one is immediately invalidated.

_TWITTER_REFRESH_BUFFER_S = 60


async def _twitter_get_bearer_access_token(cred: dict) -> str:
    """Return a valid access_token for the OAuth 2.0 credential, refreshing
    and persisting if necessary.

    Raises RuntimeError with a structured message on refresh failure;
    callers should translate that into a clean API response.
    """
    from oauth_twitter import refresh_access_token

    access_token = cred.get("access_token", "")
    expires_at = int(cred.get("access_token_expires_at") or 0)
    now = int(time.time())

    if access_token and expires_at > now + _TWITTER_REFRESH_BUFFER_S:
        return access_token

    # Stale or missing — refresh
    try:
        tokens = await refresh_access_token(
            client_id=cred["client_id"],
            client_secret=cred["client_secret"],
            refresh_token=cred["refresh_token"],
        )
    except Exception as e:
        raise RuntimeError(f"twitter_oauth2_refresh_failed: {e}")

    new_value = {
        "client_id": cred["client_id"],
        "client_secret": cred["client_secret"],
        "refresh_token": tokens["refresh_token"],
        "access_token": tokens["access_token"],
        "access_token_expires_at": now + int(tokens.get("expires_in", 7200)),
        "scope": tokens.get("scope", cred.get("scope", "")),
    }

    # Persist BEFORE using the new access_token — if we crash between
    # refresh and persist, the old refresh_token is already invalid,
    # so we must never return an access_token that hasn't been saved.
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{HSM_URL}/credentials",
            json={
                "tool_id": "twitter",
                "name": "oauth2",
                "value": json.dumps(new_value),
            },
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"twitter_oauth2_persist_failed: HSM returned {resp.status_code}"
            )

    return tokens["access_token"]


def _oauth1_header(method: str, url: str, cred: dict, body: str = "") -> dict:
    """Build OAuth 1.0a Authorization header for Twitter API v2.

    Implements the OAuth 1.0a signature base string and HMAC-SHA1 signing
    as specified by RFC 5849, using only stdlib modules.
    """
    import base64
    import hashlib
    import hmac
    import urllib.parse

    api_key = cred["api_key"]
    api_secret = cred["api_secret"]
    access_token = cred["access_token"]
    access_secret = cred["access_secret"]

    oauth_params = {
        "oauth_consumer_key": api_key,
        "oauth_nonce": os.urandom(16).hex(),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_token": access_token,
        "oauth_version": "1.0",
    }

    # Parse URL query params
    parsed = urllib.parse.urlparse(url)
    query_params = dict(urllib.parse.parse_qsl(parsed.query))
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Combine all params for signature base string (exclude body for JSON requests)
    all_params = {**query_params, **oauth_params}
    param_string = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}"
        for k, v in sorted(all_params.items())
    )

    base_string = (
        f"{method.upper()}&"
        f"{urllib.parse.quote(base_url, safe='')}&"
        f"{urllib.parse.quote(param_string, safe='')}"
    )

    signing_key = (
        f"{urllib.parse.quote(api_secret, safe='')}&"
        f"{urllib.parse.quote(access_secret, safe='')}"
    )

    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
    ).decode()

    oauth_params["oauth_signature"] = signature

    auth_header = "OAuth " + ", ".join(
        f'{urllib.parse.quote(k, safe="")}="{urllib.parse.quote(v, safe="")}"'
        for k, v in sorted(oauth_params.items())
    )

    return {"Authorization": auth_header}


async def _twitter_auth_headers(
    method: str, url: str, cred: dict, body: str = ""
) -> dict:
    """Build auth headers for a Twitter write call.

    OAuth 2.0 User Context → ``Authorization: Bearer <access>``.
    OAuth 1.0a User Context → RFC 5849-signed Authorization header.
    Raises RuntimeError on unsupported auth.
    """
    auth = cred.get("_vargate_auth")
    if auth == "oauth2":
        token = await _twitter_get_bearer_access_token(cred)
        return {"Authorization": f"Bearer {token}"}
    if auth == "oauth1a":
        return _oauth1_header(method, url, cred, body)
    raise RuntimeError(
        "twitter_auth_error: write endpoints require OAuth 1.0a or OAuth 2.0 User Context"
    )


async def _twitter_create_tweet(params: dict, credential: str, start: float) -> dict:
    """Create a tweet via Twitter API v2. Works with OAuth 2.0 User Context
    (preferred) or OAuth 1.0a."""
    text = params.get("text", "")
    if not text:
        return {
            "result": {"error": "text is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    if len(text) > 280:
        return {
            "result": {
                "error": "tweet_too_long",
                "length": len(text),
                "max": 280,
                "detail": f"Tweet is {len(text)} characters — Twitter limit is 280.",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_twitter_credential(credential)
    if cred.get("_vargate_auth") == "bearer":
        return {
            "result": {
                "error": "twitter_auth_error",
                "detail": "Creating tweets requires OAuth 1.0a or OAuth 2.0 "
                "User Context. Connect via the Vault Management UI.",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    url = f"{TWITTER_API_BASE}/tweets"
    payload = json.dumps({"text": text})

    try:
        auth_headers = await _twitter_auth_headers("POST", url, cred, payload)
        auth_headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, content=payload, headers=auth_headers)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 201):
                result = resp.json()
                data = result.get("data", {})
                return {
                    "result": {
                        "status": "tweet_created",
                        "tweet_id": data.get("id"),
                        "text": data.get("text", text),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "twitter_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _twitter_delete_tweet(params: dict, credential: str, start: float) -> dict:
    """Delete a tweet via Twitter API v2. OAuth 1.0a or OAuth 2.0."""
    tweet_id = params.get("tweet_id")
    if not tweet_id:
        return {
            "result": {"error": "tweet_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_twitter_credential(credential)
    if cred.get("_vargate_auth") == "bearer":
        return {
            "result": {
                "error": "twitter_auth_error",
                "detail": "Deleting tweets requires OAuth 1.0a or OAuth 2.0 User Context.",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    url = f"{TWITTER_API_BASE}/tweets/{tweet_id}"

    try:
        auth_headers = await _twitter_auth_headers("DELETE", url, cred)

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(url, headers=auth_headers)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 204):
                result = resp.json() if resp.text else {}
                deleted = result.get("data", {}).get("deleted", True)
                return {
                    "result": {
                        "status": "tweet_deleted",
                        "tweet_id": tweet_id,
                        "deleted": deleted,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            else:
                error_body = resp.text
                try:
                    error_body = resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "twitter_api_error",
                        "status_code": resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _twitter_get_user_tweets(params: dict, credential: str, start: float) -> dict:
    """Get recent tweets for a user via Twitter API v2.

    Uses App-Only Bearer token (or OAuth 1.0a if available).
    Note: This endpoint requires the Basic ($100/mo) tier.
    Free tier returns 403.
    """
    user_id = params.get("user_id")
    if not user_id:
        return {
            "result": {"error": "user_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    max_results = params.get("max_results", 10)
    cred = _parse_twitter_credential(credential)
    url = f"{TWITTER_API_BASE}/users/{user_id}/tweets"
    auth = cred.get("_vargate_auth")

    if auth == "oauth2":
        token = await _twitter_get_bearer_access_token(cred)
        auth_headers = {"Authorization": f"Bearer {token}"}
    elif auth == "oauth1a":
        auth_headers = _oauth1_header("GET", f"{url}?max_results={max_results}", cred)
    else:
        auth_headers = {
            "Authorization": f"Bearer {cred.get('bearer_token', credential)}"
        }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                url,
                params={"max_results": max_results},
                headers=auth_headers,
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                result = resp.json()
                tweets = result.get("data", [])
                return {
                    "result": {
                        "status": "ok",
                        "tweets": tweets,
                        "count": len(tweets),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }
            return _twitter_error_response(resp, elapsed_ms)

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


def _twitter_error_response(resp: httpx.Response, elapsed_ms: int) -> dict:
    """Translate a non-success Twitter response into the proxy's result shape.

    Credit-exhaustion errors (402 + ``problems/credits`` type) get a
    dedicated error code so agents and reviewers can spot them without
    having to parse the nested Twitter payload. Everything else falls
    through to a generic ``twitter_api_error`` with the raw detail.
    """
    error_body = resp.text
    try:
        error_body = resp.json()
    except Exception:
        pass

    # Credit-depleted pattern (Twitter's replacement for old tier limits):
    # 402 with type URI ending in problems/credits, or "CreditsDepleted"
    # title. Surface a distinct error code so callers can route to
    # "top up credits" rather than treating it as generic auth.
    type_uri = ""
    title = ""
    if isinstance(error_body, dict):
        # Wrapper shape varies: sometimes top-level, sometimes under "error"
        payload = (
            error_body.get("error", error_body) if isinstance(error_body, dict) else {}
        )
        if isinstance(payload, dict):
            type_uri = str(payload.get("type", ""))
            title = str(payload.get("title", ""))

    if (
        resp.status_code == 402
        or "problems/credits" in type_uri
        or title == "CreditsDepleted"
    ):
        return {
            "result": {
                "error": "twitter_credits_depleted",
                "status_code": resp.status_code,
                "detail": (
                    "Twitter API credits are depleted. Top up at "
                    "developer.x.com to continue. Twitter uses a credit-based "
                    "pricing model — each endpoint consumes a configurable "
                    "number of credits per call."
                ),
                "raw": error_body,
            },
            "execution_ms": elapsed_ms,
            "simulated": False,
        }

    return {
        "result": {
            "error": "twitter_api_error",
            "status_code": resp.status_code,
            "detail": error_body,
        },
        "execution_ms": elapsed_ms,
        "simulated": False,
    }


# ── Twitter: search ────────────────────────────────────────────────────────
# Recent-search (last 7 days) via /2/tweets/search/recent. Works with
# OAuth 2.0 User Context or App-Only Bearer. Credit cost applies per call.


async def _twitter_search_recent(params: dict, credential: str, start: float) -> dict:
    """Search recent tweets (last 7 days) matching a query.

    Params:
      - ``query`` (required): Twitter search operator string, e.g.
        ``"vargate.ai -is:retweet lang:en"``.
        Reference: developer.x.com/en/docs/twitter-api/tweets/search/integrate/build-a-query
      - ``max_results`` (optional, default 10, max 100): how many to return.
      - ``start_time`` / ``end_time`` (optional, ISO 8601): narrow the window.

    Read-only — no approval required. Consumes Twitter API credits per call.
    """
    query = params.get("query", "")
    if not query:
        return {
            "result": {"error": "query is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    max_results = int(params.get("max_results", 10))
    if max_results < 10:
        max_results = 10  # Twitter rejects <10 on recent search
    if max_results > 100:
        max_results = 100

    cred = _parse_twitter_credential(credential)
    url = f"{TWITTER_API_BASE}/tweets/search/recent"

    query_params = {
        "query": query,
        "max_results": max_results,
        "tweet.fields": "id,text,created_at,author_id,public_metrics,lang",
        "expansions": "author_id",
        "user.fields": "id,username,name,verified",
    }
    if params.get("start_time"):
        query_params["start_time"] = params["start_time"]
    if params.get("end_time"):
        query_params["end_time"] = params["end_time"]

    try:
        auth = cred.get("_vargate_auth")
        if auth == "oauth2":
            token = await _twitter_get_bearer_access_token(cred)
            auth_headers = {"Authorization": f"Bearer {token}"}
        elif auth == "oauth1a":
            # OAuth 1.0a signature needs the full query string baked into the URL
            from urllib.parse import urlencode

            signed_url = f"{url}?{urlencode(query_params)}"
            auth_headers = _oauth1_header("GET", signed_url, cred)
        else:
            # App-only bearer token
            auth_headers = {
                "Authorization": f"Bearer {cred.get('bearer_token', credential)}"
            }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, params=query_params, headers=auth_headers)
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                result = resp.json()
                tweets = result.get("data", [])
                users_by_id = {
                    u["id"]: u for u in result.get("includes", {}).get("users", [])
                }
                # Decorate each tweet with its author's username/name for easier
                # downstream use — otherwise the caller has to join manually.
                enriched = []
                for t in tweets:
                    author = users_by_id.get(t.get("author_id"), {})
                    enriched.append(
                        {
                            **t,
                            "author_username": author.get("username"),
                            "author_name": author.get("name"),
                        }
                    )
                meta = result.get("meta", {})
                return {
                    "result": {
                        "status": "ok",
                        "tweets": enriched,
                        "count": len(enriched),
                        "result_count": meta.get("result_count", len(enriched)),
                        "newest_id": meta.get("newest_id"),
                        "oldest_id": meta.get("oldest_id"),
                        "next_token": meta.get("next_token"),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            return _twitter_error_response(resp, elapsed_ms)

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


# ── Twitter: follows and DMs (OAuth 2.0 required) ─────────────────────────
# These endpoints aren't supported by OAuth 1.0a on the v2 API. If the
# tenant's credential is OAuth 1.0a, we return an auth_error directing
# them to connect via OAuth 2.0 in the Vault UI.


def _require_oauth2_for(cred: dict, feature: str) -> Optional[dict]:
    """Return an error response dict if cred is not OAuth 2.0; else None."""
    if cred.get("_vargate_auth") != "oauth2":
        return {
            "result": {
                "error": "twitter_auth_error",
                "detail": (
                    f"{feature} requires OAuth 2.0 User Context on the v2 API. "
                    "Use the 'Connect with Twitter' button in Vault Management "
                    "to authorise — OAuth 1.0a cannot call this endpoint."
                ),
            },
            "execution_ms": 0,
            "simulated": False,
        }
    return None


async def _twitter_current_user_id(access_token: str) -> str:
    """Fetch the authenticated user's numeric id via /2/users/me."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{TWITTER_API_BASE}/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()["data"]["id"]


async def _twitter_follow_user(params: dict, credential: str, start: float) -> dict:
    """Follow another user. Requires OAuth 2.0 with ``follows.write``.

    Params: ``target_user_id`` (required). If ``source_user_id`` is
    omitted we fetch /users/me to discover the authenticated user's id.
    """
    target_id = params.get("target_user_id")
    if not target_id:
        return {
            "result": {"error": "target_user_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_twitter_credential(credential)
    bad = _require_oauth2_for(cred, "Following a user")
    if bad:
        return bad

    try:
        access_token = await _twitter_get_bearer_access_token(cred)
        source_id = params.get("source_user_id") or await _twitter_current_user_id(
            access_token
        )
        url = f"{TWITTER_API_BASE}/users/{source_id}/following"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                json={"target_user_id": str(target_id)},
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 201):
                data = resp.json().get("data", {})
                return {
                    "result": {
                        "status": "following",
                        "target_user_id": str(target_id),
                        "source_user_id": str(source_id),
                        "pending_follow": data.get("pending_follow", False),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            error_body = resp.text
            try:
                error_body = resp.json()
            except Exception:
                pass
            return {
                "result": {
                    "error": "twitter_api_error",
                    "status_code": resp.status_code,
                    "detail": error_body,
                },
                "execution_ms": elapsed_ms,
                "simulated": False,
            }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _twitter_unfollow_user(params: dict, credential: str, start: float) -> dict:
    """Unfollow another user. Requires OAuth 2.0 with ``follows.write``."""
    target_id = params.get("target_user_id")
    if not target_id:
        return {
            "result": {"error": "target_user_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_twitter_credential(credential)
    bad = _require_oauth2_for(cred, "Unfollowing a user")
    if bad:
        return bad

    try:
        access_token = await _twitter_get_bearer_access_token(cred)
        source_id = params.get("source_user_id") or await _twitter_current_user_id(
            access_token
        )
        url = f"{TWITTER_API_BASE}/users/{source_id}/following/{target_id}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(
                url, headers={"Authorization": f"Bearer {access_token}"}
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 204):
                data = resp.json().get("data", {}) if resp.text else {}
                return {
                    "result": {
                        "status": "unfollowed",
                        "target_user_id": str(target_id),
                        "source_user_id": str(source_id),
                        "following": data.get("following", False),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            error_body = resp.text
            try:
                error_body = resp.json()
            except Exception:
                pass
            return {
                "result": {
                    "error": "twitter_api_error",
                    "status_code": resp.status_code,
                    "detail": error_body,
                },
                "execution_ms": elapsed_ms,
                "simulated": False,
            }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


TWITTER_DM_MAX = 10000


async def _twitter_send_dm(params: dict, credential: str, start: float) -> dict:
    """Send a direct message to a user. Requires OAuth 2.0 with ``dm.write``.

    Params: ``participant_id`` (recipient's numeric Twitter user id),
    ``text`` (message body, up to 10,000 chars per Twitter's docs).

    Note: the recipient must have DMs open for strangers OR already follow
    Sera, or Twitter will return a 403. That constraint is on Twitter's
    side, not something the proxy can pre-check.
    """
    participant_id = params.get("participant_id")
    text = params.get("text", "")

    if not participant_id:
        return {
            "result": {"error": "participant_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }
    if not text:
        return {
            "result": {"error": "text is required"},
            "execution_ms": 0,
            "simulated": False,
        }
    if len(text) > TWITTER_DM_MAX:
        return {
            "result": {
                "error": "dm_too_long",
                "length": len(text),
                "max": TWITTER_DM_MAX,
            },
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_twitter_credential(credential)
    bad = _require_oauth2_for(cred, "Sending a DM")
    if bad:
        return bad

    try:
        access_token = await _twitter_get_bearer_access_token(cred)
        url = f"{TWITTER_API_BASE}/dm_conversations/with/{participant_id}/messages"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                json={"text": text},
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code in (200, 201):
                data = resp.json().get("data", {})
                return {
                    "result": {
                        "status": "dm_sent",
                        "dm_conversation_id": data.get("dm_conversation_id"),
                        "dm_event_id": data.get("dm_event_id"),
                        "participant_id": str(participant_id),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            error_body = resp.text
            try:
                error_body = resp.json()
            except Exception:
                pass
            return {
                "result": {
                    "error": "twitter_api_error",
                    "status_code": resp.status_code,
                    "detail": error_body,
                },
                "execution_ms": elapsed_ms,
                "simulated": False,
            }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


async def _twitter_list_dm_conversations(
    params: dict, credential: str, start: float
) -> dict:
    """List recent DM conversations. Requires OAuth 2.0 with ``dm.read``.

    Read-only — no content sent. Does not require approval by default.
    """
    cred = _parse_twitter_credential(credential)
    bad = _require_oauth2_for(cred, "Listing DM conversations")
    if bad:
        return bad

    max_results = int(params.get("max_results", 20))

    try:
        access_token = await _twitter_get_bearer_access_token(cred)
        url = f"{TWITTER_API_BASE}/dm_events"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                url,
                params={
                    "max_results": max_results,
                    "dm_event.fields": "id,event_type,text,created_at,sender_id,dm_conversation_id",
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                result = resp.json()
                events = result.get("data", [])
                return {
                    "result": {
                        "status": "ok",
                        "events": events,
                        "count": len(events),
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            error_body = resp.text
            try:
                error_body = resp.json()
            except Exception:
                pass
            return {
                "result": {
                    "error": "twitter_api_error",
                    "status_code": resp.status_code,
                    "detail": error_body,
                },
                "execution_ms": elapsed_ms,
                "simulated": False,
            }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"twitter_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


# ── Instagram ──────────────────────────────────────────────────────────────
# Instagram Graph API (https://developers.facebook.com/docs/instagram-api)
# Content Publishing is a two-step flow:
#   1. POST /{ig-user-id}/media   → creation_id
#   2. POST /{ig-user-id}/media_publish  → media_id
# Requires a Business or Creator IG account connected to a Facebook Page,
# and a long-lived OAuth 2.0 access token with instagram_content_publish.
#
# Credential format (stored as JSON in HSM vault):
#   {"access_token": "...", "ig_user_id": "..."}

INSTAGRAM_API_BASE = "https://graph.facebook.com/v21.0"
INSTAGRAM_CAPTION_MAX = 2200
# Meta processes uploaded media asynchronously. Publish fails with
# "Media ID is not available" if we call /media_publish before the
# container reaches status_code=FINISHED, so poll the container first.
INSTAGRAM_PUBLISH_POLL_INTERVAL_S = 2.0
INSTAGRAM_PUBLISH_POLL_TIMEOUT_S = 60.0


def _parse_instagram_credential(credential: str) -> dict:
    """Parse Instagram credential — JSON with access_token and ig_user_id."""
    try:
        cred = json.loads(credential)
        if isinstance(cred, dict) and "access_token" in cred and "ig_user_id" in cred:
            return cred
    except (json.JSONDecodeError, TypeError):
        pass
    return {}


async def _instagram_create_post(params: dict, credential: str, start: float) -> dict:
    """Publish a single-image post via the Instagram Graph API.

    Expected params: { "image_url": "<public https url>", "caption": "..." }
    Instagram fetches the image from image_url — it must be a public HTTPS URL
    pointing to a JPEG. No file uploads.
    """
    image_url = params.get("image_url", "")
    caption = params.get("caption", "")

    if not image_url:
        return {
            "result": {
                "error": "image_url_required",
                "detail": "Instagram requires a public HTTPS image_url. "
                "Caption-only posts are not supported.",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    if not image_url.lower().startswith("https://"):
        return {
            "result": {
                "error": "image_url_must_be_https",
                "detail": f"image_url must be a public HTTPS URL; got: {image_url[:80]}",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    if len(caption) > INSTAGRAM_CAPTION_MAX:
        return {
            "result": {
                "error": "caption_too_long",
                "length": len(caption),
                "max": INSTAGRAM_CAPTION_MAX,
                "detail": (
                    f"Caption is {len(caption)} characters — "
                    f"Instagram limit is {INSTAGRAM_CAPTION_MAX}."
                ),
            },
            "execution_ms": 0,
            "simulated": False,
        }

    cred = _parse_instagram_credential(credential)
    if not cred:
        return {
            "result": {
                "error": "instagram_auth_error",
                "detail": "Instagram requires a JSON credential with "
                "access_token and ig_user_id fields.",
            },
            "execution_ms": 0,
            "simulated": False,
        }

    access_token = cred["access_token"]
    ig_user_id = cred["ig_user_id"]

    create_url = f"{INSTAGRAM_API_BASE}/{ig_user_id}/media"
    publish_url = f"{INSTAGRAM_API_BASE}/{ig_user_id}/media_publish"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1 — create media container
            create_resp = await client.post(
                create_url,
                data={
                    "image_url": image_url,
                    "caption": caption,
                    "access_token": access_token,
                },
            )
            if create_resp.status_code != 200:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                error_body = create_resp.text
                try:
                    error_body = create_resp.json()
                except Exception:
                    pass
                return {
                    "result": {
                        "error": "instagram_api_error",
                        "stage": "create_media",
                        "status_code": create_resp.status_code,
                        "detail": error_body,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            creation_id = create_resp.json().get("id")
            if not creation_id:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return {
                    "result": {
                        "error": "instagram_api_error",
                        "stage": "create_media",
                        "detail": "No creation_id returned by Instagram.",
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            # Step 2 — wait until Meta finishes processing the media.
            # Container status_code transitions IN_PROGRESS → FINISHED (or ERROR
            # / EXPIRED). Publishing before FINISHED returns a misleading
            # "Media ID is not available" error.
            status_url = f"{INSTAGRAM_API_BASE}/{creation_id}"
            deadline = time.monotonic() + INSTAGRAM_PUBLISH_POLL_TIMEOUT_S
            last_status = None
            while True:
                status_resp = await client.get(
                    status_url,
                    params={
                        "fields": "status_code,status",
                        "access_token": access_token,
                    },
                )
                if status_resp.status_code == 200:
                    last_status = status_resp.json()
                    code = last_status.get("status_code")
                    if code == "FINISHED":
                        break
                    if code in ("ERROR", "EXPIRED"):
                        elapsed_ms = int((time.monotonic() - start) * 1000)
                        return {
                            "result": {
                                "error": "instagram_api_error",
                                "stage": "status_poll",
                                "creation_id": creation_id,
                                "detail": last_status,
                            },
                            "execution_ms": elapsed_ms,
                            "simulated": False,
                        }
                if time.monotonic() >= deadline:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    return {
                        "result": {
                            "error": "instagram_publish_timeout",
                            "stage": "status_poll",
                            "creation_id": creation_id,
                            "timeout_s": INSTAGRAM_PUBLISH_POLL_TIMEOUT_S,
                            "last_status": last_status,
                            "detail": (
                                "Meta did not finish processing the media "
                                "within the timeout. The creation_id may still "
                                "finish; retry may succeed."
                            ),
                        },
                        "execution_ms": elapsed_ms,
                        "simulated": False,
                    }
                await asyncio.sleep(INSTAGRAM_PUBLISH_POLL_INTERVAL_S)

            # Step 3 — publish the container now that it's FINISHED
            publish_resp = await client.post(
                publish_url,
                data={
                    "creation_id": creation_id,
                    "access_token": access_token,
                },
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            if publish_resp.status_code == 200:
                data = publish_resp.json()
                return {
                    "result": {
                        "status": "post_created",
                        "media_id": data.get("id"),
                        "creation_id": creation_id,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": False,
                }

            error_body = publish_resp.text
            try:
                error_body = publish_resp.json()
            except Exception:
                pass
            return {
                "result": {
                    "error": "instagram_api_error",
                    "stage": "media_publish",
                    "status_code": publish_resp.status_code,
                    "creation_id": creation_id,
                    "detail": error_body,
                },
                "execution_ms": elapsed_ms,
                "simulated": False,
            }

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"instagram_execution_failed: {str(e)}"},
            "execution_ms": elapsed_ms,
            "simulated": False,
        }


# ── Mock tool execution ────────────────────────────────────────────────────


async def _execute_mock(tool: str, method: str, params: dict, credential: str) -> dict:
    """Execute via the mock tool server."""
    if MOCK_TOOLS_URL is None:
        return {
            "result": {"error": "execution_engine_not_initialized"},
            "execution_ms": 0,
            "simulated": True,
        }

    # Find the endpoint
    tool_methods = TOOL_ENDPOINTS.get(tool)
    if not tool_methods:
        return {
            "result": {"error": f"unknown_tool: {tool}", "simulated": True},
            "execution_ms": 0,
            "simulated": True,
        }

    endpoint = tool_methods.get(method)
    if not endpoint:
        return {
            "result": {"error": f"unknown_method: {tool}/{method}", "simulated": True},
            "execution_ms": 0,
            "simulated": True,
        }

    # Execute the call
    url = f"{MOCK_TOOLS_URL}{endpoint}"
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json=params,
                headers={
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/json",
                },
            )

            elapsed_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 401:
                return {
                    "result": {
                        "error": "credential_rejected",
                        "status_code": 401,
                        "detail": (
                            resp.json()
                            if resp.headers.get("content-type", "").startswith(
                                "application/json"
                            )
                            else resp.text
                        ),
                        "simulated": True,
                    },
                    "execution_ms": elapsed_ms,
                    "simulated": True,
                }

            result = resp.json()

    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "result": {"error": f"execution_failed: {str(e)}", "simulated": True},
            "execution_ms": elapsed_ms,
            "simulated": True,
        }

    return {
        "result": result,
        "execution_ms": elapsed_ms,
        "simulated": result.get("simulated", True),
    }
