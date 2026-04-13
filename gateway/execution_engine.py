"""
Vargate Execution Engine — Agent-Blind Tool Execution

Executes approved tool calls on behalf of agents using HSM-stored credentials.
Supports both mock tools (via mock server) and real APIs (Resend, etc.).
Credential values are used for Authorization headers but never logged or stored.
"""

import json
import os
import time

import httpx

MOCK_TOOLS_URL = None  # Set during gateway startup
RESEND_FROM_EMAIL = os.environ.get(
    "RESEND_FROM_EMAIL", "Sera (Vargate.ai) <sera@vargate.ai>"
)
SUBSTACK_BASE_URL = os.environ.get("SUBSTACK_BASE_URL", "")
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
REAL_API_TOOLS = {"resend", "substack", "twitter"}


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

    return {
        "result": {"error": f"unknown_real_method: {tool}/{method}"},
        "execution_ms": 0,
        "simulated": False,
    }


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

    # If body contains HTML tags, send as HTML too
    if "<" in body and ">" in body:
        payload["html"] = body

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


async def _substack_create_post(params: dict, session_cookie: str, start: float) -> dict:
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
        body_content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": para}],
        })

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


async def _substack_create_note(params: dict, session_cookie: str, start: float) -> dict:
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
        body_content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": para}],
        })

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
                    notes.append({
                        "note_id": comment.get("id"),
                        "body": comment.get("body", ""),
                        "date": comment.get("date"),
                        "reaction_count": comment.get("reaction_count", 0),
                        "restacks": comment.get("restacks", 0),
                        "children_count": comment.get("children_count", 0),
                    })
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


async def _substack_delete_note(params: dict, session_cookie: str, start: float) -> dict:
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
# Auth: OAuth 2.0 Bearer token (free tier supports create/delete tweets).

TWITTER_API_BASE = "https://api.twitter.com/2"


async def _twitter_create_tweet(params: dict, bearer_token: str, start: float) -> dict:
    """Create a tweet via Twitter API v2."""
    text = params.get("text", "")
    if not text:
        return {
            "result": {"error": "text is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{TWITTER_API_BASE}/tweets",
                json={"text": text},
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": "application/json",
                },
            )
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


async def _twitter_delete_tweet(params: dict, bearer_token: str, start: float) -> dict:
    """Delete a tweet via Twitter API v2."""
    tweet_id = params.get("tweet_id")
    if not tweet_id:
        return {
            "result": {"error": "tweet_id is required"},
            "execution_ms": 0,
            "simulated": False,
        }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(
                f"{TWITTER_API_BASE}/tweets/{tweet_id}",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
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


async def _twitter_get_user_tweets(params: dict, bearer_token: str, start: float) -> dict:
    """Get recent tweets for a user via Twitter API v2.

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

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{TWITTER_API_BASE}/users/{user_id}/tweets",
                params={"max_results": max_results},
                headers={"Authorization": f"Bearer {bearer_token}"},
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
            elif resp.status_code == 403:
                return {
                    "result": {
                        "error": "twitter_free_tier_limit",
                        "status_code": 403,
                        "detail": "Twitter free tier does not support reading tweets. "
                        "Upgrade to the Basic plan ($100/mo) at developer.x.com to use this endpoint.",
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
