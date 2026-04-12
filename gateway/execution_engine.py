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
REAL_API_TOOLS = {"resend", "substack"}


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
                headers={"Content-Type": "application/json"},
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
