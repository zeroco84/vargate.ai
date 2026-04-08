"""
Vargate Execution Engine — Agent-Blind Tool Execution

Executes approved tool calls on behalf of agents using HSM-stored credentials.
Supports both mock tools (via mock server) and real APIs (Resend, etc.).
Credential values are used for Authorization headers but never logged or stored.
"""

import os
import time
import httpx

MOCK_TOOLS_URL = None  # Set during gateway startup
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "Sera <sera@vargate.ai>")


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
REAL_API_TOOLS = {"resend"}


async def execute_tool_call(
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

async def _execute_real_api(tool: str, method: str, params: dict, credential: str) -> dict:
    """Execute a real API call (Resend, etc.)."""
    start = time.monotonic()

    if tool == "resend" and method == "send":
        return await _resend_send_email(params, credential, start)

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
                        "detail": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
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
