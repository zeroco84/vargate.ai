"""
Vargate Mock Tool Server — Simulated External APIs

Provides realistic mock endpoints for Gmail, Salesforce, Stripe, and Slack.
Validates Authorization headers to prove credential brokering works.
All responses include simulated: true — never pretends to be real.
"""

import time
import uuid
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Vargate Mock Tool Server", version="1.0.0")

# ── Registered mock credentials ──────────────────────────────────────────────
# In a real deployment these would be validated against an external system.
# Here we accept any non-empty Bearer token and track which ones we've seen.

_valid_tokens: dict[str, str] = {}  # tool_id -> expected token


def _register_token(tool_id: str, token: str):
    """Register a valid token for a tool (called via POST /admin/register-token)."""
    _valid_tokens[tool_id] = token


def _validate_auth(tool_id: str, authorization: str | None):
    """Validate the Authorization header. Returns the token value."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, {"error": "missing_authorization", "tool": tool_id})
    token = authorization[7:]
    if not token:
        raise HTTPException(401, {"error": "empty_token", "tool": tool_id})
    # If we have a registered token for this tool, validate it matches
    expected = _valid_tokens.get(tool_id)
    if expected and token != expected:
        raise HTTPException(
            401,
            {
                "error": "invalid_credential",
                "tool": tool_id,
                "message": "Token does not match registered credential",
            },
        )
    return token


# ── Admin endpoint to register expected tokens ──────────────────────────────


class RegisterTokenRequest(BaseModel):
    tool_id: str
    token: str


@app.post("/admin/register-token")
async def register_token(req: RegisterTokenRequest):
    """Register an expected token for strict validation."""
    _register_token(req.tool_id, req.token)
    return {"tool_id": req.tool_id, "registered": True}


# ── Gmail endpoints ─────────────────────────────────────────────────────────


class GmailSendRequest(BaseModel):
    to: str
    subject: str = "No Subject"
    body: str = ""


@app.post("/gmail/send")
async def gmail_send(req: GmailSendRequest, authorization: str | None = Header(None)):
    _validate_auth("gmail", authorization)
    time.sleep(0.02)  # Simulate network latency

    return {
        "message_id": f"msg-{uuid.uuid4().hex[:12]}",
        "to": req.to,
        "subject": req.subject,
        "status": "sent",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "simulated": True,
    }


# ── Salesforce endpoints ────────────────────────────────────────────────────


class SalesforceReadRequest(BaseModel):
    object_type: str = "Opportunity"
    record_id: str = ""


class SalesforceUpdateRequest(BaseModel):
    object_type: str = "Opportunity"
    record_id: str = ""
    fields: dict = {}


@app.post("/salesforce/read")
async def salesforce_read(
    req: SalesforceReadRequest, authorization: str | None = Header(None)
):
    _validate_auth("salesforce", authorization)
    time.sleep(0.015)

    fake_records = {
        "Opportunity": {
            "Id": req.record_id or "006Dn000003gZJHIA2",
            "Name": "Acme Corp — Enterprise License",
            "Amount": 42000.00,
            "StageName": "Negotiation/Review",
            "CloseDate": "2026-04-15",
            "Probability": 75,
            "Owner": {"Name": "Sarah Chen", "Email": "s.chen@company.com"},
        },
        "Contact": {
            "Id": req.record_id or "003Dn000002QeATIA0",
            "FirstName": "James",
            "LastName": "Morrison",
            "Email": "j.morrison@acme.com",
            "Phone": "+44 20 7946 0958",
            "Account": {"Name": "Acme Corp"},
        },
    }

    record = fake_records.get(req.object_type, fake_records["Opportunity"])
    return {
        "record": record,
        "object_type": req.object_type,
        "simulated": True,
    }


@app.post("/salesforce/update")
async def salesforce_update(
    req: SalesforceUpdateRequest, authorization: str | None = Header(None)
):
    _validate_auth("salesforce", authorization)
    time.sleep(0.02)

    return {
        "id": req.record_id or "006Dn000003gZJHIA2",
        "success": True,
        "fields_updated": list(req.fields.keys()),
        "simulated": True,
    }


# ── Stripe endpoints ────────────────────────────────────────────────────────


class StripeChargeRequest(BaseModel):
    amount: float
    currency: str = "gbp"
    description: str = ""
    customer_id: str = ""


@app.post("/stripe/charge")
async def stripe_charge(
    req: StripeChargeRequest, authorization: str | None = Header(None)
):
    _validate_auth("stripe", authorization)
    time.sleep(0.025)

    return {
        "charge_id": f"ch_{uuid.uuid4().hex[:24]}",
        "amount": req.amount,
        "currency": req.currency,
        "status": "succeeded",
        "description": req.description,
        "customer_id": req.customer_id or "cus_mock_001",
        "created": int(time.time()),
        "simulated": True,
    }


# ── Slack endpoints ─────────────────────────────────────────────────────────


class SlackPostRequest(BaseModel):
    channel: str = "#general"
    text: str = ""


@app.post("/slack/post")
async def slack_post(req: SlackPostRequest, authorization: str | None = Header(None)):
    _validate_auth("slack", authorization)
    time.sleep(0.01)

    return {
        "ok": True,
        "ts": f"{int(time.time())}.{uuid.uuid4().hex[:6]}",
        "channel": req.channel,
        "text": req.text[:100],
        "simulated": True,
    }


# ── Health ───────────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "vargate-mock-tools",
        "tools": ["gmail", "salesforce", "stripe", "slack"],
    }


if __name__ == "__main__":
    print("[MOCK-TOOLS] Starting on port 9000", flush=True)
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="info")  # nosec B104
