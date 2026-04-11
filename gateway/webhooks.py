"""
Webhook delivery system (Sprint 7.6).

Sends HMAC-SHA256 signed webhook payloads to tenant-configured URLs
when governance events occur (action denied, pending approval, chain anchored).

Delivery is async with retry and exponential backoff.
"""

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone

import httpx

# Supported event types
WEBHOOK_EVENTS = ["action.denied", "action.pending", "action.allowed", "chain.anchored", "anomaly.detected", "session.interrupted"]

# Retry config
MAX_RETRIES = 3
BACKOFF_BASE = 2  # seconds


async def send_webhook(
    url: str,
    secret: str,
    event: str,
    payload: dict,
    *,
    max_retries: int = MAX_RETRIES,
):
    """Send a signed webhook payload with retry and exponential backoff.

    The payload is JSON-encoded and signed with HMAC-SHA256 using the
    tenant's webhook secret. The signature is sent in X-Vargate-Signature.
    """
    body = json.dumps(
        {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        },
        default=str,
    )

    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Vargate-Signature": f"sha256={signature}",
        "X-Vargate-Event": event,
        "User-Agent": "Vargate-Webhook/1.0",
    }

    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, content=body, headers=headers)
                if resp.status_code < 300:
                    print(
                        f"[WEBHOOK] Delivered {event} to {url} "
                        f"(attempt {attempt + 1}, status {resp.status_code})",
                        flush=True,
                    )
                    return True
                else:
                    print(
                        f"[WEBHOOK] Non-2xx response {resp.status_code} from {url} "
                        f"(attempt {attempt + 1})",
                        flush=True,
                    )
        except Exception as e:
            print(
                f"[WEBHOOK] Delivery failed to {url} (attempt {attempt + 1}): {e}",
                flush=True,
            )

        if attempt < max_retries:
            wait = BACKOFF_BASE ** (attempt + 1)
            await asyncio.sleep(wait)

    print(f"[WEBHOOK] Exhausted retries for {event} to {url}", flush=True)
    return False


async def dispatch_webhook(tenant: dict, event: str, payload: dict):
    """Dispatch a webhook if the tenant has a URL configured and subscribes to the event.

    This is fire-and-forget — errors are logged but don't affect the caller.
    """
    webhook_url = tenant.get("webhook_url")
    webhook_secret = tenant.get("webhook_secret")
    webhook_events = tenant.get("webhook_events")

    if not webhook_url or not webhook_secret:
        return

    # Parse events list
    if isinstance(webhook_events, str):
        try:
            subscribed = json.loads(webhook_events)
        except (json.JSONDecodeError, TypeError):
            subscribed = WEBHOOK_EVENTS  # default to all
    elif isinstance(webhook_events, list):
        subscribed = webhook_events
    else:
        subscribed = WEBHOOK_EVENTS

    if event not in subscribed:
        return

    # Fire and forget
    asyncio.create_task(send_webhook(webhook_url, webhook_secret, event, payload))


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify an incoming webhook signature (for /webhooks/test endpoint)."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
