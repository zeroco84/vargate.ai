"""
Vargate GTM Agent Safety Constraints (Sprint 4)

Enforces gateway-level constraints on the GTM outbound agent:
  - Recipient allowlist (blocks emails to internal/competitor domains)
  - Daily send cap (30 emails/day)
  - 30-day cooldown per recipient (no re-contact within 30 days)
  - AI disclosure requirement (body must contain disclosure text)

These run BEFORE OPA evaluation and are hard blocks — OPA policies
are for governance, these are for safety.
"""

import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────

DAILY_SEND_CAP = 30
COOLDOWN_DAYS = 30

# Domains that should NEVER receive outbound GTM emails
# KEEP IN SYNC with policies/vargate/gtm_policy.rego consumer_domains
BLOCKED_DOMAINS = {
    # Internal
    "vargate.ai",
    "vargate.com",
    # Common personal domains (don't cold-email consumers)
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    # Catch-all
    "example.com",
    "test.com",
    "localhost",
}

AI_DISCLOSURE_PATTERNS = [
    r"ai[- ]generated",
    r"ai[- ]assisted",
    r"automated\s+message",
    r"this\s+(email|message)\s+was\s+(generated|composed|written)\s+(by|using|with)\s+(an?\s+)?ai",
    r"artificial\s+intelligence",
]

# Brand-safety content filter. Applies to outbound tweets, emails, and
# anywhere else we choose to wire it in. Matched case-insensitively with
# word boundaries — "class" / "assume" / "pass" will NOT match.
# Edit freely. Each entry should be a specific spelling (including any
# inflections you want caught); we don't try to be clever about variants.
BLOCKED_PHRASES = {
    "fuck", "fucking", "fucked", "fucker", "fuckers", "fuckin",
    "shit", "shitty", "shitting", "bullshit",
    "bitch", "bitches", "bitching",
    "bastard", "bastards",
    "cunt", "cunts",
    "asshole", "assholes",
    "dickhead", "dickheads",
}

_BLOCKED_PHRASE_RE = re.compile(
    r"\b(" + "|".join(re.escape(p) for p in sorted(BLOCKED_PHRASES)) + r")\b",
    re.IGNORECASE,
)


# ── Database setup ─────────────────────────────────────────────────────────


def init_gtm_db(conn: sqlite3.Connection):
    """Create the GTM tracking tables."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gtm_send_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id   TEXT NOT NULL,
            recipient   TEXT NOT NULL,
            sent_at     TEXT NOT NULL,
            action_id   TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_gtm_send_tenant_date
        ON gtm_send_log(tenant_id, sent_at)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_gtm_send_recipient
        ON gtm_send_log(tenant_id, recipient)
    """)
    conn.commit()


# ── Constraint checks ─────────────────────────────────────────────────────


def check_gtm_constraints(
    conn: sqlite3.Connection,
    tenant_id: str,
    tool: str,
    method: str,
    params: dict,
    action_id: str,
) -> list[dict]:
    """
    Check all GTM safety constraints. Returns list of violations.
    Empty list = all constraints passed.
    Each violation: {"rule": str, "detail": str, "severity": "critical"|"high"|"medium"}
    """
    violations = []

    # ── Email-only checks (domain, daily cap, cooldown, AI disclosure) ──
    if _is_email_action(tool, method):
        recipient = _extract_recipient(params)
        body = _extract_body(params)
        subject = params.get("subject", "") if isinstance(params, dict) else ""

        # 1. Recipient domain check
        if recipient:
            domain = recipient.split("@")[-1].lower() if "@" in recipient else ""
            if domain in BLOCKED_DOMAINS:
                violations.append(
                    {
                        "rule": "gtm_blocked_domain",
                        "detail": f"Recipient domain '{domain}' is on the blocked list",
                        "severity": "critical",
                    }
                )

        # 2. Daily send cap
        daily_count = _get_daily_send_count(conn, tenant_id)
        if daily_count >= DAILY_SEND_CAP:
            violations.append(
                {
                    "rule": "gtm_daily_cap_exceeded",
                    "detail": f"Daily send limit ({DAILY_SEND_CAP}) reached ({daily_count} sent today)",
                    "severity": "high",
                }
            )

        # 3. Cooldown check
        if recipient:
            last_contact = _get_last_contact(conn, tenant_id, recipient)
            if last_contact:
                days_since = (datetime.now(timezone.utc) - last_contact).days
                if days_since < COOLDOWN_DAYS:
                    violations.append(
                        {
                            "rule": "gtm_cooldown_active",
                            "detail": f"Recipient contacted {days_since} days ago (cooldown: {COOLDOWN_DAYS} days)",
                            "severity": "high",
                        }
                    )

        # 4. AI disclosure check
        if body and not _has_ai_disclosure(body):
            violations.append(
                {
                    "rule": "gtm_missing_ai_disclosure",
                    "detail": "Email body does not contain required AI disclosure statement",
                    "severity": "medium",
                }
            )

        # 5. Profanity check on subject + body
        match = _first_blocked_phrase(subject) or _first_blocked_phrase(body)
        if match:
            violations.append(
                {
                    "rule": "gtm_blocked_phrase",
                    "detail": f"Email contains blocked phrase: '{match}'",
                    "severity": "critical",
                }
            )

    # ── Tweet check (profanity on the tweet text) ──
    if tool == "twitter" and method == "create_tweet":
        text = params.get("text", "") if isinstance(params, dict) else ""
        match = _first_blocked_phrase(text)
        if match:
            violations.append(
                {
                    "rule": "gtm_blocked_phrase",
                    "detail": f"Tweet contains blocked phrase: '{match}'",
                    "severity": "critical",
                }
            )

    return violations


def _first_blocked_phrase(text: str) -> Optional[str]:
    """Return the first blocked phrase found in text (lowercased), or None."""
    if not text:
        return None
    m = _BLOCKED_PHRASE_RE.search(text)
    return m.group(0).lower() if m else None


def record_send(
    conn: sqlite3.Connection,
    tenant_id: str,
    recipient: str,
    action_id: str,
):
    """Record a successful email send for rate limiting and cooldown tracking."""
    conn.execute(
        "INSERT INTO gtm_send_log (tenant_id, recipient, sent_at, action_id) VALUES (?, ?, ?, ?)",
        (
            tenant_id,
            recipient.lower(),
            datetime.now(timezone.utc).isoformat(),
            action_id,
        ),
    )
    conn.commit()


# ── Internal helpers ───────────────────────────────────────────────────────


def _is_email_action(tool: str, method: str) -> bool:
    """Check if this is an email-sending action."""
    email_patterns = [
        ("gmail", "send_email"),
        ("email", "send"),
        ("smtp", "send"),
        ("resend", "send"),
        ("sendgrid", "send"),
        ("ses", "send_email"),
    ]
    return (tool.lower(), method.lower()) in email_patterns


def _extract_recipient(params: dict) -> str:
    """Extract email recipient from action params."""
    for key in ("to", "recipient", "email", "to_email", "recipient_email"):
        if key in params and isinstance(params[key], str):
            return params[key].lower()
    return ""


def _extract_body(params: dict) -> str:
    """Extract email body from action params."""
    for key in ("body", "content", "text", "html", "message", "email_body"):
        if key in params and isinstance(params[key], str):
            return params[key]
    return ""


def _get_daily_send_count(conn: sqlite3.Connection, tenant_id: str) -> int:
    """Count emails sent today by this tenant."""
    today_start = (
        datetime.now(timezone.utc)
        .replace(hour=0, minute=0, second=0, microsecond=0)
        .isoformat()
    )
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM gtm_send_log WHERE tenant_id = ? AND sent_at >= ?",
        (tenant_id, today_start),
    ).fetchone()
    return row["cnt"] if row else 0


def _get_last_contact(
    conn: sqlite3.Connection, tenant_id: str, recipient: str
) -> Optional[datetime]:
    """Get the last time this recipient was contacted."""
    row = conn.execute(
        "SELECT sent_at FROM gtm_send_log WHERE tenant_id = ? AND recipient = ? ORDER BY id DESC LIMIT 1",
        (tenant_id, recipient.lower()),
    ).fetchone()
    if row:
        return datetime.fromisoformat(row["sent_at"])
    return None


def _has_ai_disclosure(body: str) -> bool:
    """Check if the email body contains an AI disclosure statement."""
    body_lower = body.lower()
    return any(re.search(pattern, body_lower) for pattern in AI_DISCLOSURE_PATTERNS)


def get_gtm_stats(conn: sqlite3.Connection, tenant_id: str) -> dict:
    """Get GTM constraint statistics."""
    daily_count = _get_daily_send_count(conn, tenant_id)
    total = conn.execute(
        "SELECT COUNT(*) as cnt FROM gtm_send_log WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    unique_recipients = conn.execute(
        "SELECT COUNT(DISTINCT recipient) as cnt FROM gtm_send_log WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()

    return {
        "daily_sends": daily_count,
        "daily_cap": DAILY_SEND_CAP,
        "daily_remaining": max(0, DAILY_SEND_CAP - daily_count),
        "total_sends": total["cnt"] if total else 0,
        "unique_recipients": unique_recipients["cnt"] if unique_recipients else 0,
        "cooldown_days": COOLDOWN_DAYS,
    }


# ── Managed Agent Session Constraints (BUG-008) ─────────────────────────

# Blocked tool patterns for managed agent sessions
BLOCKED_MANAGED_TOOLS = {
    "vargate_shell",  # Direct shell access should never be governed
    "vargate_raw_sql",  # Raw SQL bypass
}


def check_managed_session_constraints(
    conn: sqlite3.Connection,
    tenant_id: str,
    tool_name: str,
) -> Optional[str]:
    """
    Check gateway-level constraints for managed agent session creation.
    Returns error message if blocked, None if OK.

    AG-2.9: Safety constraints evaluated before OPA.
    """
    # Block explicitly dangerous tool configurations
    if tool_name.lower() in BLOCKED_MANAGED_TOOLS:
        return f"Tool '{tool_name}' is blocked for managed agent sessions"

    # Check daily send cap if email tools are in the config
    if "email" in tool_name.lower() or "send" in tool_name.lower():
        daily_count = _get_daily_send_count(conn, tenant_id)
        if daily_count >= DAILY_SEND_CAP:
            return f"Daily send cap reached ({daily_count}/{DAILY_SEND_CAP})"

    return None
