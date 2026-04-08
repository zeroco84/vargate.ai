"""
Vargate Human-Approval Queue (Sprint 4)

Pending actions table, approve/reject API helpers, timeout enforcement.
Actions flagged with requires_human=true by OPA are held here until
a human reviewer approves or rejects them, or the timeout expires.
"""

import json
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional


# ── Configuration ──────────────────────────────────────────────────────────

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 3600  # 1 hour


# ── Database setup ─────────────────────────────────────────────────────────

def init_approval_db(conn: sqlite3.Connection):
    """Create the pending_actions table if it doesn't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id       TEXT UNIQUE NOT NULL,
            tenant_id       TEXT NOT NULL,
            agent_id        TEXT NOT NULL,
            tool            TEXT NOT NULL,
            method          TEXT NOT NULL,
            params          TEXT NOT NULL,
            opa_decision    TEXT NOT NULL,
            violations      TEXT DEFAULT '[]',
            severity        TEXT DEFAULT 'medium',
            status          TEXT DEFAULT 'pending',
            reviewer_email  TEXT,
            review_note     TEXT,
            created_at      TEXT NOT NULL,
            reviewed_at     TEXT,
            timeout_at      TEXT NOT NULL,
            execution_result TEXT
        )
    """)
    conn.commit()


# ── Queue operations ───────────────────────────────────────────────────────

def enqueue_action(
    conn: sqlite3.Connection,
    action_id: str,
    tenant_id: str,
    agent_id: str,
    tool: str,
    method: str,
    params: dict,
    opa_decision: dict,
    timeout_seconds: int = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
) -> dict:
    """Add an action to the approval queue. Returns the queued action record."""
    now = datetime.now(timezone.utc)
    timeout_at = datetime.fromtimestamp(
        now.timestamp() + timeout_seconds, tz=timezone.utc
    )

    conn.execute(
        """INSERT INTO pending_actions
           (action_id, tenant_id, agent_id, tool, method, params,
            opa_decision, violations, severity, status, created_at, timeout_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
        (
            action_id,
            tenant_id,
            agent_id,
            tool,
            method,
            json.dumps(params),
            json.dumps(opa_decision),
            json.dumps(opa_decision.get("violations", [])),
            opa_decision.get("severity", "medium"),
            now.isoformat(),
            timeout_at.isoformat(),
        ),
    )
    conn.commit()

    return {
        "action_id": action_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "tool": tool,
        "method": method,
        "params": params,
        "status": "pending",
        "created_at": now.isoformat(),
        "timeout_at": timeout_at.isoformat(),
    }


def approve_action(
    conn: sqlite3.Connection,
    action_id: str,
    tenant_id: str,
    reviewer_email: str = "",
    review_note: str = "",
) -> Optional[dict]:
    """Approve a pending action. Returns the action record or None if not found."""
    row = conn.execute(
        "SELECT * FROM pending_actions WHERE action_id = ? AND tenant_id = ?",
        (action_id, tenant_id),
    ).fetchone()

    if not row:
        return None

    if row["status"] != "pending":
        return {"error": f"Action already {row['status']}", "action_id": action_id}

    # Check timeout
    timeout_at = datetime.fromisoformat(row["timeout_at"])
    if datetime.now(timezone.utc) > timeout_at:
        conn.execute(
            "UPDATE pending_actions SET status = 'expired' WHERE action_id = ?",
            (action_id,),
        )
        conn.commit()
        return {"error": "Action has expired", "action_id": action_id}

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE pending_actions
           SET status = 'approved', reviewer_email = ?, review_note = ?, reviewed_at = ?
           WHERE action_id = ?""",
        (reviewer_email, review_note, now, action_id),
    )
    conn.commit()

    return {
        "action_id": action_id,
        "status": "approved",
        "reviewer_email": reviewer_email,
        "reviewed_at": now,
        "tool": row["tool"],
        "method": row["method"],
        "params": json.loads(row["params"]),
    }


def reject_action(
    conn: sqlite3.Connection,
    action_id: str,
    tenant_id: str,
    reviewer_email: str = "",
    review_note: str = "",
) -> Optional[dict]:
    """Reject a pending action."""
    row = conn.execute(
        "SELECT * FROM pending_actions WHERE action_id = ? AND tenant_id = ?",
        (action_id, tenant_id),
    ).fetchone()

    if not row:
        return None

    if row["status"] != "pending":
        return {"error": f"Action already {row['status']}", "action_id": action_id}

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE pending_actions
           SET status = 'rejected', reviewer_email = ?, review_note = ?, reviewed_at = ?
           WHERE action_id = ?""",
        (reviewer_email, review_note, now, action_id),
    )
    conn.commit()

    return {
        "action_id": action_id,
        "status": "rejected",
        "reviewer_email": reviewer_email,
        "reviewed_at": now,
    }


def get_pending_actions(
    conn: sqlite3.Connection,
    tenant_id: str,
    limit: int = 50,
) -> list[dict]:
    """Get all pending actions for a tenant, expiring any that have timed out."""
    now = datetime.now(timezone.utc).isoformat()

    # Expire timed-out actions
    conn.execute(
        "UPDATE pending_actions SET status = 'expired' WHERE tenant_id = ? AND status = 'pending' AND timeout_at < ?",
        (tenant_id, now),
    )
    conn.commit()

    rows = conn.execute(
        """SELECT action_id, agent_id, tool, method, params, opa_decision,
                  violations, severity, status, created_at, timeout_at
           FROM pending_actions
           WHERE tenant_id = ? AND status = 'pending'
           ORDER BY id DESC LIMIT ?""",
        (tenant_id, limit),
    ).fetchall()

    return [
        {
            "action_id": r["action_id"],
            "agent_id": r["agent_id"],
            "tool": r["tool"],
            "method": r["method"],
            "params": json.loads(r["params"]),
            "opa_decision": json.loads(r["opa_decision"]),
            "violations": json.loads(r["violations"]),
            "severity": r["severity"],
            "status": r["status"],
            "created_at": r["created_at"],
            "timeout_at": r["timeout_at"],
        }
        for r in rows
    ]


def get_approval_history(
    conn: sqlite3.Connection,
    tenant_id: str,
    limit: int = 50,
) -> list[dict]:
    """Get approval history (approved, rejected, expired) for a tenant."""
    rows = conn.execute(
        """SELECT action_id, agent_id, tool, method, severity, status,
                  reviewer_email, review_note, created_at, reviewed_at
           FROM pending_actions
           WHERE tenant_id = ? AND status != 'pending'
           ORDER BY id DESC LIMIT ?""",
        (tenant_id, limit),
    ).fetchall()

    return [
        {
            "action_id": r["action_id"],
            "agent_id": r["agent_id"],
            "tool": r["tool"],
            "method": r["method"],
            "severity": r["severity"],
            "status": r["status"],
            "reviewer_email": r["reviewer_email"],
            "review_note": r["review_note"],
            "created_at": r["created_at"],
            "reviewed_at": r["reviewed_at"],
        }
        for r in rows
    ]


def get_queue_stats(conn: sqlite3.Connection, tenant_id: str) -> dict:
    """Get approval queue statistics for a tenant."""
    row = conn.execute(
        """SELECT
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired
           FROM pending_actions WHERE tenant_id = ?""",
        (tenant_id,),
    ).fetchone()

    return {
        "pending": row["pending"] or 0,
        "approved": row["approved"] or 0,
        "rejected": row["rejected"] or 0,
        "expired": row["expired"] or 0,
    }
