"""
Vargate Transparency Endpoint (Sprint 4)

Public JSON endpoint returning aggregated allow/deny/anomaly stats.
No PII. Hourly/daily/weekly aggregations. Includes policy version history.

GET /transparency
GET /transparency/{tenant_id}  (if public dashboard enabled)
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional


def get_transparency_data(
    conn: sqlite3.Connection,
    tenant_id: Optional[str] = None,
) -> dict:
    """
    Build aggregated transparency report.
    If tenant_id is None, aggregates across all tenants with public dashboards.
    """
    now = datetime.now(timezone.utc)
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    one_day_ago = (now - timedelta(days=1)).isoformat()
    one_week_ago = (now - timedelta(weeks=1)).isoformat()

    where = "WHERE tenant_id = ?" if tenant_id else "WHERE 1=1"
    args = (tenant_id,) if tenant_id else ()

    # ── Overall stats ──────────────────────────────────────────────────────
    overall = conn.execute(
        "SELECT "
        "COUNT(*) as total, "
        "SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed, "
        "SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied, "
        "SUM(CASE WHEN anomaly_score_at_eval > 0.5 THEN 1 ELSE 0 END) as anomalous "
        "FROM audit_log " + where,  # nosec B608
        args,
    ).fetchone()

    # ── Hourly stats ───────────────────────────────────────────────────────
    hourly = conn.execute(
        "SELECT "
        "COUNT(*) as total, "
        "SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed, "
        "SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied "
        "FROM audit_log " + where + " AND created_at >= ?",  # nosec B608
        (*args, one_hour_ago),
    ).fetchone()

    # ── Daily stats ────────────────────────────────────────────────────────
    daily = conn.execute(
        "SELECT "
        "COUNT(*) as total, "
        "SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed, "
        "SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied "
        "FROM audit_log " + where + " AND created_at >= ?",  # nosec B608
        (*args, one_day_ago),
    ).fetchone()

    # ── Weekly stats ───────────────────────────────────────────────────────
    weekly = conn.execute(
        "SELECT "
        "COUNT(*) as total, "
        "SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed, "
        "SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied "
        "FROM audit_log " + where + " AND created_at >= ?",  # nosec B608
        (*args, one_week_ago),
    ).fetchone()

    # ── Violation breakdown ────────────────────────────────────────────────
    violation_rows = conn.execute(
        "SELECT violations FROM audit_log "
        + where
        + " AND decision = 'deny'",  # nosec B608
        args,
    ).fetchall()
    violation_counts = {}
    for r in violation_rows:
        try:
            for v in json.loads(r["violations"]):
                violation_counts[v] = violation_counts.get(v, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    # ── Severity distribution ──────────────────────────────────────────────
    severity_dist = conn.execute(
        "SELECT severity, COUNT(*) as cnt "
        "FROM audit_log " + where + " AND decision = 'deny' "  # nosec B608
        "GROUP BY severity",
        args,
    ).fetchall()
    severity_map = {r["severity"]: r["cnt"] for r in severity_dist}

    # ── Tool usage breakdown ───────────────────────────────────────────────
    tool_rows = conn.execute(
        "SELECT tool, COUNT(*) as cnt, "
        "SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) as allowed, "
        "SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied "
        "FROM audit_log " + where + " "  # nosec B608
        "GROUP BY tool ORDER BY cnt DESC LIMIT 20",
        args,
    ).fetchall()
    tool_stats = [
        {
            "tool": r["tool"],
            "total": r["cnt"],
            "allowed": r["allowed"] or 0,
            "denied": r["denied"] or 0,
        }
        for r in tool_rows
    ]

    # ── Policy version history ─────────────────────────────────────────────
    policy_rows = conn.execute(
        "SELECT DISTINCT bundle_revision, MIN(created_at) as first_seen "
        "FROM audit_log " + where + " AND bundle_revision IS NOT NULL "  # nosec B608
        "GROUP BY bundle_revision ORDER BY first_seen DESC LIMIT 10",
        args,
    ).fetchall()
    policy_versions = [
        {"revision": r["bundle_revision"], "first_seen": r["first_seen"]}
        for r in policy_rows
    ]

    # ── Approval queue stats (if available) ────────────────────────────────
    approval_stats = None
    try:
        if tenant_id:
            approval_row = conn.execute(
                """SELECT
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected,
                    SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired
                FROM pending_actions WHERE tenant_id = ?""",
                (tenant_id,),
            ).fetchone()
            if approval_row and approval_row["pending"] is not None:
                approval_stats = {
                    "pending": approval_row["pending"] or 0,
                    "approved": approval_row["approved"] or 0,
                    "rejected": approval_row["rejected"] or 0,
                    "expired": approval_row["expired"] or 0,
                }
    except sqlite3.OperationalError:
        pass  # Table doesn't exist yet

    # ── Chain integrity ────────────────────────────────────────────────────
    chain_info = None
    try:
        last_record = conn.execute(
            "SELECT record_hash, created_at FROM audit_log "
            + where
            + " ORDER BY id DESC LIMIT 1",  # nosec B608
            args,
        ).fetchone()
        total_records = conn.execute(
            "SELECT COUNT(*) as cnt FROM audit_log " + where,  # nosec B608
            args,
        ).fetchone()
        chain_info = {
            "total_records": total_records["cnt"] if total_records else 0,
            "latest_hash": (
                last_record["record_hash"][:16] + "..." if last_record else None
            ),
            "latest_at": last_record["created_at"] if last_record else None,
        }
    except Exception:
        pass

    return {
        "generated_at": now.isoformat(),
        "tenant_id": tenant_id,
        "overall": {
            "total_actions": overall["total"] or 0,
            "allowed": overall["allowed"] or 0,
            "denied": overall["denied"] or 0,
            "anomalous": overall["anomalous"] or 0,
            "compliance_rate": round(
                (overall["allowed"] or 0) / max(overall["total"] or 1, 1) * 100, 1
            ),
        },
        "hourly": {
            "total": hourly["total"] or 0,
            "allowed": hourly["allowed"] or 0,
            "denied": hourly["denied"] or 0,
        },
        "daily": {
            "total": daily["total"] or 0,
            "allowed": daily["allowed"] or 0,
            "denied": daily["denied"] or 0,
        },
        "weekly": {
            "total": weekly["total"] or 0,
            "allowed": weekly["allowed"] or 0,
            "denied": weekly["denied"] or 0,
        },
        "violations": violation_counts,
        "severity_distribution": severity_map,
        "tool_usage": tool_stats,
        "policy_versions": policy_versions,
        "approval_queue": approval_stats,
        "chain": chain_info,
    }
