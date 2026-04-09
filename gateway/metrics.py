"""
Vargate Prometheus Metrics

Exposes application-level metrics for Prometheus scraping.
All metric objects are created here and imported where needed.
"""

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
)

# ── Latency & throughput ────────────────────────────────────────────────────

REQUEST_DURATION = Histogram(
    "gateway_request_duration_seconds",
    "HTTP request duration in seconds",
    labelnames=["method", "path", "status"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

REQUESTS_TOTAL = Counter(
    "gateway_requests_total",
    "Total HTTP requests",
    labelnames=["method", "path", "status"],
)

ACTIVE_REQUESTS = Gauge(
    "gateway_active_requests",
    "Number of in-flight HTTP requests",
)

# ── OPA evaluation ──────────────────────────────────────────────────────────

OPA_EVAL_DURATION = Histogram(
    "gateway_opa_eval_duration_seconds",
    "OPA policy evaluation duration in seconds",
)

# ── Tool call decisions ─────────────────────────────────────────────────────

ACTIONS_TOTAL = Counter(
    "gateway_actions_total",
    "Total tool call decisions",
    labelnames=["decision", "tenant_id"],
)

# ── Audit chain ─────────────────────────────────────────────────────────────

AUDIT_CHAIN_LENGTH = Gauge(
    "gateway_audit_chain_length",
    "Number of records in the audit chain",
    labelnames=["tenant_id"],
)

# ── Blockchain anchoring ───────────────────────────────────────────────────

ANCHOR_LAST_SUCCESS = Gauge(
    "gateway_anchor_last_success_timestamp",
    "Unix epoch seconds of last successful blockchain anchor",
)

# ── Errors ──────────────────────────────────────────────────────────────────

ERRORS_TOTAL = Counter(
    "gateway_errors_total",
    "Total errors by type",
    labelnames=["type"],
)
