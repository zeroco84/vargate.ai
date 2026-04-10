"""
Vargate MCP Proxy Gateway
Intercepts AI agent tool calls, evaluates them against OPA policy,
and logs every decision to a hash-chained SQLite audit log.
Implements two-pass evaluation with Redis behavioral history.
Blockchain anchoring via Sepolia Ethereum testnet with Merkle tree roots.
Stage 8: Credential Enclave — agent-blind brokered execution.
Stage 7B: Merkle tree audit anchoring (AG-2.2 / AG-2.3).
Sprint 2: Multi-tenancy — per-tenant hash chains, API key auth, rate limiting.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import approval as approval_module
import auth as auth_module
import execution_engine
import failure_modes
import gtm_constraints
import httpx
import redis.asyncio as aioredis
import webhooks as webhooks_module
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Configuration ────────────────────────────────────────────────────────────

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_DECISION_PATH = "/v1/data/vargate/policy/decision"
DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
DEFAULT_BUNDLE_REVISION = "v1.0.0-prototype"
BUNDLE_SERVER_URL = os.getenv("BUNDLE_SERVER_URL", "http://bundle-server:8080")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
HSM_URL = os.getenv("HSM_URL", "http://hsm:8300")
MOCK_TOOLS_URL = os.getenv("MOCK_TOOLS_URL", "http://mock-tools:9000")
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://blockchain:8545")
CONTRACT_ADDRESS_FILE = os.getenv(
    "CONTRACT_ADDRESS_FILE", "/shared/contract_address.txt"
)
CONTRACT_ABI_FILE = os.getenv("CONTRACT_ABI_FILE", "/shared/AuditAnchor.abi.json")
ANCHOR_INTERVAL_SECONDS = int(os.getenv("ANCHOR_INTERVAL_SECONDS", "3600"))
SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL", "")
MERKLE_CONTRACT_FILE = os.getenv(
    "MERKLE_CONTRACT_FILE", "/shared/MerkleAuditAnchor.json"
)

# PII detection patterns
_PII_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PII_SORT_CODE_RE = re.compile(r"\d{2}-\d{2}-\d{2}")
_PII_NI_NUMBER_RE = re.compile(r"[A-Z]{2}\d{6}[A-Z]")
_PII_NAME_FIELDS = {"name", "customer_name", "full_name", "first_name", "last_name"}

# ── Multi-tenancy defaults ─────────────────────────────────────────────────
DEFAULT_TENANT_ID = "vargate-internal"
DEFAULT_TENANT_NAME = "Vargate Internal"
GTM_TENANT_ID = "vargate-gtm-agent"
GTM_TENANT_NAME = "Vargate GTM Agent"

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Vargate Gateway",
    version="1.0.0",
    description=(
        "AI agent supervision proxy. Intercepts autonomous agent tool calls, "
        "evaluates them against OPA/Rego governance policy, logs every decision "
        "to a hash-chained audit trail, and anchors Merkle tree roots to blockchain. "
        "Implements AGCS v0.9 (Agent Governance Certification Standard)."
    ),
    openapi_tags=[
        {
            "name": "Tool Calls",
            "description": "Core proxy endpoint — submit agent tool calls for governance evaluation",
        },
        {
            "name": "Auth",
            "description": "Signup, email verification, GitHub OAuth, sessions, API key rotation",
        },
        {
            "name": "Tenants",
            "description": "Tenant CRUD, dashboard settings, public dashboard",
        },
        {
            "name": "Approval Queue",
            "description": "Human-in-the-loop approval workflow for flagged actions",
        },
        {
            "name": "Audit",
            "description": "Hash-chained audit log, verification, GDPR erasure, replay",
        },
        {
            "name": "Blockchain",
            "description": "Merkle tree anchoring, proofs, verification, multi-chain status",
        },
        {
            "name": "Credentials",
            "description": "HSM-backed credential vault for agent-blind brokered execution",
        },
        {"name": "Policy", "description": "OPA policy rules and bundle status"},
        {"name": "System", "description": "Health check, backup, metrics"},
    ],
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://vargate.ai"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Prometheus metrics ─────────────────────────────────────────────────────

import metrics as prom  # noqa: E402

# ── Request body size limit middleware ─────────────────────────────────────


@app.middleware("http")
async def limit_request_size(request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1_048_576:  # 1MB
        return JSONResponse(
            status_code=413, content={"detail": "Request body too large"}
        )
    return await call_next(request)


# ── Request logging + metrics middleware ───────────────────────────────────


@app.middleware("http")
async def request_logging_middleware(request, call_next):
    """Log method/path/status/duration/client_ip and record Prometheus metrics."""
    if request.url.path in ("/health", "/metrics"):
        return await call_next(request)
    prom.ACTIVE_REQUESTS.inc()
    start = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        prom.ACTIVE_REQUESTS.dec()
        raise
    duration = time.monotonic() - start
    prom.ACTIVE_REQUESTS.dec()
    path_label = request.url.path
    status_label = str(response.status_code)
    prom.REQUEST_DURATION.labels(request.method, path_label, status_label).observe(
        duration
    )
    prom.REQUESTS_TOTAL.labels(request.method, path_label, status_label).inc()
    duration_ms = int(duration * 1000)
    client_ip = request.client.host if request.client else "unknown"
    print(
        f"[REQUEST] {request.method} {request.url.path} "
        f"status={response.status_code} duration={duration_ms}ms client={client_ip}",
        flush=True,
    )
    return response


# DEMO ONLY — stores original hashes during tamper simulation
_tamper_store: dict[int, str] = {}

# ── Redis connection pool ────────────────────────────────────────────────────

redis_pool: Optional[aioredis.Redis] = None

# ── Blockchain client (legacy Hardhat + new Sepolia Merkle) ──────────────────

blockchain_client = None
_anchor_task = None

# New Sepolia Merkle anchor client (backward compat)
merkle_blockchain_client = None
_merkle_anchor_task = None

# Sprint 5: Multi-chain manager
chain_manager = None
_tree_anchor_task = None

# Merkle tree cache (Fix 2 — avoids full rebuild on every proof/verify request)
from tree_cache import tree_cache  # noqa: E402

# Fix 5: Background task for local Merkle root recording
_merkle_root_task = None


async def run_merkle_root_loop(get_db_fn):
    """
    Sprint 5 (AG-2.2): Background task that builds hourly tenant-scoped
    Merkle trees and records cumulative roots at regular intervals.
    Runs every MERKLE_ROOT_INTERVAL_SECONDS (default 3600s, must be ≤ 3600s).
    """
    from merkle import MerkleTree as _MT
    from merkle import build_hourly_trees

    await asyncio.sleep(20)  # Initial delay

    while True:
        try:
            conn = get_db_fn()
            try:
                # Build hourly trees for each tenant
                tenants = conn.execute("SELECT tenant_id FROM tenants").fetchall()
                for t in tenants:
                    tid = t["tenant_id"]
                    new_trees = build_hourly_trees(conn, tid)
                    for nt in new_trees:
                        print(
                            f"[MERKLE-TREE] tenant={tid} tree={nt['tree_index']} "
                            f"root={nt['merkle_root'][:16]}... records={nt['record_count']} "
                            f"period={nt['period_start']}",
                            flush=True,
                        )

                # Also record cumulative root for backward compatibility
                count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                if count > 0:
                    tree = _MT.from_db(conn)
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO merkle_root_log (merkle_root, record_count, computed_at) "
                        "VALUES (?, ?, ?)",
                        (tree.root, tree.leaf_count, now),
                    )
                    conn.commit()
                    print(
                        f"[MERKLE-ROOT] Recorded cumulative root={tree.root[:16]}... records={tree.leaf_count}",
                        flush=True,
                    )
            finally:
                conn.close()
        except Exception as e:
            print(f"[MERKLE-ROOT] Background loop error: {e}", flush=True)

        await asyncio.sleep(MERKLE_ROOT_INTERVAL_SECONDS)


# ── Request / Response models ────────────────────────────────────────────────


class ContextOverride(BaseModel):
    is_business_hours: Optional[bool] = None


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "agent_id": "my-agent-v1",
                    "agent_type": "autonomous",
                    "agent_version": "1.0.0",
                    "tool": "http",
                    "method": "GET",
                    "params": {
                        "url": "https://api.example.com/data",
                        "headers": {"Accept": "application/json"},
                    },
                }
            ]
        }
    )
    agent_id: str = Field(
        ..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.]+$"
    )
    agent_type: str = Field(default="unknown", max_length=64)
    agent_version: str = Field(
        default="0.0.0", max_length=32, pattern=r"^\d+\.\d+\.\d+.*$"
    )
    tool: str = Field(
        ..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.:/]+$"
    )
    method: str = Field(
        ..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.]+$"
    )
    params: dict[str, Any] = Field(default={})
    context_override: Optional[ContextOverride] = None

    @field_validator("params")
    @classmethod
    def validate_params_size(cls, v):
        """Reject oversized params to prevent abuse."""
        serialized = json.dumps(v)
        if len(serialized) > 65536:  # 64KB max
            raise ValueError("params payload exceeds 64KB limit")
        return v


class AllowedResponse(BaseModel):
    """Returned when a tool call is allowed by policy."""

    status: str = "allowed"
    action_id: str
    execution_mode: Optional[str] = None
    execution_result: Optional[dict] = None
    latency: Optional[dict] = None


class PendingApprovalResponse(BaseModel):
    """Returned when a tool call requires human approval."""

    status: str = "pending_approval"
    action_id: str
    message: str


class HealthResponse(BaseModel):
    """Gateway health status including all dependency checks."""

    status: str
    service: str
    redis: bool
    blockchain: bool
    connected_chains: list[str]
    merkle_trees: bool
    merkle_tree_count: int
    sepolia_merkle: bool


class BlockedResponse(BaseModel):
    """Returned when a tool call is denied by policy."""

    status: str = "blocked"
    action_id: str
    violations: list[str]
    severity: str
    alert_tier: str


# ── SQLite setup ─────────────────────────────────────────────────────────────


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_db_threadsafe() -> sqlite3.Connection:
    """Get a SQLite connection safe for use in background worker threads."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    # ── Tenants table (Sprint 2) ────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            tenant_id       TEXT PRIMARY KEY,
            api_key         TEXT NOT NULL UNIQUE,
            name            TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            rate_limit_rps  INTEGER NOT NULL DEFAULT 10,
            rate_limit_burst INTEGER NOT NULL DEFAULT 20
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id             TEXT NOT NULL UNIQUE,
            tenant_id             TEXT NOT NULL DEFAULT 'vargate-internal',
            agent_id              TEXT NOT NULL,
            tool                  TEXT NOT NULL,
            method                TEXT NOT NULL,
            params                TEXT NOT NULL,
            requested_at          TEXT NOT NULL,
            decision              TEXT NOT NULL,
            violations            TEXT NOT NULL,
            severity              TEXT NOT NULL,
            alert_tier            TEXT NOT NULL,
            bundle_revision       TEXT NOT NULL,
            prev_hash             TEXT,
            record_hash           TEXT NOT NULL,
            created_at            TEXT NOT NULL,
            evaluation_pass       INTEGER DEFAULT 1,
            anomaly_score_at_eval REAL DEFAULT 0.0,
            opa_input             TEXT,
            contains_pii          INTEGER DEFAULT 0,
            pii_subject_id        TEXT,
            pii_fields            TEXT,
            erasure_status        TEXT DEFAULT 'active',
            execution_mode        TEXT DEFAULT 'agent_direct',
            execution_result      TEXT,
            execution_latency_ms  INTEGER,
            credential_accessed   TEXT,
            source                TEXT DEFAULT 'direct',
            managed_session_id    TEXT,
            delegation_chain      TEXT
        )
    """)
    # Add columns if upgrading from earlier schemas
    for col_sql in [
        "ALTER TABLE audit_log ADD COLUMN evaluation_pass INTEGER DEFAULT 1",
        "ALTER TABLE audit_log ADD COLUMN anomaly_score_at_eval REAL DEFAULT 0.0",
        "ALTER TABLE audit_log ADD COLUMN opa_input TEXT",
        "ALTER TABLE audit_log ADD COLUMN contains_pii INTEGER DEFAULT 0",
        "ALTER TABLE audit_log ADD COLUMN pii_subject_id TEXT",
        "ALTER TABLE audit_log ADD COLUMN pii_fields TEXT",
        "ALTER TABLE audit_log ADD COLUMN erasure_status TEXT DEFAULT 'active'",
        "ALTER TABLE audit_log ADD COLUMN execution_mode TEXT DEFAULT 'agent_direct'",
        "ALTER TABLE audit_log ADD COLUMN execution_result TEXT",
        "ALTER TABLE audit_log ADD COLUMN execution_latency_ms INTEGER",
        "ALTER TABLE audit_log ADD COLUMN credential_accessed TEXT",
        "ALTER TABLE audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'vargate-internal'",
        "ALTER TABLE audit_log ADD COLUMN source TEXT DEFAULT 'direct'",
        "ALTER TABLE audit_log ADD COLUMN managed_session_id TEXT",
        "ALTER TABLE audit_log ADD COLUMN delegation_chain TEXT",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Anchor log table (legacy linear chain)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anchor_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_index    INTEGER NOT NULL,
            chain_tip_hash  TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            tx_hash         TEXT NOT NULL,
            block_number    INTEGER NOT NULL,
            anchored_at     TEXT NOT NULL
        )
    """)
    # Merkle anchor log table (Stage 7B — Sepolia)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_anchor_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_index    INTEGER NOT NULL,
            merkle_root     TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            from_record     INTEGER NOT NULL,
            to_record       INTEGER NOT NULL,
            tx_hash         TEXT NOT NULL,
            block_number    INTEGER NOT NULL,
            anchored_at     TEXT NOT NULL
        )
    """)
    # Migrate: add Merkle columns to anchor_log if upgrading
    for col_sql in [
        "ALTER TABLE anchor_log ADD COLUMN merkle_root TEXT",
        "ALTER TABLE anchor_log ADD COLUMN from_record INTEGER",
        "ALTER TABLE anchor_log ADD COLUMN to_record INTEGER",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Fix 4A (AG-2.2): Add Merkle root chain columns to merkle_anchor_log
    for col_sql in [
        "ALTER TABLE merkle_anchor_log ADD COLUMN prev_merkle_root TEXT",
        "ALTER TABLE merkle_anchor_log ADD COLUMN root_chain_hash TEXT",
        "ALTER TABLE merkle_anchor_log ADD COLUMN anchor_chain TEXT DEFAULT 'sepolia'",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Sprint 5: Add anchor_chain preference to tenants
    for col_sql in [
        "ALTER TABLE tenants ADD COLUMN anchor_chain TEXT DEFAULT 'polygon'",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass
    # Sprint 9.1: Managed agent sessions table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS managed_sessions (
            id                    TEXT PRIMARY KEY,
            anthropic_session_id  TEXT NOT NULL,
            tenant_id             TEXT NOT NULL,
            agent_id              TEXT NOT NULL,
            anthropic_agent_id    TEXT,
            environment_id        TEXT,
            status                TEXT DEFAULT 'active',
            governance_profile    TEXT,
            system_prompt_hash    TEXT,
            created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ended_at              TIMESTAMP,
            total_governed_calls  INTEGER DEFAULT 0,
            total_observed_calls  INTEGER DEFAULT 0,
            total_denied          INTEGER DEFAULT 0,
            total_pending         INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
        )
    """)
    # Sprint 9.1: Managed agent configs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS managed_agent_configs (
            id                    TEXT PRIMARY KEY,
            tenant_id             TEXT NOT NULL,
            name                  TEXT NOT NULL,
            anthropic_model       TEXT DEFAULT 'claude-sonnet-4-6',
            system_prompt         TEXT,
            governance_profile    TEXT,
            allowed_tools         TEXT,
            max_session_hours     REAL,
            max_daily_sessions    INTEGER,
            require_human_approval TEXT,
            parent_agent_id       TEXT,
            max_delegation_depth  INTEGER DEFAULT 1,
            created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id),
            FOREIGN KEY (parent_agent_id) REFERENCES managed_agent_configs(id)
        )
    """)
    # Fix 5 (AG-2.2): Local Merkle root recording table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_root_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            merkle_root     TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            computed_at     TEXT NOT NULL,
            anchored        INTEGER NOT NULL DEFAULT 0,
            anchor_id       INTEGER REFERENCES merkle_anchor_log(id)
        )
    """)
    # Sprint 5 (AG-2.2): Hourly tenant-scoped Merkle trees
    from merkle import init_merkle_trees_table

    init_merkle_trees_table(conn)
    # Run schema migrations (Audit Item 15)
    from migrations import run_migrations

    run_migrations(conn)
    # ── Seed default tenant (Sprint 2) ──────────────────────────────
    existing = conn.execute(
        "SELECT 1 FROM tenants WHERE tenant_id = ?", (DEFAULT_TENANT_ID,)
    ).fetchone()
    if not existing:
        default_api_key = f"vg-internal-{secrets.token_hex(24)}"
        conn.execute(
            """INSERT INTO tenants (tenant_id, api_key, name, created_at, rate_limit_rps, rate_limit_burst)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                DEFAULT_TENANT_ID,
                default_api_key,
                DEFAULT_TENANT_NAME,
                datetime.now(timezone.utc).isoformat(),
                100,  # generous rate limit for internal
                200,
            ),
        )
        print(
            f"[VARGATE] Default tenant created: {DEFAULT_TENANT_ID} (key={default_api_key[:20]}...)",
            flush=True,
        )
    conn.commit()
    conn.close()


def _seed_gtm_tenant(conn: sqlite3.Connection):
    """Seed the GTM agent tenant with custom rate limits and public dashboard enabled.
    Requires auth tables (public_dashboard, slug columns) to be initialized first."""
    existing = conn.execute(
        "SELECT 1 FROM tenants WHERE tenant_id = ?", (GTM_TENANT_ID,)
    ).fetchone()
    if not existing:
        # Verify auth columns exist before inserting (guards against init reordering)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(tenants)").fetchall()}
        if "public_dashboard" not in cols or "slug" not in cols:
            raise RuntimeError(
                "_seed_gtm_tenant called before auth_module.init_auth_db() — "
                "public_dashboard/slug columns missing from tenants table"
            )
        gtm_api_key = f"vg-gtm-{secrets.token_hex(24)}"
        conn.execute(
            """INSERT INTO tenants (tenant_id, api_key, name, created_at, rate_limit_rps, rate_limit_burst, public_dashboard, slug)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                GTM_TENANT_ID,
                gtm_api_key,
                GTM_TENANT_NAME,
                datetime.now(timezone.utc).isoformat(),
                5,  # conservative rate limit for GTM agent
                10,
                1,  # public dashboard enabled
                "vargate-gtm-agent",
            ),
        )
        conn.commit()
        print(
            f"[VARGATE] GTM tenant created: {GTM_TENANT_ID} (key={gtm_api_key[:20]}...)",
            flush=True,
        )
        print(
            "[VARGATE] GTM public dashboard: /dashboard/vargate-gtm-agent", flush=True
        )


MERKLE_ROOT_INTERVAL_SECONDS = int(os.getenv("MERKLE_ROOT_INTERVAL_SECONDS", "3600"))

# ── Hash-chain functions ────────────────────────────────────────────────────
# Note: hash computation uses the original Session 1 fields only for
# backward compatibility. New columns are NOT included in the hash.


def compute_record_hash(
    action_id: str,
    agent_id: str,
    tool: str,
    method: str,
    params: str,
    requested_at: str,
    decision: str,
    violations: str,
    severity: str,
    bundle_revision: str,
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash of record fields in canonical order."""
    payload = json.dumps(
        {
            "action_id": action_id,
            "agent_id": agent_id,
            "tool": tool,
            "method": method,
            "params": params,
            "requested_at": requested_at,
            "decision": decision,
            "violations": violations,
            "severity": severity,
            "bundle_revision": bundle_revision,
            "prev_hash": prev_hash,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_prev_hash(conn: sqlite3.Connection, tenant_id: str = DEFAULT_TENANT_ID) -> str:
    """Get the hash of the most recent audit record for a tenant, or GENESIS.
    Each tenant has an independent hash chain."""
    row = conn.execute(
        "SELECT record_hash FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    return row["record_hash"] if row else "GENESIS"


def write_audit_record(
    conn: sqlite3.Connection,
    action_id: str,
    agent_id: str,
    tool: str,
    method: str,
    params: dict,
    requested_at: str,
    decision: str,
    violations: list[str],
    severity: str,
    alert_tier: str,
    bundle_revision: str = DEFAULT_BUNDLE_REVISION,
    evaluation_pass: int = 1,
    anomaly_score_at_eval: float = 0.0,
    opa_input: Optional[dict] = None,
    contains_pii: int = 0,
    tenant_id: str = DEFAULT_TENANT_ID,
    pii_subject_id: Optional[str] = None,
    pii_fields: Optional[list[str]] = None,
    execution_mode: str = "agent_direct",
    execution_result: Optional[dict] = None,
    execution_latency_ms: Optional[int] = None,
    credential_accessed: Optional[str] = None,
    source: str = "direct",
    managed_session_id: Optional[str] = None,
    delegation_chain: Optional[list[str]] = None,
):
    """Write a hash-chained audit record to SQLite. Chain is scoped per tenant."""
    params_str = json.dumps(params, separators=(",", ":"))
    violations_str = json.dumps(violations, separators=(",", ":"))
    opa_input_str = json.dumps(opa_input, separators=(",", ":")) if opa_input else None
    pii_fields_str = json.dumps(pii_fields) if pii_fields else None
    execution_result_str = (
        json.dumps(execution_result, separators=(",", ":"))
        if execution_result
        else None
    )
    delegation_chain_str = (
        json.dumps(delegation_chain, separators=(",", ":"))
        if delegation_chain
        else None
    )
    prev_hash = get_prev_hash(conn, tenant_id=tenant_id)

    record_hash = compute_record_hash(
        action_id=action_id,
        agent_id=agent_id,
        tool=tool,
        method=method,
        params=params_str,
        requested_at=requested_at,
        decision=decision,
        violations=violations_str,
        severity=severity,
        bundle_revision=bundle_revision,
        prev_hash=prev_hash,
    )

    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        INSERT INTO audit_log
            (action_id, tenant_id, agent_id, tool, method, params, requested_at,
             decision, violations, severity, alert_tier, bundle_revision,
             prev_hash, record_hash, created_at,
             evaluation_pass, anomaly_score_at_eval, opa_input,
             contains_pii, pii_subject_id, pii_fields, erasure_status,
             execution_mode, execution_result, execution_latency_ms, credential_accessed,
             source, managed_session_id, delegation_chain)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id,
            tenant_id,
            agent_id,
            tool,
            method,
            params_str,
            requested_at,
            decision,
            violations_str,
            severity,
            alert_tier,
            bundle_revision,
            prev_hash,
            record_hash,
            now,
            evaluation_pass,
            anomaly_score_at_eval,
            opa_input_str,
            contains_pii,
            pii_subject_id,
            pii_fields_str,
            "active",
            execution_mode,
            execution_result_str,
            execution_latency_ms,
            credential_accessed,
            source,
            managed_session_id,
            delegation_chain_str,
        ),
    )
    conn.commit()

    # Update Prometheus gauge for audit chain length
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
        prom.AUDIT_CHAIN_LENGTH.labels(tenant_id=tenant_id).set(count)
    except Exception:
        pass

    # Fix 2: Invalidate the Merkle tree cache so the next proof/verify
    # request rebuilds the tree including this new record.
    tree_cache.invalidate()


def write_anchor_audit_record(
    conn: sqlite3.Connection, anchor_result: dict, contract_address: str = None
):
    """
    Fix 3 (AG-3.2): Write a blockchain anchor event into the hash-chained audit log.

    This creates a bi-directional link between the audit chain and the public ledger:
    - This audit record contains the tx_hash pointing to Sepolia.
    - The NEXT Merkle root computed on Sepolia will include this record's hash.

    IMPORTANT: This record is included in the NEXT anchor's Merkle tree, NOT in the
    current one. This is correct and expected — the current anchor's root was computed
    BEFORE this record was written. The next anchor will cover records including this one.
    """
    import uuid

    action_id = str(uuid.uuid4())
    requested_at = datetime.now(timezone.utc).isoformat()

    explorer_url = f"https://sepolia.etherscan.io/tx/{anchor_result.get('tx_hash', '')}"

    params = {
        "merkle_root": anchor_result.get("merkle_root", ""),
        "record_count": anchor_result.get("record_count", 0),
        "from_record": anchor_result.get("from_record", 0),
        "to_record": anchor_result.get("to_record", 0),
        "tx_hash": anchor_result.get("tx_hash", ""),
        "block_number": anchor_result.get("block_number", 0),
        "network": "sepolia",
        "chain_id": 11155111,
        "contract_address": contract_address or "",
        "explorer_url": explorer_url,
    }

    write_audit_record(
        conn=conn,
        action_id=action_id,
        agent_id="vargate-system",
        tool="blockchain_anchor",
        method="submitAnchor",
        params=params,
        requested_at=requested_at,
        decision="allow",
        violations=[],
        severity="none",
        alert_tier="none",
        bundle_revision=DEFAULT_BUNDLE_REVISION,
    )

    print(
        f"[ANCHOR] AG-3.2 audit record written: action_id={action_id[:16]}... "
        f"tx={anchor_result.get('tx_hash', '?')[:18]}...",
        flush=True,
    )

    return action_id


# ── Chain verification ───────────────────────────────────────────────────────


def verify_chain_integrity(
    conn: sqlite3.Connection, tenant_id: Optional[str] = None
) -> dict:
    """Verify the hash chain. If tenant_id is given, verify only that tenant's chain.
    If tenant_id is None, verify all tenants independently."""
    if tenant_id is not None:
        return _verify_tenant_chain(conn, tenant_id)

    # Verify all tenants
    tenant_rows = conn.execute("SELECT DISTINCT tenant_id FROM audit_log").fetchall()
    if not tenant_rows:
        return {"valid": True, "record_count": 0}

    total_records = 0
    for trow in tenant_rows:
        tid = trow["tenant_id"]
        result = _verify_tenant_chain(conn, tid)
        if not result["valid"]:
            result["tenant_id"] = tid
            return result
        total_records += result["record_count"]

    return {"valid": True, "record_count": total_records}


def _verify_tenant_chain(conn: sqlite3.Connection, tenant_id: str) -> dict:
    """Verify the hash chain for a single tenant."""
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY id ASC",
        (tenant_id,),
    ).fetchall()

    if not rows:
        return {"valid": True, "record_count": 0, "tenant_id": tenant_id}

    expected_prev = "GENESIS"

    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "failed_at_action_id": row["action_id"],
                "reason": "prev_hash mismatch",
                "tenant_id": tenant_id,
            }

        expected_hash = compute_record_hash(
            action_id=row["action_id"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            method=row["method"],
            params=row["params"],
            requested_at=row["requested_at"],
            decision=row["decision"],
            violations=row["violations"],
            severity=row["severity"],
            bundle_revision=row["bundle_revision"],
            prev_hash=row["prev_hash"],
        )

        if expected_hash != row["record_hash"]:
            return {
                "valid": False,
                "failed_at_action_id": row["action_id"],
                "reason": "record_hash mismatch",
                "tenant_id": tenant_id,
            }

        expected_prev = row["record_hash"]

    return {"valid": True, "record_count": len(rows), "tenant_id": tenant_id}


# ── Helper: build OPA input ─────────────────────────────────────────────────


def build_opa_input(
    req: ToolCallRequest,
    action_id: str,
    history: Optional[dict] = None,
    credentials_registered: Optional[list[str]] = None,
    tenant: Optional[dict] = None,
) -> dict:
    """Assemble the OPA input document from the incoming request."""
    now = datetime.now(timezone.utc)
    hour = now.hour
    weekday = now.weekday()
    is_business_hours = (0 <= weekday <= 4) and (9 <= hour < 18)

    if req.context_override and req.context_override.is_business_hours is not None:
        is_business_hours = req.context_override.is_business_hours

    # Default neutral history (Pass 1)
    if history is None:
        history = _default_history()

    tenant_id = tenant["tenant_id"] if tenant else DEFAULT_TENANT_ID
    tenant_name = tenant["name"] if tenant else DEFAULT_TENANT_NAME

    # Include policy_config from tenant record if available
    policy_config = {}
    if tenant and tenant.get("policy_config"):
        try:
            policy_config = (
                json.loads(tenant["policy_config"])
                if isinstance(tenant["policy_config"], str)
                else tenant["policy_config"]
            )
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "tenant": {
            "id": tenant_id,
            "name": tenant_name,
            "policy_config": policy_config,
        },
        "agent": {
            "id": req.agent_id,
            "type": req.agent_type,
            "version": req.agent_version,
            "deployment": "bridge",
            "enclave_verified": False,
            "roles": ["crm_read", "crm_write", "email_send"],
            "jurisdiction": "EU",
        },
        "action": {
            "id": action_id,
            "tool": req.tool,
            "method": req.method,
            "params": req.params,
            "requested_at": now.isoformat(),
        },
        "context": {
            "time_utc": now.isoformat(),
            "hour_of_day": hour,
            "is_business_hours": is_business_hours,
            "approval": {
                "required": False,
                "granted": False,
                "approver": None,
            },
        },
        "data": {
            "contains_pii": False,
            "pii_types": [],
            "classification": "internal",
            "residency_required": "EU",
            "destination": {
                "type": "external_saas",
                "approved": True,
            },
        },
        "history": history,
        "vault": {
            "credentials_registered": credentials_registered or [],
            "brokered_execution": True,
        },
    }


# ── Tenant resolution & API key authentication ─────────────────────────────

# In-memory tenant cache (refreshed from SQLite on startup and on tenant creation)
_tenant_cache: dict[str, dict] = {}  # api_key -> tenant dict
_tenant_by_id: dict[str, dict] = {}  # tenant_id -> tenant dict


def _refresh_tenant_cache():
    """Reload tenant cache from SQLite."""
    global _tenant_cache, _tenant_by_id
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM tenants").fetchall()
        _tenant_cache = {row["api_key"]: dict(row) for row in rows}
        _tenant_by_id = {row["tenant_id"]: dict(row) for row in rows}
    finally:
        conn.close()


def resolve_tenant(api_key: Optional[str]) -> dict:
    """Resolve an API key to a tenant dict. Falls back to default tenant if no key given."""
    if not api_key:
        tenant = _tenant_by_id.get(DEFAULT_TENANT_ID)
        if not tenant:
            _refresh_tenant_cache()
            tenant = _tenant_by_id.get(DEFAULT_TENANT_ID)
        return tenant

    tenant = _tenant_cache.get(api_key)
    if not tenant:
        # Cache miss — try refreshing from DB
        _refresh_tenant_cache()
        tenant = _tenant_cache.get(api_key)
    return tenant


async def get_tenant(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
) -> dict:
    """FastAPI dependency that resolves the tenant from X-API-Key, Bearer JWT,
    or public dashboard header. Falls back to default tenant if none provided."""
    # Try JWT session first (dashboard uses this)
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = auth_module.verify_session_token(token)
        if payload:
            tenant = _tenant_by_id.get(payload["tenant_id"])
            if not tenant:
                _refresh_tenant_cache()
                tenant = _tenant_by_id.get(payload["tenant_id"])
            if tenant:
                return tenant

    # Try API key
    if x_api_key:
        tenant = resolve_tenant(x_api_key)
        if tenant is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return tenant

    # Try public dashboard header (read-only, no auth required)
    if x_vargate_public_tenant:
        _refresh_tenant_cache()
        tenant = _tenant_by_id.get(x_vargate_public_tenant)
        if tenant and tenant.get("public_dashboard"):
            return {**tenant, "is_public_viewer": True}
        # Also try slug lookup
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT tenant_id FROM tenants WHERE slug = ? AND public_dashboard = 1",
                (x_vargate_public_tenant,),
            ).fetchone()
        finally:
            conn.close()
        if row:
            tid = row["tenant_id"]
            tenant = _tenant_by_id.get(tid)
            if not tenant:
                _refresh_tenant_cache()
                tenant = _tenant_by_id.get(tid)
            if tenant:
                return {**tenant, "is_public_viewer": True}
        raise HTTPException(status_code=403, detail="Dashboard is not public")

    # Fallback to default tenant (backward compat)
    tenant = resolve_tenant(None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="No tenant found")
    return tenant


# ── Per-tenant rate limiting (Redis sliding window) ────────────────────────


async def check_rate_limit(tenant: dict) -> bool:
    """Check and increment rate limit for a tenant. Returns True if allowed."""
    if redis_pool is None:
        return True  # No Redis = no rate limiting

    tenant_id = tenant["tenant_id"]
    _rps = tenant["rate_limit_rps"]  # noqa: F841
    burst = tenant["rate_limit_burst"]
    now_ts = time.time()
    window_key = f"t:{tenant_id}:ratelimit"

    try:
        pipe = redis_pool.pipeline()
        # Remove entries older than 1 second
        pipe.zremrangebyscore(window_key, "-inf", now_ts - 1.0)
        # Count entries in current window
        pipe.zcard(window_key)
        # Add current request
        pipe.zadd(window_key, {f"{now_ts}:{secrets.token_hex(4)}": now_ts})
        # Set TTL on the key
        pipe.expire(window_key, 2)
        results = await pipe.execute()

        current_count = results[1]
        if current_count >= burst:
            return False
        return True
    except Exception as e:
        print(f"[RATELIMIT] Error checking rate limit for {tenant_id}: {e}", flush=True)
        fm = failure_modes.get_failure_mode(tenant, "redis")
        if fm == failure_modes.FailureMode.FAIL_CLOSED:
            return False
        return True  # Fail open (default)


# ── Redis behavioral history ────────────────────────────────────────────────


async def fetch_behavioral_history(
    agent_id: str, tenant_id: str = DEFAULT_TENANT_ID
) -> dict:
    """Fetch agent behavioral history from Redis for Pass 2 enrichment."""
    if redis_pool is None:
        return _default_history()

    prefix = f"t:{tenant_id}:agent:{agent_id}"
    try:
        now_ts = time.time()
        ts_10min_ago = now_ts - 600
        ts_24h_ago = now_ts - 86400

        pipe = redis_pool.pipeline()
        pipe.hgetall(f"{prefix}:counters")
        pipe.get(f"{prefix}:anomaly_score")
        pipe.zcount(f"{prefix}:actions", ts_10min_ago, "+inf")
        pipe.zcount(f"{prefix}:actions", ts_24h_ago, "+inf")
        results = await pipe.execute()

        counters = results[0] or {}
        anomaly_raw = results[1]
        action_count_10min = results[2] or 0
        action_count_24h = results[3] or 0

        anomaly_score = float(anomaly_raw) if anomaly_raw else 0.0
        denied_10min = int(
            counters.get(b"denied_count_10min", counters.get("denied_count_10min", 0))
        )
        high_value_24h = int(
            counters.get(
                b"high_value_count_24h", counters.get("high_value_count_24h", 0)
            )
        )
        violation_24h = int(
            counters.get(b"violation_count_24h", counters.get("violation_count_24h", 0))
        )

        # Check 1-hour cooldown: active if 3+ violations in 24h AND last violation < 1h ago
        cooldown_active = False
        if violation_24h >= 3:
            last_violation_ts = counters.get(
                b"last_violation_ts", counters.get("last_violation_ts", None)
            )
            if last_violation_ts:
                elapsed = now_ts - float(last_violation_ts)
                cooldown_active = elapsed < 3600  # 1 hour cooldown

        return {
            "last_10min": {
                "action_count": action_count_10min,
                "denied_count": denied_10min,
            },
            "last_24h": {
                "high_value_transactions": high_value_24h,
                "policy_violations": violation_24h,
                "action_count": action_count_24h,
            },
            "anomaly_score": round(anomaly_score, 4),
            "flagged": anomaly_score > 0.5,
            "cooldown_active": cooldown_active,
        }
    except Exception as e:
        print(f"[REDIS] Error fetching history for {agent_id}: {e}", flush=True)
        return _default_history()


def _default_history() -> dict:
    return {
        "last_10min": {"action_count": 0, "denied_count": 0},
        "last_24h": {
            "high_value_transactions": 0,
            "policy_violations": 0,
            "action_count": 0,
        },
        "anomaly_score": 0.0,
        "flagged": False,
        "cooldown_active": False,
    }


async def update_behavioral_history(
    agent_id: str,
    action_id: str,
    decision: str,
    amount: Optional[float],
    tenant_id: str = DEFAULT_TENANT_ID,
):
    """Update Redis behavioral history after a decision."""
    if redis_pool is None:
        return

    prefix = f"t:{tenant_id}:agent:{agent_id}"
    try:
        now_ts = time.time()
        ts_24h_ago = now_ts - 86400

        # Always read current anomaly score from Redis
        current_raw = await redis_pool.get(f"{prefix}:anomaly_score")
        current_score = float(current_raw) if current_raw else 0.0

        # Compute new anomaly score with decay
        new_score = current_score * 0.95  # decay
        if decision == "deny":
            new_score = min(1.0, new_score + 0.15)
        elif amount is not None and amount >= 1000:
            new_score = min(1.0, new_score + 0.03)

        pipe = redis_pool.pipeline()

        # Increment counters
        pipe.hincrby(f"{prefix}:counters", "action_count_10min", 1)
        pipe.hincrby(f"{prefix}:counters", "action_count_24h", 1)

        if decision == "deny":
            pipe.hincrby(f"{prefix}:counters", "denied_count_10min", 1)
            pipe.hincrby(f"{prefix}:counters", "violation_count_24h", 1)
            pipe.hset(f"{prefix}:counters", "last_violation_ts", str(now_ts))

        if amount is not None and amount >= 1000:
            pipe.hincrby(f"{prefix}:counters", "high_value_count_24h", 1)

        # Update anomaly score
        pipe.set(
            f"{prefix}:anomaly_score", str(round(new_score, 6)), ex=7 * 86400
        )  # 7 day TTL

        # Add action to sorted set
        pipe.zadd(f"{prefix}:actions", {action_id: now_ts})

        # Trim sorted set to last 24 hours
        pipe.zremrangebyscore(f"{prefix}:actions", "-inf", ts_24h_ago)

        # Set TTL on counters (25 hours)
        pipe.expire(f"{prefix}:counters", 25 * 3600)

        await pipe.execute()
    except Exception as e:
        print(f"[REDIS] Error updating history for {agent_id}: {e}", flush=True)


async def flush_agent_history(agent_id: str, tenant_id: str = DEFAULT_TENANT_ID):
    """Clear all Redis data for an agent (used by tests)."""
    if redis_pool is None:
        return
    prefix = f"t:{tenant_id}:agent:{agent_id}"
    try:
        pipe = redis_pool.pipeline()
        pipe.delete(f"{prefix}:counters")
        pipe.delete(f"{prefix}:anomaly_score")
        pipe.delete(f"{prefix}:actions")
        # Also clean legacy (non-prefixed) keys for backward compat during migration
        pipe.delete(f"agent:{agent_id}:counters")
        pipe.delete(f"agent:{agent_id}:anomaly_score")
        pipe.delete(f"agent:{agent_id}:actions")
        await pipe.execute()
    except Exception as e:
        print(f"[REDIS] Error flushing agent {agent_id}: {e}", flush=True)


async def get_agent_anomaly_score(
    agent_id: str, tenant_id: str = DEFAULT_TENANT_ID
) -> float:
    """Get current anomaly score for an agent."""
    if redis_pool is None:
        return 0.0
    prefix = f"t:{tenant_id}:agent:{agent_id}"
    try:
        val = await redis_pool.get(f"{prefix}:anomaly_score")
        return float(val) if val else 0.0
    except Exception:
        return 0.0


async def _agent_has_violations(
    agent_id: str, tenant_id: str = DEFAULT_TENANT_ID
) -> bool:
    """Quick check: does this agent have any recorded violations?
    Single Redis HGET — fast enough for every request."""
    if redis_pool is None:
        return False
    prefix = f"t:{tenant_id}:agent:{agent_id}"
    try:
        val = await redis_pool.hget(f"{prefix}:counters", "violation_count_24h")
        return val is not None and int(val) > 0
    except Exception:
        return False


# ── OPA query helper ────────────────────────────────────────────────────────


async def query_opa(opa_input: dict, tenant: dict = None) -> dict:
    """Send input to OPA and return the decision result.

    On OPA failure, respects the tenant's configured failure mode:
    fail_closed (default), fail_open, or fail_to_queue.
    """
    opa_start = time.monotonic()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                f"{OPA_URL}{OPA_DECISION_PATH}",
                json={"input": opa_input},
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            prom.ERRORS_TOTAL.labels("opa_timeout").inc()
            if tenant:
                fm = failure_modes.handle_failure(tenant, "opa", e)
                if fm["status"] == "allowed":
                    print(
                        f"[OPA-FAILOPEN] OPA unreachable, fail_open for tenant {tenant['tenant_id']}",
                        flush=True,
                    )
                    return {
                        "allow": True,
                        "violations": [],
                        "severity": "none",
                        "failure_mode": "fail_open",
                        "warning": fm["warning"],
                    }
                elif fm["status"] == "escalated":
                    print(
                        f"[OPA-QUEUE] OPA unreachable, fail_to_queue for tenant {tenant['tenant_id']}",
                        flush=True,
                    )
                    return {
                        "allow": True,
                        "requires_human": True,
                        "violations": [],
                        "severity": "none",
                        "failure_mode": "fail_to_queue",
                    }
            # Default: fail_closed
            raise HTTPException(
                status_code=502,
                detail=f"OPA unreachable: {str(e)}",
            )
    prom.OPA_EVAL_DURATION.observe(time.monotonic() - opa_start)
    return resp.json().get("result", {})


# ── Bundle revision ─────────────────────────────────────────────────────────


async def get_bundle_revision() -> str:
    """Fetch the current bundle revision from the bundle server."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{BUNDLE_SERVER_URL}/bundles/vargate/status")
            if resp.status_code == 200:
                data = resp.json()
                revision = data.get("revision", "")
                if revision:
                    return revision
    except Exception:
        pass
    return DEFAULT_BUNDLE_REVISION


POLICY_TEMPLATES = {
    "general": {
        "name": "General Purpose",
        "description": "Sensible defaults for any agent type — rate limits, anomaly detection, destructive action approval",
        "config_keys": [
            "daily_action_limit",
            "anomaly_threshold",
            "cooldown_violations",
            "approve_destructive",
        ],
    },
    "financial": {
        "name": "Financial Services",
        "description": "Transaction limits, currency enforcement, business-hours controls, mandatory approval above threshold",
        "config_keys": [
            "transaction_limit",
            "currency",
            "business_hours_only",
            "approval_threshold",
            "daily_transaction_cap",
        ],
    },
    "email": {
        "name": "Email & Outreach",
        "description": "Blocked recipient domains, daily send limits, AI disclosure mandates, first-contact approval",
        "config_keys": [
            "daily_send_limit",
            "require_disclosure",
            "first_contact_approval",
            "blocked_domains",
        ],
    },
    "crm": {
        "name": "CRM & Sales",
        "description": "Record modification limits, field-level access control, bulk operation approval, export restrictions",
        "config_keys": [
            "bulk_threshold",
            "allow_delete",
            "export_approval",
            "restricted_fields",
        ],
    },
    "data_access": {
        "name": "Data Access",
        "description": "PII handling, data residency controls, query scope limits, masking requirements",
        "config_keys": [
            "max_row_limit",
            "pii_allowed",
            "allowed_regions",
            "require_masking",
            "daily_query_limit",
        ],
    },
}


@app.get("/policy/templates", tags=["Policy"])
async def list_policy_templates():
    """List available policy templates with their configurable parameters."""
    return {"templates": [{"id": k, **v} for k, v in POLICY_TEMPLATES.items()]}


@app.get("/policy/rules", tags=["Policy"])
async def policy_rules():
    """Parse active OPA policy files and return structured rule descriptions."""
    rules = []
    policy_dir = (
        "/app/policies"
        if os.path.isdir("/app/policies")
        else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "policies")
    )

    # Find all .rego files
    rego_files = []
    for root, dirs, files in os.walk(policy_dir):
        for f in files:
            if f.endswith(".rego"):
                rego_files.append(os.path.join(root, f))

    if not rego_files:
        # Fallback: try relative to working dir
        for root, dirs, files in os.walk("policies"):
            for f in files:
                if f.endswith(".rego"):
                    rego_files.append(os.path.join(root, f))

    for fpath in sorted(rego_files):
        try:
            with open(fpath, "r") as fh:
                content = fh.read()

            fname = os.path.basename(fpath)

            # Extract violation rules: "violations contains msg if {"
            in_violation = False
            current_comment = ""
            block_lines = []
            brace_depth = 0

            for line in content.split("\n"):
                stripped = line.strip()

                # Capture comments above rules
                if stripped.startswith("#") and not in_violation:
                    comment_text = stripped.lstrip("#").strip()
                    if (
                        comment_text
                        and not comment_text.startswith("──")
                        and not comment_text.startswith("═")
                    ):
                        current_comment = comment_text
                    continue

                # Start of a violation rule
                if "violations contains msg if" in stripped:
                    in_violation = True
                    block_lines = []
                    brace_depth = stripped.count("{") - stripped.count("}")
                    continue

                if in_violation:
                    block_lines.append(stripped)
                    brace_depth += stripped.count("{") - stripped.count("}")
                    if brace_depth <= 0:
                        # Parse the block
                        rule_body = "\n".join(block_lines)
                        msg_match = re.search(r'msg\s*:=\s*"([^"]+)"', rule_body)
                        rule_id = msg_match.group(1) if msg_match else "unknown"
                        rules.append(
                            {
                                "id": rule_id,
                                "description": current_comment
                                or _rule_id_to_description(rule_id),
                                "type": "deny",
                                "source": fname,
                            }
                        )
                        in_violation = False
                        current_comment = ""
                    continue

                # requires_human_approval rules
                if "requires_human_approval if" in stripped:
                    desc = current_comment or "Requires human approval"
                    rules.append(
                        {
                            "id": f"requires_human_approval:{desc}",
                            "description": desc,
                            "type": "approval",
                            "source": fname,
                        }
                    )
                    current_comment = ""
                    continue

                # Reset comment if we hit a non-comment, non-rule line
                if stripped and not stripped.startswith("#"):
                    current_comment = ""

        except Exception as e:
            print(f"[POLICY] Error parsing {fpath}: {e}", flush=True)

    # Deduplicate by id
    seen = set()
    unique_rules = []
    for r in rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique_rules.append(r)

    # Fetch current revision
    revision = DEFAULT_BUNDLE_REVISION
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{BUNDLE_SERVER_URL}/bundles/vargate/status")
            if resp.status_code == 200:
                revision = resp.json().get("revision", revision)
    except Exception:
        pass

    return {"rules": unique_rules, "revision": revision}


def _rule_id_to_description(rule_id: str) -> str:
    """Convert a snake_case rule ID to a human-readable description."""
    descriptions = {
        "high_value_transaction_unapproved": "Transactions over €5,000 require approval",
        "gdpr_pii_residency_violation": "Unmasked PII leaving EU — blocked",
        "anomaly_score_threshold_exceeded": "Anomaly score above 0.7 — blocked",
        "high_value_out_of_hours_eur": "High-value actions (€1,000+) outside business hours — blocked",
        "violation_cooldown_active": "3+ violations in 24h — blocked for 1 hour",
        "gtm_consumer_email_blocked": "GTM: emails to consumer domains — blocked",
        "gtm_daily_rate_exceeded": "GTM: daily send limit exceeded — blocked",
        "no_credential_registered_for_tool": "Uncredentialed tool calls — blocked",
    }
    return descriptions.get(rule_id, rule_id.replace("_", " ").capitalize())


@app.get("/bundles/vargate/status", tags=["Policy"])
async def bundle_status_proxy():
    """Proxy bundle status from the bundle server. Returns current policy bundle revision and hash."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{BUNDLE_SERVER_URL}/bundles/vargate/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"revision": DEFAULT_BUNDLE_REVISION, "etag": "unknown"}


# ── PII detection and HSM encryption ────────────────────────────────────────


def detect_pii_fields(params: dict) -> list[str]:
    """Scan params for fields containing PII. Returns list of field names."""
    pii_fields = []
    for key, value in params.items():
        if not isinstance(value, str):
            continue
        # Check name fields
        if key.lower() in _PII_NAME_FIELDS:
            pii_fields.append(key)
            continue
        # Check email
        if _PII_EMAIL_RE.search(value):
            pii_fields.append(key)
            continue
        # Check sort code
        if _PII_SORT_CODE_RE.fullmatch(value):
            pii_fields.append(key)
            continue
        # Check NI number
        if _PII_NI_NUMBER_RE.fullmatch(value.upper()):
            pii_fields.append(key)
            continue
    return pii_fields


def extract_subject_id(params: dict, agent_id: str) -> str:
    """Extract data subject ID from params, falling back to agent_id."""
    for key in ("customer_id", "subject_id", "user_id"):
        if key in params and isinstance(params[key], str):
            return params[key]
    return agent_id


async def encrypt_pii_in_params(
    params: dict, pii_fields: list[str], subject_id: str
) -> dict:
    """Encrypt PII fields in params via the HSM service. Returns modified params."""
    # Ensure key exists for this subject
    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(f"{HSM_URL}/keys", json={"subject_id": subject_id})

        encrypted_params = dict(params)
        for field in pii_fields:
            plaintext = str(params[field])
            resp = await client.post(
                f"{HSM_URL}/encrypt",
                json={"subject_id": subject_id, "plaintext": plaintext},
            )
            if resp.status_code == 200:
                data = resp.json()
                encrypted_params[field] = (
                    f"[ENCRYPTED:{data['key_id']}:{data['ciphertext_b64']}]"
                )
            else:
                print(
                    f"[VARGATE] HSM encrypt failed for {field}: {resp.text}", flush=True
                )

    return encrypted_params


async def decrypt_field_value(value: str) -> dict:
    """Attempt to decrypt an [ENCRYPTED:key_id:ciphertext] value."""
    if not isinstance(value, str) or not value.startswith("[ENCRYPTED:"):
        return {"plaintext": value, "encrypted": False}

    # Parse [ENCRYPTED:key_id:ciphertext_b64]
    inner = value[len("[ENCRYPTED:") : -1]
    parts = inner.split(":", 1)
    if len(parts) != 2:
        return {"error": "malformed_encrypted_field"}

    key_id = parts[0]
    ciphertext_b64 = parts[1]

    # Extract subject_id from key_id (key-{subject_id}-v1)
    subject_id = key_id.replace("key-", "").replace("-v1", "")

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{HSM_URL}/decrypt",
            json={"subject_id": subject_id, "ciphertext_b64": ciphertext_b64},
        )
        if resp.status_code == 200:
            data = resp.json()
            if "error" in data:
                return data
            return {
                "plaintext": data["plaintext"],
                "encrypted": True,
                "decrypted": True,
            }
        return {"error": f"HSM returned {resp.status_code}", "encrypted": True}


# ── Startup / Shutdown ──────────────────────────────────────────────────────


@app.on_event("startup")
async def startup():
    global redis_pool, _anchor_task, merkle_blockchain_client, _merkle_anchor_task, chain_manager, _tree_anchor_task
    init_db()
    # Initialize auth tables (Sprint 3)
    conn = get_db()
    try:
        auth_module.init_auth_db(conn)
    finally:
        conn.close()
    # Initialize approval queue + GTM tables (Sprint 4)
    conn = get_db()
    try:
        approval_module.init_approval_db(conn)
        gtm_constraints.init_gtm_db(conn)
        _seed_gtm_tenant(conn)
    finally:
        conn.close()
    try:
        redis_pool = aioredis.from_url(
            REDIS_URL,
            decode_responses=False,
            socket_connect_timeout=5,
        )
        await redis_pool.ping()
        print("[VARGATE] Redis connected.", flush=True)
    except Exception as e:
        print(
            f"[VARGATE] Redis not available ({e}), running without history.", flush=True
        )
        redis_pool = None

    # Initialize legacy blockchain anchoring (Hardhat)
    if _init_blockchain():
        _anchor_task = asyncio.create_task(_anchor_loop())
        print(
            f"[VARGATE] Legacy anchor task started (interval: {ANCHOR_INTERVAL_SECONDS}s).",
            flush=True,
        )

    # Sprint 5: Initialize multi-chain blockchain anchoring
    try:
        from blockchain_client import CONTRACT_INFO_FILE as _SEPOLIA_CONTRACT
        from blockchain_client import DEPLOYER_PRIVATE_KEY as _DEPLOYER_KEY
        from blockchain_client import ETH_CONTRACT_FILE as _ETH_CONTRACT
        from blockchain_client import ETH_MAINNET_PRIVATE_KEY as _ETH_KEY
        from blockchain_client import ETH_MAINNET_RPC_URL as _ETH_RPC
        from blockchain_client import POLYGON_CONTRACT_FILE as _POLYGON_CONTRACT
        from blockchain_client import POLYGON_PRIVATE_KEY as _POLYGON_KEY
        from blockchain_client import POLYGON_RPC_URL as _POLYGON_RPC
        from blockchain_client import SEPOLIA_RPC_URL as _SEPOLIA_RPC
        from blockchain_client import BlockchainClient as MerkleBlockchainClient
        from blockchain_client import (
            ChainManager,
            EnvVarSigner,
        )
        from blockchain_client import run_anchor_loop as merkle_anchor_loop
        from blockchain_client import (
            run_tree_anchor_loop,
        )

        chain_manager = ChainManager()

        # Initialize Sepolia (backward compat / development)
        if _SEPOLIA_RPC and _DEPLOYER_KEY:
            sepolia_client = MerkleBlockchainClient(
                chain_name="sepolia",
                rpc_url=_SEPOLIA_RPC,
                contract_file=_SEPOLIA_CONTRACT,
                signer=EnvVarSigner(_DEPLOYER_KEY),
            )
            if sepolia_client.connect():
                chain_manager.add_client("sepolia", sepolia_client)
                merkle_blockchain_client = sepolia_client  # backward compat

        # Initialize Polygon PoS (primary production chain)
        if _POLYGON_RPC and _POLYGON_KEY:
            polygon_client = MerkleBlockchainClient(
                chain_name="polygon",
                rpc_url=_POLYGON_RPC,
                contract_file=_POLYGON_CONTRACT,
                signer=EnvVarSigner(_POLYGON_KEY),
            )
            if polygon_client.connect():
                chain_manager.add_client("polygon", polygon_client)
                if not merkle_blockchain_client:
                    merkle_blockchain_client = polygon_client

        # Initialize Polygon Amoy testnet
        if _POLYGON_RPC and _POLYGON_KEY and "amoy" in _POLYGON_RPC.lower():
            # Already connected above as "polygon", re-label
            if "polygon" in chain_manager.clients:
                chain_manager.clients["polygon_amoy"] = chain_manager.clients.pop(
                    "polygon"
                )

        # Initialize Ethereum mainnet (institutional tier)
        if _ETH_RPC and _ETH_KEY:
            eth_client = MerkleBlockchainClient(
                chain_name="ethereum",
                rpc_url=_ETH_RPC,
                contract_file=_ETH_CONTRACT,
                signer=EnvVarSigner(_ETH_KEY),
            )
            if eth_client.connect():
                chain_manager.add_client("ethereum", eth_client)

        connected = chain_manager.connected_chains
        if connected:
            # Start cumulative anchor loop on primary client
            primary = chain_manager.get_default_client()
            if primary:

                def _post_anchor(conn, result):
                    write_anchor_audit_record(
                        conn,
                        result,
                        contract_address=primary.contract_address,
                    )

                _merkle_anchor_task = asyncio.create_task(
                    merkle_anchor_loop(
                        primary, get_db_threadsafe, post_anchor_fn=_post_anchor
                    )
                )

            # Start hourly tree anchor loop
            _tree_anchor_task = asyncio.create_task(
                run_tree_anchor_loop(chain_manager, get_db_threadsafe)
            )

            print(
                f"[VARGATE] Blockchain anchoring connected: {', '.join(connected)}",
                flush=True,
            )
        else:
            print(
                "[VARGATE] No blockchain chains configured — anchoring disabled.",
                flush=True,
            )
    except Exception as e:
        print(f"[VARGATE] Blockchain init failed: {e}", flush=True)
        merkle_blockchain_client = None
        chain_manager = None

    # Fix 5 (AG-2.2): Start background Merkle root recording loop
    _merkle_root_task = asyncio.create_task(  # noqa: F841
        run_merkle_root_loop(get_db_threadsafe)
    )
    print(
        f"[VARGATE] Merkle root recording started (interval: {MERKLE_ROOT_INTERVAL_SECONDS}s).",
        flush=True,
    )

    # Initialize execution engine
    execution_engine.init(MOCK_TOOLS_URL)
    print(
        f"[VARGATE] Execution engine initialized (mock-tools: {MOCK_TOOLS_URL}).",
        flush=True,
    )

    # Register mock tokens with the mock tool server for validation
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            for tool_id, token in [
                ("gmail", "mock-gmail-key-001"),
                ("salesforce", "mock-salesforce-key-001"),
                ("stripe", "mock-stripe-key-001"),
                ("slack", "mock-slack-key-001"),
            ]:
                await client.post(
                    f"{MOCK_TOOLS_URL}/admin/register-token",
                    json={"tool_id": tool_id, "token": token},
                )
        print("[VARGATE] Mock tool tokens registered.", flush=True)
    except Exception as e:
        print(f"[VARGATE] Could not register mock tokens: {e}", flush=True)

    # Load tenant cache
    _refresh_tenant_cache()
    print(f"[VARGATE] Tenant cache loaded: {len(_tenant_cache)} tenant(s).", flush=True)

    # Start daily SQLite backup task
    asyncio.create_task(_backup_loop())
    print("[VARGATE] SQLite backup task started (interval: 24h).", flush=True)

    print("[VARGATE] Gateway started. Database initialised.", flush=True)


async def _backup_loop():
    """Run SQLite backup once per 24 hours."""
    import backup as backup_module

    while True:
        await asyncio.sleep(86400)  # 24 hours
        try:
            await asyncio.to_thread(backup_module.backup_database)
        except Exception as e:
            print(f"[BACKUP] Scheduled backup failed: {e}", flush=True)


@app.on_event("shutdown")
async def shutdown():
    if redis_pool:
        await redis_pool.close()


# ── Routes ───────────────────────────────────────────────────────────────────


@app.post("/mcp/tools/call", tags=["Tool Calls"])
async def tool_call(req: ToolCallRequest, tenant: dict = Depends(get_tenant)):
    """Submit an agent tool call for governance evaluation.

    The proxy evaluates the action against OPA policy, checks gateway
    constraints, logs the decision to the hash-chained audit trail,
    and returns allow/deny/escalate with violation details.
    """
    tenant_id = tenant["tenant_id"]

    # ── Per-tenant rate limiting ────────────────────────────────────
    if not await check_rate_limit(tenant):
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "tenant_id": tenant_id,
                "rate_limit_rps": tenant["rate_limit_rps"],
                "rate_limit_burst": tenant["rate_limit_burst"],
            },
        )

    total_start = time.monotonic()
    action_id = str(uuid.uuid4())
    bundle_revision = await get_bundle_revision()
    amount = req.params.get("amount")

    # ── Fetch registered credentials for OPA vault input ─────────
    credentials_registered = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            cred_resp = await client.get(f"{HSM_URL}/credentials")
            if cred_resp.status_code == 200:
                cred_data = cred_resp.json()
                credentials_registered = list(
                    set(c["tool_id"] for c in cred_data.get("credentials", []))
                )
    except Exception as e:
        print(f"[VARGATE] Failed to fetch credential list: {e}", flush=True)

    # ── Pass 1: Fast path (no Redis) ─────────────────────────────
    opa_start = time.monotonic()
    opa_input_p1 = build_opa_input(
        req,
        action_id,
        history=None,
        credentials_registered=credentials_registered,
        tenant=tenant,
    )
    requested_at = opa_input_p1["action"]["requested_at"]
    result_p1 = await query_opa(opa_input_p1, tenant=tenant)

    allowed_p1 = result_p1.get("allow", False)
    _violations_p1 = result_p1.get("violations", [])  # noqa: F841
    eval_mode = result_p1.get("evaluation_mode", "fast")

    evaluation_pass = 1
    anomaly_score = 0.0

    # Check if agent has behavioral red flags (cheap single Redis key check)
    agent_flagged = await _agent_has_violations(req.agent_id, tenant_id=tenant_id)

    # If denied on Pass 1 — block immediately
    if not allowed_p1:
        final_result = result_p1
    # If needs_enrichment OR agent has behavioral flags — do Pass 2
    elif eval_mode == "needs_enrichment" or agent_flagged:
        evaluation_pass = 2
        history = await fetch_behavioral_history(req.agent_id, tenant_id=tenant_id)
        anomaly_score = history.get("anomaly_score", 0.0)
        opa_input_p2 = build_opa_input(
            req,
            action_id,
            history=history,
            credentials_registered=credentials_registered,
            tenant=tenant,
        )
        # Preserve the same requested_at from Pass 1
        opa_input_p2["action"]["requested_at"] = requested_at
        final_result = await query_opa(opa_input_p2, tenant=tenant)
    # If allowed and fast mode with clean history — forward immediately
    else:
        final_result = result_p1

    opa_elapsed_ms = int((time.monotonic() - opa_start) * 1000)

    # Extract final decision
    allowed = final_result.get("allow", False)
    violations = final_result.get("violations", [])
    severity = final_result.get("severity", "none")
    alert_tier = final_result.get("alert_tier", "none")
    requires_human = final_result.get("requires_human", False)
    decision_str = "allow" if allowed else "deny"

    # ── Sprint 4: GTM safety constraints (checked before execution) ──
    gtm_violations = []
    if allowed and tenant_id == GTM_TENANT_ID:
        gtm_conn = get_db()
        try:
            gtm_violations = gtm_constraints.check_gtm_constraints(
                gtm_conn,
                tenant_id,
                req.tool,
                req.method,
                req.params,
                action_id,
            )
        finally:
            gtm_conn.close()
        if gtm_violations:
            allowed = False
            decision_str = "deny"
            violations = violations + [v["rule"] for v in gtm_violations]
            severity = max(
                [severity] + [v["severity"] for v in gtm_violations],
                key=lambda s: {"critical": 3, "high": 2, "medium": 1, "none": 0}.get(
                    s, 0
                ),
            )
            requires_human = False  # blocked outright, no approval queue

    # ── Sprint 4: Human-approval queue ────────────────────────────
    pending_approval = False
    if allowed and requires_human:
        # Enqueue action instead of executing it
        approval_conn = get_db()
        try:
            _queued = approval_module.enqueue_action(  # noqa: F841
                approval_conn,
                action_id,
                tenant_id,
                req.agent_id,
                req.tool,
                req.method,
                req.params,
                final_result,
            )
        finally:
            approval_conn.close()

        # Still log to audit trail as "pending_approval"
        decision_str = "pending_approval"
        allowed = False  # don't execute yet
        pending_approval = True

    # Determine the final opa_input used for the decision
    if evaluation_pass == 2:
        final_opa_input = opa_input_p2
    else:
        final_opa_input = opa_input_p1

    # ── Brokered execution (Stage 8) ─────────────────────────────
    execution_mode = "agent_direct"
    execution_result = None
    execution_latency_ms = None
    credential_accessed = None
    hsm_fetch_ms = 0
    exec_ms = 0

    if allowed:
        # Attempt brokered execution
        cred_name = "api_key"  # Default credential name
        try:
            # Fetch credential from HSM vault
            hsm_start = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0) as client:
                fetch_resp = await client.get(
                    f"{HSM_URL}/credentials/{req.tool}/status"
                )
                if fetch_resp.status_code == 200 and fetch_resp.json().get(
                    "registered"
                ):
                    # Credential exists — do brokered execution
                    # SECURITY: fetch via HSM HTTP endpoint, logs access but never the value
                    cred_fetch_resp = await client.post(
                        f"{HSM_URL}/credentials/fetch-for-execution",
                        json={
                            "tool_id": req.tool,
                            "name": cred_name,
                            "action_id": action_id,
                            "agent_id": req.agent_id,
                        },
                    )
                    hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)

                    if cred_fetch_resp.status_code == 200:
                        cred_data = cred_fetch_resp.json()
                        credential_value = cred_data.get("credential")
                        # SECURITY: credential_value used only for execution, never logged

                        # Execute the tool call
                        exec_result = await execution_engine.execute_tool_call(
                            tool=req.tool,
                            method=req.method,
                            params=req.params,
                            credential=credential_value,
                        )

                        execution_mode = "vargate_brokered"
                        execution_result = exec_result.get("result", {})
                        exec_ms = exec_result.get("execution_ms", 0)
                        execution_latency_ms = hsm_fetch_ms + exec_ms
                        credential_accessed = f"{req.tool}:{cred_name}"
                    else:
                        hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)
                else:
                    hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)
        except Exception as e:
            print(f"[VARGATE] Brokered execution error: {e}", flush=True)

    # Log to stdout
    pass_label = f"P{evaluation_pass}"
    total_ms = int((time.monotonic() - total_start) * 1000)
    latency_breakdown = {
        "opa_eval_ms": opa_elapsed_ms,
        "hsm_fetch_ms": hsm_fetch_ms,
        "execution_ms": exec_ms,
        "total_ms": total_ms,
    }

    if allowed:
        mode_label = "BROKERED" if execution_mode == "vargate_brokered" else "DIRECT"
        print(
            f"[ALLOW] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"mode={mode_label} pass={pass_label} bundle={bundle_revision} "
            f"latency={json.dumps(latency_breakdown)}",
            flush=True,
        )
    elif pending_approval:
        print(
            f"[PENDING] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"queued_for_approval pass={pass_label} bundle={bundle_revision}",
            flush=True,
        )
    else:
        print(
            f"[BLOCK] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"violations={json.dumps(sorted(violations))} severity={severity} "
            f"pass={pass_label} bundle={bundle_revision}",
            flush=True,
        )

    # ── PII detection and encryption ─────────────────────────────────
    pii_fields = detect_pii_fields(req.params)
    contains_pii = 1 if pii_fields else 0
    pii_subject_id = None
    params_for_audit = req.params

    if pii_fields:
        pii_subject_id = extract_subject_id(req.params, req.agent_id)
        try:
            params_for_audit = await encrypt_pii_in_params(
                req.params, pii_fields, pii_subject_id
            )
            print(
                f"[PII] Encrypted {len(pii_fields)} field(s) for subject "
                f"{pii_subject_id}: {pii_fields}",
                flush=True,
            )
        except Exception as e:
            print(f"[PII] HSM encryption failed: {e}. Storing plaintext.", flush=True)
            params_for_audit = req.params
            contains_pii = 0
            pii_fields = []

    # Record Prometheus metrics
    prom.ACTIONS_TOTAL.labels(decision=decision_str, tenant_id=tenant_id).inc()

    # Write audit record
    conn = get_db()
    try:
        write_audit_record(
            conn=conn,
            action_id=action_id,
            agent_id=req.agent_id,
            tool=req.tool,
            method=req.method,
            params=params_for_audit,
            requested_at=requested_at,
            decision=decision_str,
            violations=sorted(violations),
            severity=severity,
            alert_tier=alert_tier,
            bundle_revision=bundle_revision,
            evaluation_pass=evaluation_pass,
            anomaly_score_at_eval=anomaly_score,
            opa_input=final_opa_input,
            contains_pii=contains_pii,
            tenant_id=tenant_id,
            pii_subject_id=pii_subject_id,
            pii_fields=pii_fields if pii_fields else None,
            execution_mode=execution_mode,
            execution_result=execution_result,
            execution_latency_ms=execution_latency_ms,
            credential_accessed=credential_accessed,
        )
    finally:
        conn.close()

    # Update Redis behavioral history
    await update_behavioral_history(
        agent_id=req.agent_id,
        action_id=action_id,
        decision=decision_str,
        amount=amount,
        tenant_id=tenant_id,
    )

    # ── Webhook dispatch ─────────────────────────────────────────
    webhook_payload = {
        "action_id": action_id,
        "agent_id": req.agent_id,
        "tool": req.tool,
        "method": req.method,
        "decision": decision_str,
        "violations": sorted(violations) if violations else [],
        "severity": severity,
        "requires_human": requires_human,
    }
    if decision_str == "deny":
        await webhooks_module.dispatch_webhook(tenant, "action.denied", webhook_payload)
    elif pending_approval:
        await webhooks_module.dispatch_webhook(
            tenant, "action.pending", webhook_payload
        )
    elif allowed:
        await webhooks_module.dispatch_webhook(
            tenant, "action.allowed", webhook_payload
        )

    # Return response
    if allowed:
        response = {"status": "allowed", "action_id": action_id}
        if execution_mode == "vargate_brokered":
            response["execution_mode"] = "vargate_brokered"
            response["execution_result"] = execution_result
            response["latency"] = latency_breakdown
        return response
    elif pending_approval:
        return JSONResponse(
            status_code=202,
            content={
                "status": "pending_approval",
                "action_id": action_id,
                "message": "Action requires human approval. It has been queued for review.",
            },
        )
    else:
        raise HTTPException(
            status_code=403,
            detail=BlockedResponse(
                action_id=action_id,
                violations=sorted(violations),
                severity=severity,
                alert_tier=alert_tier,
            ).model_dump(),
        )


# ── Agent history endpoints (for test scripts) ──────────────────────────────


@app.delete("/agents/{agent_id}/history", tags=["Audit"])
async def clear_agent_history(agent_id: str, tenant: dict = Depends(get_tenant)):
    """Clear behavioral history for an agent. Used by test scripts."""
    await flush_agent_history(agent_id, tenant_id=tenant["tenant_id"])
    return {"status": "cleared", "agent_id": agent_id}


@app.get("/agents/{agent_id}/anomaly_score", tags=["Audit"])
async def agent_anomaly_score(agent_id: str, tenant: dict = Depends(get_tenant)):
    """Get current anomaly score for an agent."""
    score = await get_agent_anomaly_score(agent_id, tenant_id=tenant["tenant_id"])
    return {"agent_id": agent_id, "anomaly_score": round(score, 6)}


@app.delete("/agents/{agent_id}/counters", tags=["Audit"])
async def clear_agent_counters(agent_id: str, tenant: dict = Depends(get_tenant)):
    """Clear counters and actions but keep anomaly_score. Used by test scripts."""
    tenant_id = tenant["tenant_id"]
    prefix = f"t:{tenant_id}:agent:{agent_id}"
    if redis_pool:
        try:
            pipe = redis_pool.pipeline()
            pipe.delete(f"{prefix}:counters")
            pipe.delete(f"{prefix}:actions")
            # Also clean legacy keys
            pipe.delete(f"agent:{agent_id}:counters")
            pipe.delete(f"agent:{agent_id}:actions")
            await pipe.execute()
        except Exception:
            pass
    return {"status": "counters_cleared", "agent_id": agent_id}


# ── Blockchain Anchoring ─────────────────────────────────────────────────────


class BlockchainClient:
    """Interacts with the AuditAnchor smart contract on Hardhat local chain."""

    def __init__(self, rpc_url: str, contract_address: str, abi: list):
        from web3 import Web3

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi,
        )
        self.account = self.w3.eth.accounts[0]  # Hardhat default funded account
        self.contract_address = contract_address

    def submit_anchor(
        self, chain_tip_hash: str, record_count: int, system_id: str
    ) -> dict:
        # Pad/truncate to bytes32
        hash_bytes = bytes.fromhex(chain_tip_hash)
        if len(hash_bytes) < 32:
            hash_bytes = hash_bytes.ljust(32, b"\x00")
        elif len(hash_bytes) > 32:
            hash_bytes = hash_bytes[:32]

        tx_hash = self.contract.functions.submitAnchor(
            hash_bytes, record_count, system_id
        ).transact({"from": self.account})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Extract anchor index from event logs
        anchor_index = 0
        try:
            logs = self.contract.events.AnchorSubmitted().process_receipt(receipt)
            if logs:
                anchor_index = logs[0]["args"]["anchorIndex"]
        except Exception:
            pass

        return {
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "anchor_index": anchor_index,
        }

    def get_anchor(self, index: int) -> dict:
        anchor = self.contract.functions.getAnchor(index).call()
        return {
            "block_number": anchor[0],
            "timestamp": anchor[1],
            "chain_tip_hash": anchor[2].hex(),
            "record_count": anchor[3],
            "system_id": anchor[4],
        }

    def get_latest_anchor(self) -> Optional[dict]:
        try:
            anchor, index = self.contract.functions.getLatestAnchor().call()
            return {
                "index": index,
                "block_number": anchor[0],
                "timestamp": anchor[1],
                "chain_tip_hash": anchor[2].hex(),
                "record_count": anchor[3],
                "system_id": anchor[4],
            }
        except Exception:
            return None

    def get_anchor_count(self) -> int:
        try:
            return self.contract.functions.getAnchorCount().call()
        except Exception:
            return 0


def _get_chain_tip() -> dict:
    """Get the current chain tip hash and record count from SQLite."""
    conn = get_db()
    row = conn.execute(
        "SELECT record_hash, id FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    count = conn.execute("SELECT COUNT(*) as c FROM audit_log").fetchone()["c"]
    conn.close()
    if row:
        return {"record_hash": row["record_hash"], "record_count": count}
    return {"record_hash": "GENESIS", "record_count": 0}


_last_anchored_count = 0


async def submit_anchor(force=False):
    """Submit current chain state to the blockchain.
    Skips if no new records since last anchor (unless force=True).
    """
    global _last_anchored_count
    if not blockchain_client:
        return None

    tip = _get_chain_tip()
    if tip["record_count"] == 0:
        return None

    # Skip if no new records since last anchor (saves gas)
    if not force and tip["record_count"] == _last_anchored_count:
        return None

    try:
        result = blockchain_client.submit_anchor(
            chain_tip_hash=tip["record_hash"],
            record_count=tip["record_count"],
            system_id="vargate-prototype-v1",
        )

        # Write to anchor_log
        anchored_at = datetime.now(timezone.utc).isoformat()
        conn = get_db()
        conn.execute(
            """INSERT INTO anchor_log
               (anchor_index, chain_tip_hash, record_count, tx_hash, block_number, anchored_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                result["anchor_index"],
                tip["record_hash"],
                tip["record_count"],
                result["tx_hash"],
                result["block_number"],
                anchored_at,
            ),
        )
        conn.commit()
        conn.close()

        print(
            f"[ANCHOR] chain_tip={tip['record_hash'][:16]}... "
            f"records={tip['record_count']} "
            f"tx={result['tx_hash'][:16]}... "
            f"block={result['block_number']}",
            flush=True,
        )

        _last_anchored_count = tip["record_count"]

        return {
            "chain_tip_hash": tip["record_hash"],
            "record_count": tip["record_count"],
            "tx_hash": result["tx_hash"],
            "block_number": result["block_number"],
            "anchor_index": result["anchor_index"],
            "anchored_at": anchored_at,
        }
    except Exception as e:
        print(f"[ANCHOR] Error: {e}", flush=True)
        return None


async def _anchor_loop():
    """Background task that anchors the chain every ANCHOR_INTERVAL_SECONDS."""
    await asyncio.sleep(10)  # Initial delay to let things settle
    while True:
        try:
            await submit_anchor()
        except Exception as e:
            print(f"[ANCHOR] Background error: {e}", flush=True)
        await asyncio.sleep(ANCHOR_INTERVAL_SECONDS)


def _init_blockchain():
    """Initialize blockchain client from shared volume files."""
    global blockchain_client

    try:
        if not os.path.exists(CONTRACT_ADDRESS_FILE):
            print(
                f"[ANCHOR] Contract address file not found: {CONTRACT_ADDRESS_FILE}",
                flush=True,
            )
            return False

        with open(CONTRACT_ADDRESS_FILE) as f:
            contract_address = f.read().strip()

        if not os.path.exists(CONTRACT_ABI_FILE):
            print(
                f"[ANCHOR] Contract ABI file not found: {CONTRACT_ABI_FILE}", flush=True
            )
            return False

        with open(CONTRACT_ABI_FILE) as f:
            abi = json.load(f)

        blockchain_client = BlockchainClient(BLOCKCHAIN_RPC_URL, contract_address, abi)
        print(
            f"[ANCHOR] Blockchain connected. Contract: {contract_address}",
            flush=True,
        )
        return True
    except Exception as e:
        print(f"[ANCHOR] Failed to init blockchain: {e}", flush=True)
        return False


async def get_session_tenant(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
) -> dict:
    """Resolve tenant from Bearer token (JWT session), X-API-Key, or public dashboard header."""
    # Try JWT session first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = auth_module.verify_session_token(token)
        if payload:
            tenant = _tenant_by_id.get(payload["tenant_id"])
            if not tenant:
                _refresh_tenant_cache()
                tenant = _tenant_by_id.get(payload["tenant_id"])
            if tenant:
                return tenant
        raise HTTPException(401, "Invalid or expired session token")

    # Fall back to API key
    if x_api_key:
        tenant = resolve_tenant(x_api_key)
        if tenant:
            return tenant
        raise HTTPException(401, "Invalid API key")

    # Try public dashboard header (read-only access)
    if x_vargate_public_tenant:
        _refresh_tenant_cache()
        tenant = _tenant_by_id.get(x_vargate_public_tenant)
        if tenant and tenant.get("public_dashboard"):
            return {**tenant, "is_public_viewer": True}
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT tenant_id FROM tenants WHERE slug = ? AND public_dashboard = 1",
                (x_vargate_public_tenant,),
            ).fetchone()
        finally:
            conn.close()
        if row:
            tid = row["tenant_id"]
            tenant = _tenant_by_id.get(tid)
            if not tenant:
                _refresh_tenant_cache()
                tenant = _tenant_by_id.get(tid)
            if tenant:
                return {**tenant, "is_public_viewer": True}
        raise HTTPException(403, "Dashboard is not public")

    raise HTTPException(
        401, "Authentication required — provide Bearer token or X-API-Key"
    )


@app.get("/health", tags=["System"], response_model=HealthResponse)
async def health():
    """Check gateway health including Redis, blockchain, and Merkle tree status."""
    redis_ok = False
    if redis_pool:
        try:
            await redis_pool.ping()
            redis_ok = True
        except Exception:
            pass
    blockchain_ok = blockchain_client is not None

    # Sprint 5: Multi-chain and Merkle tree status
    connected_chains = chain_manager.connected_chains if chain_manager else []
    any_chain_connected = bool(connected_chains) or blockchain_ok

    # Merkle tree health
    merkle_ok = False
    merkle_tree_count = 0
    try:
        conn = get_db()
        try:
            row = conn.execute("SELECT COUNT(*) as cnt FROM merkle_trees").fetchone()
            merkle_tree_count = row["cnt"] if row else 0
            merkle_ok = True
        finally:
            conn.close()
    except Exception:
        pass

    return {
        "status": "ok",
        "service": "vargate-gateway",
        "redis": redis_ok,
        "blockchain": any_chain_connected,
        "connected_chains": connected_chains,
        "merkle_trees": merkle_ok,
        "merkle_tree_count": merkle_tree_count,
        # Backward compat
        "sepolia_merkle": "sepolia" in connected_chains,
    }


# /metrics is intentionally unauthenticated — Prometheus scrapes it from
# the internal Docker network. The prod overlay binds gateway to 127.0.0.1
# and nginx does not proxy /metrics, so it is not externally reachable.
@app.get("/metrics", tags=["System"])
async def metrics_endpoint():
    """Prometheus metrics endpoint. Unauthenticated — only accessible from internal Docker network."""
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    from starlette.responses import Response

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/backup/trigger", tags=["System"])
async def trigger_backup(request: Request, tenant: dict = Depends(get_session_tenant)):
    """Trigger an immediate SQLite backup. Requires authentication. Rate-limited to 2/min."""
    from rate_limit import enforce_ip_rate_limit

    await enforce_ip_rate_limit(
        redis_pool, request, "backup", max_requests=2, window_seconds=60
    )
    import backup as backup_module

    try:
        result = await asyncio.to_thread(backup_module.backup_database)
        return {"status": "ok", "backup": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")


# ── Route modules (Audit Item 14) ────────────────────────────────────────────
# Routes are organized into separate modules for maintainability.
# Each module uses late imports to avoid circular dependencies.

from compliance_export import router as compliance_router  # noqa: E402
from mcp_server import router as mcp_server_router  # noqa: E402
from routes_anchor import router as anchor_router  # noqa: E402
from routes_audit import router as audit_router  # noqa: E402
from routes_auth import router as auth_router  # noqa: E402
from routes_tenant import router as tenant_router  # noqa: E402

app.include_router(audit_router)
app.include_router(anchor_router)
app.include_router(tenant_router)
app.include_router(auth_router)
app.include_router(compliance_router)
app.include_router(mcp_server_router)
