"""
Vargate Event Consumer — Passive Observability for Managed Agent Sessions (Sprint 10)

Subscribes to Anthropic's managed agent SSE event streams and logs all activity
(governed and built-in tool executions) to Vargate's audit trail.

AGCS Controls: AG-1.2, AG-1.5, AG-1.10, AG-2.1, AG-2.2
"""

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

import httpx

# ── Configuration ──────────────────────────────────────────────────────────

ANTHROPIC_API_BASE = "https://api.anthropic.com"
DEFAULT_RECONNECT_DELAY = 2  # seconds
MAX_RECONNECT_DELAY = 60
SSE_TIMEOUT = 300  # 5 min idle timeout before reconnect

# ── Anomaly Detection Patterns ─────────────────────────────────────────────
# Pattern categories for built-in tool anomaly detection (Sprint 10.3)

BASH_DANGEROUS_PATTERNS = [
    # Destructive commands
    (
        re.compile(r"\brm\s+(-[rfR]+\s+|--force|--recursive)"),
        "destructive_command",
        "high",
    ),
    (re.compile(r"\bmkfs\b"), "destructive_command", "critical"),
    (re.compile(r"\bdd\s+.*of=/dev/"), "destructive_command", "critical"),
    # Credential access
    (
        re.compile(r"cat\s+.*(\.env|credentials|secret|password|\.pem|\.key|id_rsa)"),
        "credential_file_access",
        "high",
    ),
    (
        re.compile(r"(cat|less|more|head|tail)\s+.*(/etc/passwd|/etc/shadow)"),
        "credential_file_access",
        "critical",
    ),
    # Exfiltration patterns
    (
        re.compile(r"curl\s+.*(-d|--data|--upload-file|--form|-F|-T)"),
        "potential_exfiltration",
        "medium",
    ),
    (re.compile(r"wget\s+.*--post"), "potential_exfiltration", "medium"),
    (
        re.compile(r"base64\s+(-e|--encode)?\s+.*\|.*curl"),
        "encoded_exfiltration",
        "high",
    ),
    (re.compile(r"curl\s+.*\|\s*bash"), "remote_code_execution", "critical"),
    (re.compile(r"wget\s+.*\|\s*bash"), "remote_code_execution", "critical"),
    # Privilege escalation
    (re.compile(r"\bsudo\b"), "privilege_escalation_attempt", "medium"),
    (re.compile(r"\bchmod\s+[0-7]*7[0-7]*\b"), "permission_escalation", "medium"),
    (re.compile(r"\bchown\b.*root"), "ownership_change", "medium"),
    # Network recon
    (re.compile(r"\bnmap\b"), "network_scanning", "high"),
    (re.compile(r"\bnetcat\b|\bnc\s+-"), "network_tool_usage", "high"),
]

FILE_DANGEROUS_PATTERNS = [
    (
        re.compile(r"(\.env|credentials|secret|password|\.pem|\.key|id_rsa|\.ssh/)"),
        "sensitive_file_access",
        "high",
    ),
    (re.compile(r"/proc/|/sys/|/dev/"), "system_file_access", "medium"),
    (re.compile(r"\.\./\.\./"), "directory_traversal", "high"),
]

# ── Event Types ────────────────────────────────────────────────────────────

EVENT_TYPES = {
    "agent.tool_use",
    "agent.tool_result",
    "agent.message",
    "session.status_idled",
    "session.status_active",
    "session.completed",
    "session.failed",
}


# ── SSE Parser ─────────────────────────────────────────────────────────────


class SSEEvent:
    """Parsed Server-Sent Event."""

    def __init__(self, event: str = "", data: str = "", id: str = ""):
        self.event = event
        self.data = data
        self.id = id

    @property
    def json_data(self) -> Optional[dict]:
        try:
            return json.loads(self.data)
        except (json.JSONDecodeError, TypeError):
            return None

    def __repr__(self):
        return f"SSEEvent(event={self.event!r}, data={self.data[:80]!r})"


async def parse_sse_stream(response):
    """Async generator that yields SSEEvent objects from an httpx streaming response."""
    event = ""
    data_lines = []
    event_id = ""

    async for line in response.aiter_lines():
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].strip())
        elif line.startswith("id:"):
            event_id = line[3:].strip()
        elif line == "":
            # Empty line = end of event
            if data_lines:
                yield SSEEvent(
                    event=event,
                    data="\n".join(data_lines),
                    id=event_id,
                )
            event = ""
            data_lines = []
            event_id = ""


# ── Anomaly Detection ──────────────────────────────────────────────────────


class AnomalyResult:
    """Result of anomaly detection on an observed event."""

    def __init__(self):
        self.anomalies: list[dict] = []

    def add(self, pattern_name: str, severity: str, detail: str = ""):
        self.anomalies.append(
            {
                "pattern": pattern_name,
                "severity": severity,
                "detail": detail,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    @property
    def is_anomalous(self) -> bool:
        return len(self.anomalies) > 0

    @property
    def max_severity(self) -> str:
        if not self.anomalies:
            return "none"
        severities = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        worst = max(self.anomalies, key=lambda a: severities.get(a["severity"], 0))
        return worst["severity"]


def detect_anomalies(
    tool_name: str,
    arguments: dict,
    domain_allowlist: Optional[set[str]] = None,
) -> AnomalyResult:
    """
    Detect anomalies in a passively observed tool execution.

    Checks bash commands, file operations, and web fetches against
    known dangerous patterns.
    """
    result = AnomalyResult()

    # Normalize tool name
    tool_lower = tool_name.lower()

    # ── Bash / shell commands ──────────────────────────────────────────
    if tool_lower in ("bash", "computer", "terminal", "shell"):
        command = arguments.get("command", arguments.get("input", ""))
        if isinstance(command, str):
            for pattern, name, severity in BASH_DANGEROUS_PATTERNS:
                if pattern.search(command):
                    result.add(name, severity, command[:200])

    # ── File operations ────────────────────────────────────────────────
    elif tool_lower in ("read", "write", "edit", "str_replace_editor", "file"):
        path = arguments.get("path", arguments.get("file_path", ""))
        if isinstance(path, str):
            for pattern, name, severity in FILE_DANGEROUS_PATTERNS:
                if pattern.search(path):
                    result.add(name, severity, path[:200])

        # Large file write detection
        content = arguments.get("content", "")
        if isinstance(content, str) and len(content) > 50000:
            result.add("large_file_write", "medium", f"{len(content)} bytes")

    # ── Web fetch ──────────────────────────────────────────────────────
    elif tool_lower in ("web_fetch", "web_search", "http", "fetch", "curl"):
        url = arguments.get("url", arguments.get("query", ""))
        if isinstance(url, str) and domain_allowlist:
            # Extract domain from URL
            domain_match = re.match(r"https?://([^/:]+)", url)
            if domain_match:
                domain = domain_match.group(1).lower()
                # Check if domain or any parent domain is in allowlist
                parts = domain.split(".")
                allowed = False
                for i in range(len(parts)):
                    if ".".join(parts[i:]) in domain_allowlist:
                        allowed = True
                        break
                if not allowed:
                    result.add("domain_not_allowlisted", "medium", domain)

    return result


# ── Event Consumer ─────────────────────────────────────────────────────────


class ManagedAgentEventConsumer:
    """
    Consumes SSE events from an Anthropic managed agent session.

    Subscribes to the session's event stream, parses events, detects anomalies,
    and logs everything to Vargate's audit trail via callback functions.
    """

    def __init__(
        self,
        session_id: str,
        anthropic_session_id: str,
        tenant_id: str,
        anthropic_api_key: str,
        agent_id: str = "managed-agent",
        on_tool_observed: Optional[Callable] = None,
        on_anomaly_detected: Optional[Callable] = None,
        on_message_observed: Optional[Callable] = None,
        on_session_status: Optional[Callable] = None,
        domain_allowlist: Optional[set[str]] = None,
        api_base: str = ANTHROPIC_API_BASE,
    ):
        self.session_id = session_id
        self.anthropic_session_id = anthropic_session_id
        self.tenant_id = tenant_id
        self.anthropic_api_key = anthropic_api_key
        self.agent_id = agent_id
        self.on_tool_observed = on_tool_observed
        self.on_anomaly_detected = on_anomaly_detected
        self.on_message_observed = on_message_observed
        self.on_session_status = on_session_status
        self.domain_allowlist = domain_allowlist or set()
        self.api_base = api_base

        # State
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._reconnect_delay = DEFAULT_RECONNECT_DELAY
        self._last_event_id: Optional[str] = None
        self._tool_use_buffer: dict[str, dict] = {}  # id → tool_use event

        # Counters
        self.total_events = 0
        self.total_tool_observations = 0
        self.total_anomalies = 0

    async def start(self):
        """Start consuming events (non-blocking, runs as background task)."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._consume_loop())
        print(
            f"[EVENT-CONSUMER] Started for session {self.session_id} "
            f"(anthropic={self.anthropic_session_id})",
            flush=True,
        )

    async def stop(self):
        """Stop the consumer gracefully."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print(f"[EVENT-CONSUMER] Stopped for session {self.session_id}", flush=True)

    async def _consume_loop(self):
        """Main consume loop with reconnection logic."""
        while self._running:
            try:
                await self._connect_and_consume()
            except asyncio.CancelledError:
                break
            except Exception as e:
                if not self._running:
                    break
                print(
                    f"[EVENT-CONSUMER] Connection error for {self.session_id}: {e}. "
                    f"Reconnecting in {self._reconnect_delay}s...",
                    flush=True,
                )
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(
                    self._reconnect_delay * 2, MAX_RECONNECT_DELAY
                )

    async def _connect_and_consume(self):
        """Connect to the SSE stream and process events."""
        url = f"{self.api_base}/v1/sessions/{self.anthropic_session_id}/events"
        headers = {
            "Authorization": f"Bearer {self.anthropic_api_key}",
            "Accept": "text/event-stream",
            "anthropic-version": "2024-11-05",
        }
        if self._last_event_id:
            headers["Last-Event-ID"] = self._last_event_id

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=10.0,
                read=SSE_TIMEOUT,
                write=10.0,
                pool=10.0,
            )
        ) as client:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    body = await response.aread()
                    raise ConnectionError(
                        f"SSE stream returned {response.status_code}: {body[:200]}"
                    )

                # Reset reconnect delay on successful connection
                self._reconnect_delay = DEFAULT_RECONNECT_DELAY
                print(
                    f"[EVENT-CONSUMER] Connected to SSE stream for {self.session_id}",
                    flush=True,
                )

                async for sse_event in parse_sse_stream(response):
                    if not self._running:
                        break

                    self.total_events += 1
                    if sse_event.id:
                        self._last_event_id = sse_event.id

                    await self._handle_event(sse_event)

    async def _handle_event(self, sse_event: SSEEvent):
        """Dispatch a single SSE event to the appropriate handler."""
        event_type = sse_event.event
        data = sse_event.json_data

        if not data:
            return

        if event_type == "agent.tool_use":
            await self._handle_tool_use(data)
        elif event_type == "agent.tool_result":
            await self._handle_tool_result(data)
        elif event_type == "agent.message":
            await self._handle_message(data)
        elif event_type in (
            "session.status_idled",
            "session.status_active",
            "session.completed",
            "session.failed",
        ):
            await self._handle_session_status(event_type, data)

    async def _handle_tool_use(self, data: dict):
        """Handle an agent.tool_use event — buffer it until we get the result."""
        tool_use_id = data.get("id", str(uuid.uuid4()))
        self._tool_use_buffer[tool_use_id] = {
            "tool_name": data.get("name", "unknown"),
            "arguments": data.get("input", data.get("arguments", {})),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _handle_tool_result(self, data: dict):
        """Handle an agent.tool_result event — match with buffered tool_use and log."""
        tool_use_id = data.get("tool_use_id", "")
        result_content = data.get("content", data.get("output", ""))

        # Look up the corresponding tool_use
        tool_use = self._tool_use_buffer.pop(tool_use_id, None)
        if tool_use:
            tool_name = tool_use["tool_name"]
            arguments = tool_use["arguments"]
        else:
            # No matching tool_use — log what we have
            tool_name = data.get("name", "unknown")
            arguments = {}

        # Run anomaly detection
        anomaly_result = detect_anomalies(tool_name, arguments, self.domain_allowlist)

        self.total_tool_observations += 1

        # Notify callback for audit logging
        if self.on_tool_observed:
            await self.on_tool_observed(
                session_id=self.session_id,
                tenant_id=self.tenant_id,
                agent_id=self.agent_id,
                tool_name=tool_name,
                arguments=arguments,
                result=(
                    result_content
                    if isinstance(result_content, str)
                    else json.dumps(result_content)
                ),
                anomaly_result=anomaly_result,
            )

        # Notify anomaly callback if anomalies detected
        if anomaly_result.is_anomalous:
            self.total_anomalies += 1
            if self.on_anomaly_detected:
                await self.on_anomaly_detected(
                    session_id=self.session_id,
                    tenant_id=self.tenant_id,
                    agent_id=self.agent_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    anomalies=anomaly_result.anomalies,
                    max_severity=anomaly_result.max_severity,
                )

    async def _handle_message(self, data: dict):
        """Handle an agent.message event — capture reasoning for transparency (AG-1.5)."""
        content = data.get("content", [])
        text_parts = []
        for block in (content if isinstance(content, list) else [content]):
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif isinstance(block, str):
                text_parts.append(block)

        if text_parts and self.on_message_observed:
            await self.on_message_observed(
                session_id=self.session_id,
                tenant_id=self.tenant_id,
                agent_id=self.agent_id,
                message="\n".join(text_parts),
                role=data.get("role", "assistant"),
            )

    async def _handle_session_status(self, event_type: str, data: dict):
        """Handle session lifecycle events."""
        status_map = {
            "session.status_idled": "idled",
            "session.status_active": "active",
            "session.completed": "completed",
            "session.failed": "failed",
        }
        status = status_map.get(event_type, event_type)

        print(
            f"[EVENT-CONSUMER] Session {self.session_id} status: {status}",
            flush=True,
        )

        if self.on_session_status:
            await self.on_session_status(
                session_id=self.session_id,
                tenant_id=self.tenant_id,
                status=status,
            )

        # Stop consuming on terminal states
        if status in ("completed", "failed"):
            self._running = False


# ── Passive Audit Pipeline (Sprint 10.2) ──────────────────────────────────
# Functions that wire event consumer callbacks into Vargate's audit system.


async def log_observed_tool(
    session_id: str,
    tenant_id: str,
    agent_id: str,
    tool_name: str,
    arguments: dict,
    result: str,
    anomaly_result: AnomalyResult,
):
    """
    Log a passively observed tool execution to the audit chain.
    Sets source='mcp_observed', decision='observed'.
    """
    import main as gateway_main

    action_id = str(uuid.uuid4())
    conn = gateway_main.get_db()

    # Determine severity from anomalies
    severity = anomaly_result.max_severity if anomaly_result.is_anomalous else "none"
    violations = (
        [a["pattern"] for a in anomaly_result.anomalies]
        if anomaly_result.is_anomalous
        else []
    )

    try:
        bundle_revision = await gateway_main.get_bundle_revision()
    except Exception:
        bundle_revision = gateway_main.DEFAULT_BUNDLE_REVISION

    try:
        gateway_main.write_audit_record(
            conn=conn,
            action_id=action_id,
            agent_id=agent_id,
            tool=tool_name,
            method="observed",
            params=arguments,
            requested_at=datetime.now(timezone.utc).isoformat(),
            decision="observed",
            violations=violations,
            severity=severity,
            alert_tier="P4" if not anomaly_result.is_anomalous else "P1",
            bundle_revision=bundle_revision,
            evaluation_pass=0,  # 0 = passive observation, not OPA evaluated
            anomaly_score_at_eval=0.0,
            opa_input=None,
            contains_pii=0,
            tenant_id=tenant_id,
            execution_mode="observed",
            execution_result={"output": result[:10000]} if result else None,
            source="mcp_observed",
            managed_session_id=session_id,
        )
        print(
            f"[EVENT-CONSUMER] Logged observed: {tool_name} session={session_id} "
            f"anomalies={len(violations)}",
            flush=True,
        )
    except Exception as e:
        print(f"[EVENT-CONSUMER] Error logging observed tool: {e}", flush=True)
    finally:
        conn.close()

    # Update Redis behavioral analysis (AG-1.10)
    try:
        await gateway_main.update_behavioral_history(
            agent_id=agent_id,
            action_id=action_id,
            decision="observed" if not anomaly_result.is_anomalous else "deny",
            amount=None,
            tenant_id=tenant_id,
        )
    except Exception as e:
        print(f"[EVENT-CONSUMER] Error updating behavioral history: {e}", flush=True)


async def handle_anomaly_detected(
    session_id: str,
    tenant_id: str,
    agent_id: str,
    tool_name: str,
    arguments: dict,
    anomalies: list[dict],
    max_severity: str,
):
    """Fire webhook and increment Redis anomaly score when anomaly is detected."""
    import main as gateway_main
    import webhooks as webhooks_module

    # Increment anomaly score in Redis
    if gateway_main.redis_pool:
        try:
            prefix = f"t:{tenant_id}:agent:{agent_id}"
            current_raw = await gateway_main.redis_pool.get(f"{prefix}:anomaly_score")
            current_score = float(current_raw) if current_raw else 0.0

            severity_bump = {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.05}
            bump = severity_bump.get(max_severity, 0.05)
            new_score = min(1.0, current_score + bump)

            await gateway_main.redis_pool.set(
                f"{prefix}:anomaly_score",
                str(round(new_score, 6)),
                ex=7 * 86400,
            )
            print(
                f"[ANOMALY] {tool_name} in session {session_id}: "
                f"severity={max_severity} anomaly_score={current_score:.4f}→{new_score:.4f}",
                flush=True,
            )
        except Exception as e:
            print(f"[ANOMALY] Error updating anomaly score: {e}", flush=True)

    # Fire webhook (AG-2.7)
    try:
        # Look up tenant for webhook config
        conn = gateway_main.get_db()
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if row:
                tenant = dict(row)
                await webhooks_module.dispatch_webhook(
                    tenant,
                    "anomaly.detected",
                    {
                        "session_id": session_id,
                        "agent_id": agent_id,
                        "tool_name": tool_name,
                        "anomalies": anomalies,
                        "max_severity": max_severity,
                        "source": "mcp_observed",
                    },
                )
        finally:
            conn.close()
    except Exception as e:
        print(f"[ANOMALY] Error dispatching webhook: {e}", flush=True)


async def handle_session_status(
    session_id: str,
    tenant_id: str,
    status: str,
):
    """Update managed_sessions table when session status changes."""
    import main as gateway_main

    conn = gateway_main.get_db()
    try:
        if status in ("completed", "failed", "interrupted"):
            conn.execute(
                "UPDATE managed_sessions SET status = ?, ended_at = ? WHERE id = ?",
                (status, datetime.now(timezone.utc).isoformat(), session_id),
            )
            conn.commit()
            print(
                f"[EVENT-CONSUMER] Session {session_id} status updated: {status}",
                flush=True,
            )
    except Exception as e:
        print(f"[EVENT-CONSUMER] Error updating session status: {e}", flush=True)
    finally:
        conn.close()


# ── Consumer Factory ───────────────────────────────────────────────────────


def create_consumer(
    session_id: str,
    anthropic_session_id: str,
    tenant_id: str,
    anthropic_api_key: str,
    agent_id: str = "managed-agent",
    domain_allowlist: Optional[set[str]] = None,
    api_base: str = ANTHROPIC_API_BASE,
) -> ManagedAgentEventConsumer:
    """
    Create a fully-wired event consumer for a managed agent session.

    The consumer's callbacks are connected to:
    - Audit logging pipeline (source='mcp_observed')
    - Anomaly detection → webhook dispatch
    - Session status tracking
    """
    return ManagedAgentEventConsumer(
        session_id=session_id,
        anthropic_session_id=anthropic_session_id,
        tenant_id=tenant_id,
        anthropic_api_key=anthropic_api_key,
        agent_id=agent_id,
        on_tool_observed=log_observed_tool,
        on_anomaly_detected=handle_anomaly_detected,
        on_session_status=handle_session_status,
        domain_allowlist=domain_allowlist,
        api_base=api_base,
    )


# ── Active Consumer Registry ──────────────────────────────────────────────
# Tracks all running consumers so they can be stopped or queried.

_active_consumers: dict[str, ManagedAgentEventConsumer] = {}


async def start_consumer(
    session_id: str,
    anthropic_session_id: str,
    tenant_id: str,
    anthropic_api_key: str,
    agent_id: str = "managed-agent",
    domain_allowlist: Optional[set[str]] = None,
) -> ManagedAgentEventConsumer:
    """Start a new event consumer and register it."""
    consumer = create_consumer(
        session_id=session_id,
        anthropic_session_id=anthropic_session_id,
        tenant_id=tenant_id,
        anthropic_api_key=anthropic_api_key,
        agent_id=agent_id,
        domain_allowlist=domain_allowlist,
    )
    _active_consumers[session_id] = consumer
    await consumer.start()
    return consumer


async def stop_consumer(session_id: str):
    """Stop and deregister a consumer."""
    consumer = _active_consumers.pop(session_id, None)
    if consumer:
        await consumer.stop()


def get_consumer(session_id: str) -> Optional[ManagedAgentEventConsumer]:
    """Get an active consumer by session ID."""
    return _active_consumers.get(session_id)


def list_active_consumers() -> list[dict]:
    """List all active consumers with their stats."""
    return [
        {
            "session_id": c.session_id,
            "tenant_id": c.tenant_id,
            "agent_id": c.agent_id,
            "total_events": c.total_events,
            "total_tool_observations": c.total_tool_observations,
            "total_anomalies": c.total_anomalies,
            "running": c._running,
        }
        for c in _active_consumers.values()
    ]
