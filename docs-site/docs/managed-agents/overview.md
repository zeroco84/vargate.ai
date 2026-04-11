# Managed Agents Overview

Anthropic's [managed agents](https://docs.anthropic.com/en/docs/agents/managed-agents) are a hosted agent runtime where Claude autonomously executes tools inside cloud containers. Vargate adds the governance, audit, and compliance layer that enterprises require before deploying autonomous agents in production.

---

## The Compliance Gap

Managed agents ship with powerful capabilities but no built-in governance:

| Enterprise Requirement | Managed Agents | With Vargate |
|------------------------|:--------------:|:------------:|
| Policy enforcement on tool calls | -- | OPA/Rego evaluation |
| Tamper-evident audit trail | -- | Hash-chained + Merkle + blockchain |
| Human-in-the-loop approval gates | -- | Approval queue with webhooks |
| Credential isolation from agent | -- | HSM vault brokered execution |
| Compliance export artifacts | -- | Per-session PDF/JSON with proofs |
| Anomaly detection | -- | Behavioral analysis + auto-interrupt |

> **Anthropic provides the brain. Vargate provides the governance.**

---

## Three-Layer Architecture

Vargate integrates with managed agents through three complementary layers:

```
┌─────────────────────────────────────────────────┐
│             Customer Application                 │
│                                                  │
│  POST /managed/sessions → Vargate Control Plane  │
└─────────────────────┬────────────────────────────┘
                      │
               ┌──────▼──────┐
               │   VARGATE   │
               │  CONTROL    │◄── Layer 3: Session lifecycle,
               │  PLANE      │    agent config, policy checks
               └──────┬──────┘
                      │
         ┌────────────▼────────────────┐
         │  Anthropic Managed Agents   │
         │                             │
         │  ┌───────────────────────┐  │
         │  │    Agent Session      │  │
         │  │                       │  │
         │  │  Built-in tools ──────┼──┼─► SSE ──► VARGATE EVENT
         │  │  (bash, files, web)   │  │          CONSUMER (Layer 2)
         │  │                       │  │
         │  │  Governed tools ──────┼──┼─► MCP ──► VARGATE MCP
         │  │  (email, pay, APIs)   │  │          SERVER (Layer 1)
         │  │                       │  │
         │  └───────────────────────┘  │
         └─────────────────────────────┘
```

### Layer 1: Active Governance (MCP Server)

Vargate registers as a [remote MCP server](https://modelcontextprotocol.io) on the managed agent. When the agent invokes a governed tool (email, payments, API calls), the request routes through Vargate's full governance pipeline:

1. **OPA/Rego policy evaluation** (two-pass: fast path + behavioral enrichment)
2. **PII detection** and encryption on parameters
3. **Human approval gate** for sensitive actions
4. **HSM credential brokering** -- the agent never sees real credentials
5. **Hash-chained audit logging** with action UUID for traceability

The agent receives a tool result containing the Vargate `action_id`, enabling end-to-end traceability.

### Layer 2: Passive Observability (Event Consumer)

Vargate subscribes to the agent session's SSE event stream, capturing activity from built-in tools (bash, file ops, web fetch) that don't route through the MCP server:

- Every tool execution logged with `source: 'mcp_observed'`
- Anomaly detection on dangerous patterns (credential access, exfiltration attempts, destructive commands)
- Behavioral scoring fed into Redis for real-time analysis
- Events included in Merkle tree aggregation and blockchain anchoring

!!! info "Observed vs. Governed"
    Passively observed events are logged with `decision: "observed"` to clearly distinguish them from actively governed events. Auditors see: "12 tool calls went through active policy enforcement; 8 built-in operations were passively logged."

### Layer 3: Control Plane (Session Governance)

Vargate wraps the Anthropic managed agents API, becoming the entry point for session lifecycle:

- **Agent configuration** with governance profiles, tool restrictions, budget caps
- **Session creation** with automatic MCP server injection and governance prompt
- **Rate limiting** -- max concurrent sessions, daily limits, per-agent quotas
- **Emergency interrupt** -- manual or auto-triggered on anomaly threshold
- **Compliance export** -- per-session audit artifacts with cryptographic proofs

---

## AGCS Control Coverage

The integration maps to every control in the [Agent Governance Certification Standard (AGCS v0.9)](https://vargate.ai/agcs):

| Control | Description | Layer |
|---------|-------------|-------|
| AG-1.1 | Policy-Based Action Evaluation | MCP Server |
| AG-1.2 | Immutable Audit Trail | MCP Server + Event Consumer |
| AG-1.3 | Action Identification | MCP Server |
| AG-1.4 | Agent Identification | Control Plane |
| AG-1.5 | Decision Transparency | Event Consumer |
| AG-1.6 | Human Override | MCP Server + Control Plane |
| AG-1.7 | Rate Limiting | Control Plane |
| AG-1.8 | Per-Tenant Isolation | All Layers |
| AG-1.9 | Credential Brokering | MCP Server |
| AG-1.10 | Behavioral Analysis | Event Consumer |
| AG-1.11 | PII Detection | MCP Server |
| AG-2.1 | Structured Audit Schema | All Layers |
| AG-2.2 | Merkle Tree Aggregation | Event Consumer |
| AG-2.3 | Blockchain Anchoring | Event Consumer |
| AG-2.8 | Decision Replayability | MCP Server |
| AG-2.9 | Safety Constraints | MCP Server + Control Plane |

---

## Prerequisites

Before setting up managed agent governance, you'll need:

1. **A Vargate account** -- [sign up](https://vargate.ai/signup) or see [Quick Start](../quickstart.md)
2. **An Anthropic API key** with managed agents access
3. **Enterprise egress IPs** (recommended) -- Anthropic provides stable egress IPs for enterprise accounts, enabling IP allowlisting on Vargate's MCP server endpoint

---

## Next Steps

- [Setup Guide](setup.md) -- step-by-step walkthrough from first connection to production
- [Policy Templates](policies.md) -- pre-built OPA/Rego policies for managed agent governance
- [API Reference](../api/managed-agents.md) -- full endpoint documentation
