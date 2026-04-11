# Python Integration

Full working example of integrating a Python agent with Vargate.

---

## Prerequisites

- Python 3.10+
- `httpx` (recommended) or `requests`

```bash
pip install httpx
```

---

## Complete Example

```python
import os
import httpx

# Configuration
VARGATE_URL = os.environ.get("VARGATE_URL", "https://vargate.ai/api")
API_KEY = os.environ["VARGATE_API_KEY"]  # Never hardcode

client = httpx.Client(
    base_url=VARGATE_URL,
    headers={"X-API-Key": API_KEY},
    timeout=30,
)


def governed_tool_call(tool: str, method: str, params: dict) -> dict:
    """Submit a governed tool call to Vargate."""
    response = client.post("/mcp/tools/call", json={
        "agent_id": "my-agent-v1",
        "agent_type": "autonomous",
        "agent_version": "1.0.0",
        "tool": tool,
        "method": method,
        "params": params,
    })

    if response.status_code == 200:
        result = response.json()
        print(f"Allowed: {result['action_id']}")
        return result
    elif response.status_code == 403:
        detail = response.json()["detail"]
        print(f"Denied: {detail['violations']}")
        raise PermissionError(f"Action denied: {detail['violations']}")
    elif response.status_code == 202:
        result = response.json()
        print(f"Pending approval: {result['action_id']}")
        return result
    else:
        response.raise_for_status()


def check_audit_integrity() -> dict:
    """Verify the audit hash chain is intact."""
    response = client.get("/audit/verify")
    response.raise_for_status()
    return response.json()


def get_merkle_proof(record_hash: str) -> dict:
    """Get a Merkle inclusion proof for an audit record."""
    response = client.get(f"/audit/merkle/proof/{record_hash}")
    response.raise_for_status()
    return response.json()


def replay_decision(action_id: str) -> dict:
    """Replay a historical decision against current policy."""
    response = client.post("/audit/replay", json={"action_id": action_id})
    response.raise_for_status()
    return response.json()


# Usage
if __name__ == "__main__":
    # Send a governed action
    result = governed_tool_call("http", "GET", {
        "url": "https://api.example.com/data",
    })

    # Verify audit integrity
    integrity = check_audit_integrity()
    print(f"Chain valid: {integrity['valid']}, records: {integrity['record_count']}")

    # Replay the decision
    if result.get("action_id"):
        replay = replay_decision(result["action_id"])
        print(f"Replay consistent: {replay.get('consistent')}")
```

---

## Async Example

```python
import httpx
import asyncio

async def governed_action_async():
    async with httpx.AsyncClient(
        base_url="https://vargate.ai/api",
        headers={"X-API-Key": API_KEY},
        timeout=30,
    ) as client:
        response = await client.post("/mcp/tools/call", json={
            "agent_id": "async-agent",
            "agent_type": "autonomous",
            "agent_version": "1.0.0",
            "tool": "http",
            "method": "GET",
            "params": {"url": "https://api.example.com/data"},
        })
        return response.json()

result = asyncio.run(governed_action_async())
```

---

## Error Handling

```python
import httpx

try:
    result = governed_tool_call("stripe", "create_transfer", {
        "amount": 50000,
        "destination": "acct_xyz",
    })
except PermissionError as e:
    # Handle policy denial
    print(f"Policy blocked this action: {e}")
except httpx.HTTPStatusError as e:
    if e.response.status_code == 429:
        print("Rate limited — back off and retry")
    elif e.response.status_code == 502:
        print("OPA unavailable — check failure mode config")
    else:
        raise
```

---

## Managed Agents Example

Create and govern an Anthropic managed agent session:

```python
import os
import time
import httpx

client = httpx.Client(
    base_url="https://vargate.ai/api",
    headers={"X-API-Key": os.environ["VARGATE_API_KEY"]},
    timeout=30,
)

# Create agent config
agent = client.post("/managed/agents", json={
    "name": "Research Assistant",
    "anthropic_model": "claude-sonnet-4-6",
    "allowed_tools": ["vargate_web_search", "vargate_send_email"],
    "require_human_approval": ["vargate_send_email"],
    "max_session_hours": 2.0,
}).json()
print(f"Agent config: {agent['id']}")

# Create governed session
session = client.post("/managed/sessions", json={
    "agent_id": agent["id"],
    "user_message": "Research AI governance trends.",
}).json()
print(f"Session: {session['session_id']}")

# Monitor session
while True:
    status = client.get(f"/managed/sessions/{session['session_id']}/status").json()
    print(f"  Governed: {status['total_governed_calls']} | Observed: {status['total_observed_calls']}")
    if status["status"] != "active":
        break
    time.sleep(5)

# Download compliance artifact
compliance = client.get(f"/managed/sessions/{session['session_id']}/compliance").json()
print(f"Events: {compliance['summary']['total_events']}")
```

See the full [Managed Agents Setup Guide](../managed-agents/setup.md) for detailed walkthrough.
