"""
Vargate Python Integration Example

Submit a governed tool call to the Vargate proxy.
Requires: pip install httpx
"""
import httpx

VARGATE_URL = "https://vargate.ai/api"
API_KEY = "your-api-key-here"  # From signup or /api-keys/rotate


def governed_tool_call(tool: str, method: str, params: dict) -> dict:
    """Submit a tool call through Vargate governance proxy."""
    response = httpx.post(
        f"{VARGATE_URL}/mcp/tools/call",
        json={
            "agent_id": "my-agent-v1",
            "agent_type": "autonomous",
            "agent_version": "1.0.0",
            "tool": tool,
            "method": method,
            "params": params,
        },
        headers={"X-API-Key": API_KEY},
        timeout=30,
    )
    response.raise_for_status()
    result = response.json()

    if result["status"] == "blocked":
        print(f"Action denied: {result.get('detail', {}).get('violations', [])}")
    elif result["status"] == "pending_approval":
        print(f"Action requires human approval: {result['action_id']}")
    else:
        print(f"Action allowed: {result['action_id']}")

    return result


def check_audit_integrity() -> dict:
    """Verify the hash chain is intact."""
    response = httpx.get(
        f"{VARGATE_URL}/audit/verify",
        headers={"X-API-Key": API_KEY},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def get_merkle_proof(record_hash: str) -> dict:
    """Get a Merkle inclusion proof for a specific audit record."""
    response = httpx.get(
        f"{VARGATE_URL}/audit/merkle/proof/{record_hash}",
        headers={"X-API-Key": API_KEY},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    # Example: govern an HTTP GET action
    result = governed_tool_call(
        tool="http",
        method="GET",
        params={"url": "https://api.example.com/data"},
    )
    print(result)

    # Verify audit chain
    integrity = check_audit_integrity()
    print(f"Chain valid: {integrity.get('valid')}")
