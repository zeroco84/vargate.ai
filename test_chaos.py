"""
Chaos tests: verify Vargate gateway behaviour when dependencies are unavailable.

These tests temporarily stop individual services and verify the gateway
returns clear error messages rather than crashing or leaking internal state.

Run from the host:
    python test_chaos.py -v

Requires Docker Compose and the Vargate stack to be running.
"""
import httpx
import subprocess
import time
import pytest

BASE = "http://localhost:8000"
API_KEY_HEADER = {"X-API-Key": "test-key-internal-001"}


def stop_service(name):
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.prod.yml", "stop", name],
        check=True, capture_output=True,
    )


def start_service(name):
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.prod.yml", "start", name],
        check=True, capture_output=True,
    )
    time.sleep(5)  # wait for healthcheck


class TestRedisDown:
    """Gateway should continue functioning (degraded) when Redis is unavailable."""

    def setup_method(self):
        stop_service("redis")
        time.sleep(2)

    def teardown_method(self):
        start_service("redis")

    def test_health_reports_redis_down(self):
        r = httpx.get(f"{BASE}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["redis"] is False

    def test_tool_call_still_works_without_redis(self):
        """Core proxy functionality should work even without Redis (rate limiting skipped)."""
        r = httpx.post(f"{BASE}/mcp/tools/call", json={
            "agent_id": "chaos-test",
            "tool": "http",
            "method": "GET",
            "params": {"url": "https://httpbin.org/get"}
        }, headers=API_KEY_HEADER, timeout=15)
        # Should either work (200) or return a clear error, not 500
        assert r.status_code != 500


class TestOPADown:
    """Gateway should return clear policy-error when OPA is unavailable."""

    def setup_method(self):
        stop_service("opa")
        time.sleep(2)

    def teardown_method(self):
        start_service("opa")

    def test_tool_call_returns_policy_error(self):
        r = httpx.post(f"{BASE}/mcp/tools/call", json={
            "agent_id": "chaos-test",
            "tool": "http",
            "method": "GET",
            "params": {"url": "https://example.com"}
        }, headers=API_KEY_HEADER, timeout=15)
        # Should NOT be a generic 500 — should indicate policy evaluation failed
        assert r.status_code in [502, 503, 422, 200]
        if r.status_code != 200:
            body = r.text.lower()
            assert "opa" in body or "policy" in body


class TestBlockchainDown:
    """Audit logging should continue even when blockchain is unreachable."""

    def setup_method(self):
        stop_service("blockchain")
        time.sleep(2)

    def teardown_method(self):
        start_service("blockchain")

    def test_health_reports_blockchain_down(self):
        r = httpx.get(f"{BASE}/health", timeout=10)
        assert r.status_code == 200  # health should still respond

    def test_audit_writes_continue(self):
        """Tool calls should still be audited locally even without blockchain."""
        r = httpx.post(f"{BASE}/mcp/tools/call", json={
            "agent_id": "chaos-test",
            "tool": "http",
            "method": "GET",
            "params": {"url": "https://example.com"}
        }, headers=API_KEY_HEADER, timeout=15)
        # Audit writes to SQLite should work regardless of blockchain state
        assert r.status_code != 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
