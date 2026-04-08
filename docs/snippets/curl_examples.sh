#!/usr/bin/env bash
# Vargate cURL Integration Examples
# Replace YOUR_API_KEY with your actual key from signup.

API_KEY="YOUR_API_KEY"
BASE="https://vargate.ai/api"

# ── Submit a governed tool call ──────────────────────────────────────────────
echo "=== Tool Call ==="
curl -s -X POST "$BASE/mcp/tools/call" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-v1",
    "agent_type": "autonomous",
    "agent_version": "1.0.0",
    "tool": "http",
    "method": "GET",
    "params": {"url": "https://api.example.com/data"}
  }' | python3 -m json.tool

# ── Verify audit chain integrity ─────────────────────────────────────────────
echo "=== Audit Verify ==="
curl -s "$BASE/audit/verify" \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool

# ── Get dashboard data ───────────────────────────────────────────────────────
echo "=== Dashboard ==="
curl -s "$BASE/dashboard/me" \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool

# ── Check Merkle tree roots ──────────────────────────────────────────────────
echo "=== Merkle Roots ==="
curl -s "$BASE/merkle/roots" \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool

# ── View blockchain anchor status ────────────────────────────────────────────
echo "=== Anchor Status ==="
curl -s "$BASE/anchor/status" \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool

# ── List pending approvals ───────────────────────────────────────────────────
echo "=== Pending Approvals ==="
curl -s "$BASE/approvals" \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool

# ── Approve an action ────────────────────────────────────────────────────────
# curl -s -X POST "$BASE/approve/ACTION_ID" \
#   -H "X-API-Key: $API_KEY" | python3 -m json.tool
