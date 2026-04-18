#!/bin/bash
set -e

HSM_URL="${HSM_URL:-http://localhost:8300}"

echo "=== CI Seed: Registering mock credentials ==="

# Wait for HSM
echo -n "Waiting for HSM service..."
for i in $(seq 1 30); do
  if curl -sf "$HSM_URL/health" > /dev/null 2>&1; then
    echo " ready!"
    break
  fi
  echo -n "."
  sleep 2
done

# Register mock credentials for test tools
TOOLS=("gmail" "salesforce" "stripe" "slack" "jira")
for tool in "${TOOLS[@]}"; do
  echo "  Registering $tool..."
  curl -sf -X POST "$HSM_URL/credentials" \
    -H "Content-Type: application/json" \
    -d "{\"tool_id\": \"$tool\", \"name\": \"ci-test\", \"value\": \"mock-credential-for-ci-$tool\"}" \
    > /dev/null
done

# Verify
echo ""
echo "Registered credentials:"
curl -sf "$HSM_URL/credentials" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(f'  ✓ {c[\"tool_id\"]}/{c[\"name\"]}') for c in data.get('credentials',[])]"

# Expose the default tenant's API key so tests that hit admin-only
# endpoints (e.g. /anchor/trigger, gated since b74a72e8) can authenticate.
# Written to $GITHUB_ENV so subsequent CI steps inherit it.
echo ""
echo "Exporting default-tenant API key for admin tests..."
GATEWAY_CONTAINER=$(docker ps --filter "name=gateway" --format "{{.Names}}" | head -1)
if [ -n "$GATEWAY_CONTAINER" ]; then
  DEFAULT_API_KEY=$(docker exec "$GATEWAY_CONTAINER" python3 -c "
import sqlite3
conn = sqlite3.connect('/data/audit.db')
row = conn.execute(\"SELECT api_key FROM tenants WHERE tenant_id='vargate-internal' LIMIT 1\").fetchone()
print(row[0] if row and row[0] else '')
" 2>/dev/null || true)
  if [ -n "$DEFAULT_API_KEY" ]; then
    echo "  ✓ Default-tenant key retrieved (${DEFAULT_API_KEY:0:12}...)"
    if [ -n "${GITHUB_ENV:-}" ]; then
      echo "VARGATE_API_KEY=$DEFAULT_API_KEY" >> "$GITHUB_ENV"
      echo "  ✓ VARGATE_API_KEY exported to subsequent CI steps"
    else
      export VARGATE_API_KEY="$DEFAULT_API_KEY"
      echo "  (GITHUB_ENV not set — exported to current shell only)"
    fi
  else
    echo "  ⚠ Could not retrieve default tenant API key; admin tests may fail"
  fi
else
  echo "  ⚠ Gateway container not found; skipping API-key export"
fi

echo ""
echo "=== CI Seed complete ==="
