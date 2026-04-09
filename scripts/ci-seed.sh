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
echo ""
echo "=== CI Seed complete ==="
