#!/bin/bash
# blockchain/entrypoint.sh (production)
#
# Problem: Hardhat's in-memory chain resets on every container restart,
# which means the AuditAnchor contract loses its address and all anchored state.
# The gateway reads the contract address from /shared/contract_address.txt at
# startup — if the chain resets but the file still exists with the old address,
# the gateway will try to call a contract that no longer exists.
#
# Solution: Always re-deploy the contract on restart (the Hardhat chain is
# ephemeral anyway). The deploy.js script writes contract_address.txt and
# AuditAnchor.abi.json to /shared/ for the gateway to consume.
#
# This is a demo-grade solution. For production you'd use a real chain.

set -e

SHARED_DIR="/shared"
mkdir -p "$SHARED_DIR"

echo "==> Compiling contracts..."
npx hardhat compile

echo "==> Starting Hardhat node..."
npx hardhat node --hostname 0.0.0.0 &
HARDHAT_PID=$!

# Wait for Hardhat to be ready
echo "==> Waiting for Hardhat node to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8545 -X POST \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        > /dev/null 2>&1; then
        echo "==> Hardhat node is ready."
        break
    fi
    echo "    Waiting... ($i/30)"
    sleep 2
done

# Deploy contract — deploy.js writes:
#   /shared/contract_address.txt   (plain text address)
#   /shared/AuditAnchor.abi.json   (contract ABI)
echo "==> Deploying AuditAnchor contract..."
npx hardhat run scripts/deploy.js --network localhost

# Verify the files were written
if [ ! -f "$SHARED_DIR/contract_address.txt" ]; then
    echo "ERROR: deploy.js did not write $SHARED_DIR/contract_address.txt"
    exit 1
fi

if [ ! -f "$SHARED_DIR/AuditAnchor.abi.json" ]; then
    echo "ERROR: deploy.js did not write $SHARED_DIR/AuditAnchor.abi.json"
    exit 1
fi

CONTRACT_ADDRESS=$(cat "$SHARED_DIR/contract_address.txt")
echo "==> Contract deployed at: $CONTRACT_ADDRESS"

# Keep Hardhat running
echo "==> Hardhat node running (PID $HARDHAT_PID). Tailing logs..."
wait $HARDHAT_PID
