#!/bin/sh
set -e

echo "[BLOCKCHAIN] Compiling contracts..."
npx hardhat compile

echo "[BLOCKCHAIN] Starting Hardhat node..."
npx hardhat node --hostname 0.0.0.0 &
NODE_PID=$!

echo "[BLOCKCHAIN] Waiting for node to be ready..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8545 -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null 2>&1; then
    echo "[BLOCKCHAIN] Node is ready!"
    break
  fi
  echo "[BLOCKCHAIN] Waiting... ($i)"
  sleep 1
done

echo "[BLOCKCHAIN] Deploying AuditAnchor contract..."
npx hardhat run scripts/deploy.js --network localhost

echo "[BLOCKCHAIN] Deployment complete. Node running on port 8545."
wait $NODE_PID
