# Vargate — Sepolia Merkle Anchor Deployment Guide

## Overview

Stage 7B replaces the local Hardhat blockchain with a real Ethereum Sepolia testnet deployment.
Audit log Merkle roots are anchored on-chain, providing independently-verifiable tamper evidence
with O(log n) inclusion proofs for any individual record (AG-2.2 / AG-2.3).

---

## Prerequisites

### 1. Get Sepolia ETH

You need a small amount of Sepolia testnet ETH to deploy the contract and submit anchors.
Each anchor submission costs ~0.0001 ETH in gas.

**Free faucets:**
- [Alchemy Sepolia Faucet](https://sepoliafaucet.com) — requires an Alchemy account
- [QuickNode Sepolia Faucet](https://faucet.quicknode.com/ethereum/sepolia) — fast, no account needed
- [Google Cloud Sepolia Faucet](https://cloud.google.com/application/web3/faucet/ethereum/sepolia) — requires Google account

You'll need the wallet address derived from your private key. To check your address:

```bash
# Using cast (foundry)
cast wallet address --private-key YOUR_PRIVATE_KEY

# Or using Node.js
node -e "const {ethers} = require('ethers'); console.log(new ethers.Wallet('YOUR_PRIVATE_KEY').address)"
```

### 2. Get a Free RPC Endpoint

Sign up for a free account at one of these providers:

| Provider | Free Tier | URL Format |
|----------|-----------|------------|
| [Alchemy](https://www.alchemy.com/) | 300M compute units/month | `https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY` |
| [Infura](https://www.infura.io/) | 100K requests/day | `https://sepolia.infura.io/v3/YOUR_KEY` |
| [QuickNode](https://www.quicknode.com/) | 1 endpoint free | Provided in dashboard |

Alternatively, you can use a public RPC (less reliable):
```
https://rpc.sepolia.org
https://ethereum-sepolia-rpc.publicnode.com
```

### 3. Generate a Private Key (if you don't have one)

```bash
# Using openssl
openssl rand -hex 32

# Using cast (foundry)
cast wallet new
```

> ⚠️ **Never use a mainnet-funded private key for testing.** Always use a dedicated testnet key.

---

## Deployment Steps

### Step 1: Set Environment Variables

```bash
export SEPOLIA_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
export DEPLOYER_PRIVATE_KEY="your_64_char_hex_private_key"

# Optional: for contract verification on Etherscan
export ETHERSCAN_API_KEY="your_etherscan_api_key"
```

### Step 2: Install Dependencies

```bash
cd blockchain
npm install
```

### Step 3: Compile the Contract

```bash
npx hardhat compile
```

### Step 4: Deploy to Sepolia

```bash
npx hardhat run scripts/deploy_merkle.js --network sepolia
```

Expected output:
```
Deploying MerkleAuditAnchor with account: 0xYourAddress...
Account balance: 0.1 ETH
MerkleAuditAnchor deployed to: 0xContractAddress...
Contract info written to ./MerkleAuditAnchor-deployed.json

── Verify on Etherscan ──
npx hardhat verify --network sepolia 0xContractAddress
```

### Step 5: Copy Deployment Artifact

The deployment script creates `MerkleAuditAnchor-deployed.json`. Copy this to the shared volume:

```bash
# If running locally (not Docker)
cp blockchain/MerkleAuditAnchor-deployed.json shared/MerkleAuditAnchor.json

# If running in Docker, the script writes to /shared/ automatically
```

### Step 6: Verify on Etherscan (Optional)

```bash
npx hardhat verify --network sepolia CONTRACT_ADDRESS
```

Or visit: `https://sepolia.etherscan.io/address/CONTRACT_ADDRESS`

---

## Docker Compose Configuration

Add/update these environment variables in your `.env` file or docker-compose:

```env
# Required for Sepolia Merkle anchoring
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
DEPLOYER_PRIVATE_KEY=your_64_char_hex_private_key

# Optional
ANCHOR_INTERVAL_SECONDS=3600    # How often to auto-anchor (default: 1 hour)
ETHERSCAN_API_KEY=your_key      # For contract verification
```

Then restart the gateway:

```bash
docker compose up -d gateway
```

---

## Verification

### Check Status

```bash
curl http://localhost:8000/anchor/status | jq .
```

Expected:
```json
{
  "network": "sepolia",
  "contract_address": "0x...",
  "deployer_address": "0x...",
  "web3_connected": true,
  "anchor_count": 0
}
```

### Trigger an Anchor

```bash
curl -X POST http://localhost:8000/anchor/trigger | jq .
```

### Verify the Anchor

```bash
curl http://localhost:8000/anchor/verify | jq .
```

### Get an Inclusion Proof

```bash
curl http://localhost:8000/anchor/proof/ACTION_ID | jq .
```

### Run the Full Test

```bash
python test_sepolia_blockchain.py
```

---

## Cost Estimates

| Operation | Approximate Gas | Cost at 1 gwei |
|-----------|----------------|-----------------|
| Contract deployment | ~800,000 | ~0.0008 ETH |
| Each anchor submission | ~80,000 | ~0.00008 ETH |
| 1 anchor/hour for 30 days | ~720 anchors | ~0.06 ETH |

Sepolia ETH is free from faucets, so there is no real cost for testing.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `No RPC_URL configured` | Set `SEPOLIA_RPC_URL` in environment |
| `No DEPLOYER_PRIVATE_KEY` | Set the private key in environment |
| `Contract info not found` | Run the deploy script, copy the JSON to `/shared/` |
| `Transaction reverted` | Check deployer has ETH; check you're using the deployer address |
| `Gas estimation failed` | RPC may be rate-limited; try a different provider |
| Gateway still works without Sepolia | This is by design — Merkle endpoints return `{"error": "blockchain unavailable"}` |

---

## Production Key Management (Fix 8 — AG-3.4)

### Overview

The `BlockchainClient` uses a `SignerBackend` protocol for transaction signing.
Two implementations are provided:

| Backend | Status | Use Case |
|---------|--------|----------|
| `EnvVarSigner` | ✅ Default | Development, testnet, demo |
| `HsmSigner` | 🔲 Stub | Production with FIPS 140-2 Level 3 HSM |

### SignerBackend Protocol

```python
class SignerBackend:
    def sign_transaction(self, w3, transaction: dict) -> SignedTransaction: ...
    def get_address(self) -> str: ...
```

### Default: EnvVarSigner

Reads `DEPLOYER_PRIVATE_KEY` from the environment. The key is held in memory as
plaintext. This is acceptable for **Sepolia testnet** and **demo deployments** but
not for production or mainnet.

### Production: HsmSigner via PKCS#11

To satisfy **AGCS AG-3.4** (Tier 3 certification requires FIPS 140-2 Level 3 HSM):

```python
# Example implementation using python-pkcs11
import pkcs11
from pkcs11 import Mechanism
from eth_account import Account

class Pkcs11HsmSigner(SignerBackend):
    def __init__(self, lib_path: str, slot: int, pin: str, key_label: str):
        self.lib = pkcs11.lib(lib_path)
        self.token = self.lib.get_token(slot=slot)
        self.pin = pin
        self.key_label = key_label

    def sign_transaction(self, w3, transaction: dict):
        with self.token.open(user_pin=self.pin) as session:
            priv_key = session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                label=self.key_label
            )
            # Sign the transaction hash using ECDSA on secp256k1
            tx_hash = w3.eth.account._sign_hash(
                transaction_hash, private_key=None  # delegated to HSM
            )
            # NOTE: actual implementation requires serializing the
            # transaction, computing the hash, signing via PKCS#11,
            # and reconstructing the SignedTransaction object.
            raise NotImplementedError("Full PKCS#11 signing flow TBD")

    def get_address(self) -> str:
        # Derive address from HSM public key
        with self.token.open(user_pin=self.pin) as session:
            pub_key = session.get_key(
                object_class=pkcs11.ObjectClass.PUBLIC_KEY,
                label=self.key_label
            )
            # Convert to Ethereum address
            raise NotImplementedError("Full PKCS#11 address derivation TBD")
```

### Usage

```python
from blockchain_client import BlockchainClient, HsmSigner

# Production with HSM
signer = Pkcs11HsmSigner(
    lib_path="/usr/lib/softhsm/libsofthsm2.so",
    slot=0,
    pin="1234",
    key_label="vargate-deployer"
)
client = BlockchainClient(signer=signer)
```

### Important Notes

- **SoftHSM2** (used in Stage 6 for certificate management) does **NOT** satisfy
  AG-3.4 for Tier 3 certification. SoftHSM2 is a software-only implementation
  and does not meet the FIPS 140-2 Level 3 physical tamper-resistance requirement.
- For Tier 1–2 certification, `EnvVarSigner` with proper secrets management
  (e.g., HashiCorp Vault, AWS Secrets Manager) may be acceptable.
- For mainnet deployment, budget for a cloud HSM (AWS CloudHSM, Azure Dedicated HSM)
  or a hardware unit (YubiHSM 2, Thales Luna).

### Dependencies for HSM Integration

```bash
pip install python-pkcs11
# or for AWS CloudHSM:
pip install aws-cloudhsm-pkcs11
```

