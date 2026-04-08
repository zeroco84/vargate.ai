# Blockchain & Merkle Proofs

Vargate aggregates audit records into Merkle trees and anchors the tree roots to public blockchains. This creates an independently verifiable, immutable record of governance decisions.

---

## Architecture

```
Audit Records → Hourly Merkle Trees → Blockchain Anchor → On-Chain Verification
```

1. **Hourly Merkle trees** — audit records are grouped into per-tenant Merkle trees every hour
2. **Inclusion proofs** — any record can be proven to exist in a tree with O(log n) proof
3. **Blockchain anchor** — the Merkle root is submitted to a smart contract on-chain
4. **Verification** — anyone can verify the on-chain root matches the local tree root

### Supported Chains

| Chain | Usage | Explorer |
|-------|-------|---------|
| Polygon | Production (default) | [polygonscan.com](https://polygonscan.com) |
| Ethereum mainnet | High-assurance | [etherscan.io](https://etherscan.io) |
| Sepolia | Testing | [sepolia.etherscan.io](https://sepolia.etherscan.io) |

Configure your chain preference:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"anchor_chain": "polygon"}'
```

---

## Endpoints

### Anchor Status

```
GET /anchor/status
```

Returns the current state of blockchain anchoring:

```json
{
  "network": "polygon",
  "connected_chains": ["polygon"],
  "contract_address": "0xe742E768...",
  "anchor_count": 42,
  "last_anchor": {
    "merkle_root": "a1b2c3...",
    "tx_hash": "0xdef456...",
    "block_number": 12345678,
    "anchored_at": "2026-04-08T09:00:00Z"
  }
}
```

### Verify On-Chain Anchor

```
GET /anchor/verify
```

Compares the local Merkle root against the on-chain value:

```json
{
  "verified": true,
  "on_chain_root": "a1b2c3...",
  "local_root": "a1b2c3...",
  "tx_hash": "0xdef456..."
}
```

### Trigger Manual Anchor

```
POST /anchor/trigger
```

Manually trigger an anchor cycle (normally runs on schedule):

```json
{
  "status": "anchored",
  "merkle_root": "a1b2c3...",
  "tx_hash": "0xdef456..."
}
```

### List Merkle Trees

```
GET /audit/merkle/roots
```

Returns all Merkle trees with their roots and record ranges:

```json
{
  "trees": [
    {
      "tree_index": 0,
      "merkle_root": "a1b2c3...",
      "record_count": 50,
      "from_record_id": 1,
      "to_record_id": 50,
      "period_start": "2026-04-08T08:00:00Z",
      "period_end": "2026-04-08T09:00:00Z"
    }
  ]
}
```

### Inclusion Proof

```
GET /audit/merkle/proof/{record_hash}
```

Get a Merkle inclusion proof for a specific audit record:

```json
{
  "record_hash": "a1b2c3...",
  "merkle_root": "d4e5f6...",
  "proof": ["hash1", "hash2", "hash3"],
  "verified": true
}
```

!!! note "Proof availability"
    Proofs are only available after the hourly Merkle tree build includes the record.

### Consistency Proof

```
GET /audit/merkle/consistency/{tree_n}/{tree_m}
```

Verify consistency between two Merkle tree periods. Proves that the earlier tree is a prefix of the later tree.

### Compliance Export

```
GET /compliance/export/{tenant_id}?from=2026-01-01&to=2026-04-30&format=json
```

Export a complete compliance package containing:

- All audit records in the date range
- Hash chain verification result
- Merkle tree summary
- Blockchain anchor references with explorer links
- Sample inclusion proofs
- Policy snapshot

Supports `format=json` (default) and `format=pdf`.

!!! tip "Enterprise artifact"
    The compliance export is designed for auditors and regulators. The PDF version includes cover page, summary statistics, and tabular data.
