"""
Vargate Blockchain Client — Multi-Chain Merkle Anchor (Sprint 5, AG-2.2/AG-2.3)

Supports dual-chain anchoring strategy:
  - Polygon PoS: High-frequency anchoring (~$0.01-0.10 per anchor) — default for all tenants
  - Ethereum mainnet: High-value institutional anchoring (~$1-10) — configurable per tenant
  - Sepolia/Amoy testnets for development

Anchors hourly Merkle tree roots from the merkle_trees table to the blockchain.
Each anchor stores the tree's root, record range, and links to the previous anchor
via prev_merkle_root for forward integrity (AG-2.2).

Uses web3.py ~6.x/7.x API — no deprecated patterns.
"""

import asyncio
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from merkle import MerkleTree, GENESIS_ROOT

# ── Configuration ────────────────────────────────────────────────────────────

# Legacy Sepolia (backward compat)
SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL", os.getenv("RPC_URL", ""))
DEPLOYER_PRIVATE_KEY = os.getenv("DEPLOYER_PRIVATE_KEY", "")

# Polygon PoS (primary production chain)
POLYGON_RPC_URL = os.getenv("POLYGON_RPC_URL", "")
POLYGON_PRIVATE_KEY = os.getenv("POLYGON_PRIVATE_KEY", "")

# Ethereum mainnet (institutional tier)
ETH_MAINNET_RPC_URL = os.getenv("ETH_MAINNET_RPC_URL", "")
ETH_MAINNET_PRIVATE_KEY = os.getenv("ETH_MAINNET_PRIVATE_KEY", "")

CONTRACT_INFO_FILE = os.getenv("MERKLE_CONTRACT_FILE", "/shared/MerkleAuditAnchor.json")
POLYGON_CONTRACT_FILE = os.getenv("POLYGON_CONTRACT_FILE", "/shared/PolygonMerkleAuditAnchor.json")
ETH_CONTRACT_FILE = os.getenv("ETH_CONTRACT_FILE", "/shared/EthMerkleAuditAnchor.json")

ANCHOR_INTERVAL_SECONDS = int(os.getenv("ANCHOR_INTERVAL_SECONDS", "3600"))
ANCHOR_MODE = os.getenv("ANCHOR_MODE", "full")
SYSTEM_ID = os.getenv("SYSTEM_ID", "vargate-v1")

# Explorer URLs per chain
CHAIN_EXPLORERS = {
    "sepolia": "https://sepolia.etherscan.io",
    "polygon": "https://polygonscan.com",
    "polygon_amoy": "https://amoy.polygonscan.com",
    "ethereum": "https://etherscan.io",
    "hardhat": None,
}


# ── Signer Abstraction (AG-3.4) ─────────────────────────────────────────────

class SignerBackend:
    """Protocol for transaction signing backends."""

    def sign_transaction(self, w3, transaction: dict):
        raise NotImplementedError

    def get_address(self) -> str:
        raise NotImplementedError


class EnvVarSigner(SignerBackend):
    """Reads private key from environment variable. Dev/testnet only."""

    def __init__(self, private_key: str = ""):
        self._key = private_key
        if self._key and not self._key.startswith("0x"):
            self._key = f"0x{self._key}"
        self._account = None

    def init_account(self, w3):
        if not self._account and self._key:
            self._account = w3.eth.account.from_key(self._key)

    def sign_transaction(self, w3, transaction: dict):
        self.init_account(w3)
        return w3.eth.account.sign_transaction(transaction, self._account.key)

    def get_address(self) -> str:
        if self._account:
            return self._account.address
        return ""

    @property
    def account(self):
        return self._account


class HsmSigner(SignerBackend):
    """Stub: PKCS#11 HSM-backed signer for production (AG-3.4 Tier 3)."""

    def __init__(self, hsm_slot: int = 0, hsm_pin: str = "", key_label: str = ""):
        self.hsm_slot = hsm_slot
        self.hsm_pin = hsm_pin
        self.key_label = key_label

    def sign_transaction(self, w3, transaction: dict):
        raise NotImplementedError("HsmSigner requires PKCS#11 integration.")

    def get_address(self) -> str:
        raise NotImplementedError("HsmSigner requires PKCS#11 integration.")


# ── Blockchain Client ────────────────────────────────────────────────────────

class BlockchainClient:
    """
    Connects to an EVM chain via web3.py. Submits Merkle root anchors to
    the MerkleAuditAnchor smart contract.

    Supports Polygon, Ethereum mainnet, Sepolia, and Amoy testnets.
    """

    def __init__(self, chain_name: str = "sepolia",
                 rpc_url: str = "", contract_file: str = "",
                 signer: Optional[SignerBackend] = None):
        self.chain_name = chain_name
        self.rpc_url = rpc_url
        self.contract_file = contract_file
        self.w3 = None
        self.contract = None
        self.signer = signer or EnvVarSigner()
        self.contract_address: Optional[str] = None
        self._connected = False
        self.chain_id: Optional[int] = None
        self._last_successful_anchor: Optional[datetime] = None

    def connect(self) -> bool:
        """Attempt to connect to the chain and load the contract."""
        try:
            from web3 import Web3

            if not self.rpc_url:
                print(f"[ANCHOR-{self.chain_name}] No RPC URL configured.", flush=True)
                return False

            if self.rpc_url.startswith("wss://") or self.rpc_url.startswith("ws://"):
                provider = Web3.WebSocketProvider(self.rpc_url)
            else:
                provider = Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 30})

            self.w3 = Web3(provider)

            if not self.w3.is_connected():
                print(f"[ANCHOR-{self.chain_name}] Cannot connect to RPC: {self.rpc_url}", flush=True)
                return False

            if not os.path.exists(self.contract_file):
                print(f"[ANCHOR-{self.chain_name}] Contract info not found: {self.contract_file}", flush=True)
                return False

            with open(self.contract_file) as f:
                info = json.load(f)

            contract_address = info.get("address", "")
            abi = info.get("abi", [])

            if not contract_address or not abi:
                print(f"[ANCHOR-{self.chain_name}] Invalid contract info file.", flush=True)
                return False

            self.contract_address = Web3.to_checksum_address(contract_address)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=abi)

            try:
                self.signer.init_account(self.w3)
            except Exception:
                pass

            signer_addr = self.signer.get_address()
            if not signer_addr:
                print(f"[ANCHOR-{self.chain_name}] No signing key configured.", flush=True)
                return False

            self.chain_id = self.w3.eth.chain_id
            print(
                f"[ANCHOR-{self.chain_name}] Connected to chain {self.chain_id}. "
                f"Contract: {self.contract_address}  Deployer: {signer_addr}",
                flush=True,
            )
            self._connected = True
            return True

        except Exception as e:
            print(f"[ANCHOR-{self.chain_name}] Connection failed: {e}", flush=True)
            self._connected = False
            return False

    @property
    def connected(self) -> bool:
        if not self._connected or not self.w3:
            return False
        try:
            if self.w3.is_connected():
                return True
        except Exception:
            pass
        # Fallback: if we anchored recently, we're probably still connected
        if self._last_successful_anchor:
            elapsed = (datetime.now(timezone.utc) - self._last_successful_anchor).total_seconds()
            return elapsed < ANCHOR_INTERVAL_SECONDS * 2
        return False

    @property
    def explorer_base(self) -> str:
        return CHAIN_EXPLORERS.get(self.chain_name, "")

    def explorer_tx_url(self, tx_hash: str) -> Optional[str]:
        base = self.explorer_base
        if base:
            return f"{base}/tx/{tx_hash}"
        return None

    # ── Anchor submission ────────────────────────────────────────────────

    def _anchor_now_sync(self, conn: sqlite3.Connection) -> dict:
        """
        Synchronous core: build Merkle tree, submit root to contract.
        Supports both full and incremental modes.
        """
        if not self.connected:
            raise RuntimeError("Blockchain not connected")

        if ANCHOR_MODE == "incremental":
            last_anchor = conn.execute(
                "SELECT to_record FROM merkle_anchor_log WHERE anchor_chain = ? ORDER BY id DESC LIMIT 1",
                (self.chain_name,),
            ).fetchone()
            if not last_anchor:
                last_anchor = conn.execute(
                    "SELECT to_record FROM merkle_anchor_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
            last_anchored_id = (
                (last_anchor["to_record"] if isinstance(last_anchor, sqlite3.Row) else last_anchor[0])
                if last_anchor else 0
            )
            rows = conn.execute(
                "SELECT id, record_hash FROM audit_log WHERE id > ? ORDER BY id ASC",
                (last_anchored_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, record_hash FROM audit_log ORDER BY id ASC"
            ).fetchall()

        if not rows:
            raise ValueError("No new audit records to anchor")

        leaves = [r["record_hash"] if isinstance(r, sqlite3.Row) else r[1] for r in rows]
        record_ids = [r["id"] if isinstance(r, sqlite3.Row) else r[0] for r in rows]
        from_record = record_ids[0]
        to_record = record_ids[-1]
        record_count = len(leaves)

        tree = MerkleTree(leaves)
        merkle_root_hex = tree.root

        # Look up previous Merkle root for hash-chaining and skip check
        prev_row = conn.execute(
            "SELECT merkle_root FROM merkle_anchor_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_merkle_root_hex = (
            (prev_row["merkle_root"] if isinstance(prev_row, sqlite3.Row) else prev_row[0])
            if prev_row else GENESIS_ROOT
        )

        # Skip if root hasn't changed since last anchor
        if prev_row and prev_merkle_root_hex == merkle_root_hex:
            print(f"[ANCHOR-{self.chain_name}] Root unchanged, skipping anchor.", flush=True)
            return {"skipped": True, "reason": "root_unchanged", "merkle_root": merkle_root_hex}

        root_bytes = bytes.fromhex(merkle_root_hex)
        if len(root_bytes) < 32:
            root_bytes = root_bytes.ljust(32, b"\x00")
        elif len(root_bytes) > 32:
            root_bytes = root_bytes[:32]

        root_chain_hash = hashlib.sha256(
            bytes.fromhex(prev_merkle_root_hex) + bytes.fromhex(merkle_root_hex)
        ).hexdigest()

        prev_root_bytes32 = bytes.fromhex(prev_merkle_root_hex)
        if len(prev_root_bytes32) < 32:
            prev_root_bytes32 = prev_root_bytes32.ljust(32, b"\x00")
        elif len(prev_root_bytes32) > 32:
            prev_root_bytes32 = prev_root_bytes32[:32]

        # Build and sign transaction
        nonce = self.w3.eth.get_transaction_count(self.signer.get_address())

        fn = self.contract.functions.submitAnchor(
            root_bytes, prev_root_bytes32,
            record_count, from_record, to_record, SYSTEM_ID,
        )

        try:
            gas_estimate = fn.estimate_gas({"from": self.signer.get_address()})
            gas_limit = int(gas_estimate * 1.3)
        except Exception as e:
            print(f"[ANCHOR-{self.chain_name}] Gas estimation failed, using fallback: {e}", flush=True)
            gas_limit = 200_000

        try:
            latest_block = self.w3.eth.get_block("latest")
            base_fee = latest_block.get("baseFeePerGas", 0)
            if base_fee:
                max_priority = self.w3.eth.max_priority_fee
                max_fee = base_fee * 2 + max_priority
                tx = fn.build_transaction({
                    "from": self.signer.get_address(),
                    "nonce": nonce,
                    "gas": gas_limit,
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": max_priority,
                    "chainId": self.chain_id,
                })
            else:
                gas_price = self.w3.eth.gas_price
                tx = fn.build_transaction({
                    "from": self.signer.get_address(),
                    "nonce": nonce,
                    "gas": gas_limit,
                    "gasPrice": gas_price,
                    "chainId": self.chain_id,
                })
        except Exception:
            gas_price = self.w3.eth.gas_price
            tx = fn.build_transaction({
                "from": self.signer.get_address(),
                "nonce": nonce,
                "gas": gas_limit,
                "gasPrice": int(gas_price * 1.2),
                "chainId": self.chain_id,
            })

        signed = self.signer.sign_transaction(self.w3, tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted. tx_hash={tx_hash.hex()}")

        anchor_index = 0
        try:
            logs = self.contract.events.AnchorSubmitted().process_receipt(receipt)
            if logs:
                anchor_index = logs[0]["args"]["anchorIndex"]
        except Exception:
            pass

        tx_hash_hex = receipt.transactionHash.hex()
        if not tx_hash_hex.startswith("0x"):
            tx_hash_hex = f"0x{tx_hash_hex}"

        anchored_at = datetime.now(timezone.utc).isoformat()
        self._last_successful_anchor = datetime.now(timezone.utc)
        try:
            import metrics as prom
            prom.ANCHOR_LAST_SUCCESS.set(self._last_successful_anchor.timestamp())
        except Exception:
            pass

        # Write to legacy anchor_log
        conn.execute(
            """INSERT INTO anchor_log
               (anchor_index, chain_tip_hash, merkle_root, record_count,
                from_record, to_record, tx_hash, block_number, anchored_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (anchor_index, merkle_root_hex, merkle_root_hex,
             record_count, from_record, to_record,
             tx_hash_hex, receipt.blockNumber, anchored_at),
        )

        # Write to merkle_anchor_log with chain info
        conn.execute(
            """INSERT INTO merkle_anchor_log
               (anchor_index, merkle_root, record_count, from_record, to_record,
                tx_hash, block_number, anchored_at, prev_merkle_root, root_chain_hash,
                anchor_chain)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (anchor_index, merkle_root_hex, record_count,
             from_record, to_record, tx_hash_hex, receipt.blockNumber,
             anchored_at, prev_merkle_root_hex, root_chain_hash,
             self.chain_name),
        )
        conn.commit()

        print(
            f"[ANCHOR-{self.chain_name}] root={merkle_root_hex[:16]}... "
            f"records={record_count} [{from_record}..{to_record}] "
            f"tx={tx_hash_hex[:18]}... block={receipt.blockNumber}",
            flush=True,
        )

        return {
            "merkle_root": merkle_root_hex,
            "tx_hash": tx_hash_hex,
            "anchor_index": anchor_index,
            "record_count": record_count,
            "from_record": from_record,
            "to_record": to_record,
            "block_number": receipt.blockNumber,
            "anchored_at": anchored_at,
            "chain": self.chain_name,
            "explorer_url": self.explorer_tx_url(tx_hash_hex),
        }

    async def anchor_now(self, conn_or_fn) -> dict:
        """Async wrapper. Accepts a connection (legacy) or get_db callable."""
        if callable(conn_or_fn):
            def _run():
                conn = conn_or_fn()
                try:
                    return self._anchor_now_sync(conn)
                finally:
                    conn.close()
            return await asyncio.to_thread(_run)
        return await asyncio.to_thread(self._anchor_now_sync, conn_or_fn)

    # ── Anchor hourly trees ─────────────────────────────────────────────

    def _anchor_trees_sync(self, conn: sqlite3.Connection, tenant_id: str) -> list[dict]:
        """Anchor all un-anchored hourly trees for a tenant."""
        if not self.connected:
            return []

        un_anchored = conn.execute(
            "SELECT * FROM merkle_trees WHERE tenant_id = ? AND anchor_tx_hash IS NULL "
            "ORDER BY tree_index ASC",
            (tenant_id,),
        ).fetchall()

        results = []
        for tree_row in un_anchored:
            try:
                merkle_root_hex = tree_row["merkle_root"]
                root_bytes = bytes.fromhex(merkle_root_hex)
                if len(root_bytes) < 32:
                    root_bytes = root_bytes.ljust(32, b"\x00")
                elif len(root_bytes) > 32:
                    root_bytes = root_bytes[:32]

                prev_root_hex = tree_row["prev_tree_root"] or GENESIS_ROOT
                prev_root_bytes = bytes.fromhex(prev_root_hex)
                if len(prev_root_bytes) < 32:
                    prev_root_bytes = prev_root_bytes.ljust(32, b"\x00")
                elif len(prev_root_bytes) > 32:
                    prev_root_bytes = prev_root_bytes[:32]

                nonce = self.w3.eth.get_transaction_count(self.signer.get_address())

                fn = self.contract.functions.submitAnchor(
                    root_bytes, prev_root_bytes,
                    tree_row["record_count"],
                    tree_row["from_record_id"],
                    tree_row["to_record_id"],
                    SYSTEM_ID,
                )

                try:
                    gas_estimate = fn.estimate_gas({"from": self.signer.get_address()})
                    gas_limit = int(gas_estimate * 1.3)
                except Exception:
                    gas_limit = 200_000

                try:
                    latest_block = self.w3.eth.get_block("latest")
                    base_fee = latest_block.get("baseFeePerGas", 0)
                    if base_fee:
                        max_priority = self.w3.eth.max_priority_fee
                        max_fee = base_fee * 2 + max_priority
                        tx = fn.build_transaction({
                            "from": self.signer.get_address(),
                            "nonce": nonce,
                            "gas": gas_limit,
                            "maxFeePerGas": max_fee,
                            "maxPriorityFeePerGas": max_priority,
                            "chainId": self.chain_id,
                        })
                    else:
                        gas_price = self.w3.eth.gas_price
                        tx = fn.build_transaction({
                            "from": self.signer.get_address(),
                            "nonce": nonce,
                            "gas": gas_limit,
                            "gasPrice": gas_price,
                            "chainId": self.chain_id,
                        })
                except Exception:
                    gas_price = self.w3.eth.gas_price
                    tx = fn.build_transaction({
                        "from": self.signer.get_address(),
                        "nonce": nonce,
                        "gas": gas_limit,
                        "gasPrice": int(gas_price * 1.2),
                        "chainId": self.chain_id,
                    })

                signed = self.signer.sign_transaction(self.w3, tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

                if receipt.status != 1:
                    print(f"[ANCHOR-{self.chain_name}] Tree {tree_row['tree_index']} tx reverted", flush=True)
                    continue

                tx_hash_hex = receipt.transactionHash.hex()
                if not tx_hash_hex.startswith("0x"):
                    tx_hash_hex = f"0x{tx_hash_hex}"

                self._last_successful_anchor = datetime.now(timezone.utc)
                try:
                    import metrics as prom
                    prom.ANCHOR_LAST_SUCCESS.set(self._last_successful_anchor.timestamp())
                except Exception:
                    pass

                # Update merkle_trees with anchor info
                conn.execute(
                    "UPDATE merkle_trees SET anchor_tx_hash = ?, anchor_chain = ?, anchor_block = ? "
                    "WHERE id = ?",
                    (tx_hash_hex, self.chain_name, receipt.blockNumber, tree_row["id"]),
                )
                conn.commit()

                print(
                    f"[ANCHOR-{self.chain_name}] tree[{tree_row['tree_index']}] tenant={tenant_id} "
                    f"root={merkle_root_hex[:16]}... tx={tx_hash_hex[:18]}... "
                    f"block={receipt.blockNumber}",
                    flush=True,
                )

                results.append({
                    "tree_index": tree_row["tree_index"],
                    "merkle_root": merkle_root_hex,
                    "tx_hash": tx_hash_hex,
                    "block_number": receipt.blockNumber,
                    "chain": self.chain_name,
                    "explorer_url": self.explorer_tx_url(tx_hash_hex),
                })
            except Exception as e:
                print(
                    f"[ANCHOR-{self.chain_name}] Failed to anchor tree[{tree_row['tree_index']}]: {e}",
                    flush=True,
                )

        return results

    async def anchor_trees(self, conn_or_fn, tenant_id: str) -> list[dict]:
        """Async wrapper. Accepts a connection (legacy) or get_db callable."""
        if callable(conn_or_fn):
            def _run():
                conn = conn_or_fn()
                try:
                    return self._anchor_trees_sync(conn, tenant_id)
                finally:
                    conn.close()
            return await asyncio.to_thread(_run)
        return await asyncio.to_thread(self._anchor_trees_sync, conn_or_fn, tenant_id)

    # ── Verification ─────────────────────────────────────────────────────

    def _verify_latest_sync(self, conn: sqlite3.Connection) -> dict:
        if not self.connected:
            return {"error": "blockchain unavailable"}

        try:
            anchor_data, anchor_index = self.contract.functions.getLatestAnchor().call()
            on_chain_root = anchor_data[0].hex()
            on_chain_count = anchor_data[2]
            on_chain_from = anchor_data[3]
            on_chain_to = anchor_data[4]
        except Exception as e:
            return {"error": f"No anchors on-chain or call failed: {e}", "match": False}

        try:
            if ANCHOR_MODE == "incremental":
                rows = conn.execute(
                    "SELECT record_hash FROM audit_log WHERE id >= ? AND id <= ? ORDER BY id ASC",
                    (on_chain_from, on_chain_to),
                ).fetchall()
                leaves = [r["record_hash"] if isinstance(r, sqlite3.Row) else r[0] for r in rows]
                tree = MerkleTree(leaves)
            else:
                tree = MerkleTree.from_db(conn)

            computed_root = tree.root
        except Exception as e:
            return {
                "error": f"Failed to build Merkle tree: {e}",
                "match": False,
                "on_chain_root": on_chain_root,
                "computed_root": None,
            }

        on_chain_clean = on_chain_root.lstrip("0") or "0"
        computed_clean = computed_root.lstrip("0") or "0"
        match = on_chain_clean == computed_clean

        last_anchor = conn.execute(
            "SELECT tx_hash, anchored_at FROM anchor_log ORDER BY id DESC LIMIT 1"
        ).fetchone()

        return {
            "match": match,
            "on_chain_root": on_chain_root,
            "computed_root": computed_root,
            "record_count": tree.leaf_count,
            "on_chain_record_count": on_chain_count,
            "anchor_index": anchor_index,
            "anchor_mode": ANCHOR_MODE,
            "chain": self.chain_name,
            "last_anchor_tx": last_anchor["tx_hash"] if last_anchor else None,
            "last_anchor_time": last_anchor["anchored_at"] if last_anchor else None,
        }

    async def verify_latest(self, conn_or_fn) -> dict:
        """Async wrapper. Accepts a connection (legacy) or get_db callable."""
        if callable(conn_or_fn):
            def _run():
                conn = conn_or_fn()
                try:
                    return self._verify_latest_sync(conn)
                finally:
                    conn.close()
            return await asyncio.to_thread(_run)
        return await asyncio.to_thread(self._verify_latest_sync, conn_or_fn)

    # ── View helpers ─────────────────────────────────────────────────────

    def get_anchor_count(self) -> int:
        if not self.connected:
            return 0
        try:
            return self.contract.functions.getAnchorCount().call()
        except Exception:
            return 0

    def _get_latest_anchor_sync(self) -> Optional[dict]:
        if not self.connected:
            return None
        try:
            anchor_data, index = self.contract.functions.getLatestAnchor().call()
            return {
                "index": index,
                "merkle_root": anchor_data[0].hex(),
                "prev_merkle_root": anchor_data[1].hex(),
                "record_count": anchor_data[2],
                "from_record": anchor_data[3],
                "to_record": anchor_data[4],
                "block_number": anchor_data[5],
                "timestamp": anchor_data[6],
                "system_id": anchor_data[7],
                "chain": self.chain_name,
            }
        except Exception:
            return None

    async def get_latest_anchor(self) -> Optional[dict]:
        return await asyncio.to_thread(self._get_latest_anchor_sync)

    def get_deployer_address(self) -> Optional[str]:
        addr = self.signer.get_address()
        return addr if addr else None


# ── Multi-Chain Manager ──────────────────────────────────────────────────────

class ChainManager:
    """
    Manages multiple blockchain clients for dual-chain anchoring.
    Tenants select their preferred chain; ChainManager routes accordingly.
    """

    def __init__(self):
        self.clients: dict[str, BlockchainClient] = {}
        self.default_chain: str = "polygon"

    def add_client(self, chain_name: str, client: BlockchainClient):
        self.clients[chain_name] = client

    def get_client(self, chain_name: str) -> Optional[BlockchainClient]:
        return self.clients.get(chain_name)

    def get_default_client(self) -> Optional[BlockchainClient]:
        """Return the first connected client, preferring polygon."""
        for name in ["polygon", "polygon_amoy", "sepolia", "ethereum"]:
            client = self.clients.get(name)
            if client and client.connected:
                return client
        # Fallback to any connected client
        for client in self.clients.values():
            if client.connected:
                return client
        return None

    def get_tenant_client(self, tenant: dict) -> Optional[BlockchainClient]:
        """Get the blockchain client for a tenant's preferred chain."""
        chain_pref = tenant.get("anchor_chain", self.default_chain)
        client = self.clients.get(chain_pref)
        if client and client.connected:
            return client
        return self.get_default_client()

    @property
    def connected_chains(self) -> list[str]:
        return [name for name, c in self.clients.items() if c.connected]

    def status(self) -> dict:
        return {
            name: {
                "connected": c.connected,
                "chain_id": c.chain_id,
                "contract": c.contract_address,
                "deployer": c.get_deployer_address(),
                "anchor_count": c.get_anchor_count(),
                "explorer": c.explorer_base,
            }
            for name, c in self.clients.items()
        }


# ── Background anchor loop ──────────────────────────────────────────────────

async def run_anchor_loop(client: BlockchainClient, get_db_fn, post_anchor_fn=None):
    """Background task anchoring every ANCHOR_INTERVAL_SECONDS."""
    await asyncio.sleep(15)

    while True:
        try:
            if client.connected:
                conn = get_db_fn()
                try:
                    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                finally:
                    conn.close()
                if count > 0:
                    # Pass get_db_fn so the sync thread creates its own connection
                    result = await client.anchor_now(get_db_fn)
                    if post_anchor_fn and result:
                        cb_conn = get_db_fn()
                        try:
                            post_anchor_fn(cb_conn, result)
                        finally:
                            cb_conn.close()
                else:
                    print(f"[ANCHOR-{client.chain_name}] No records to anchor yet.", flush=True)
        except Exception as e:
            print(f"[ANCHOR-{client.chain_name}] Background loop error: {e}", flush=True)

        await asyncio.sleep(ANCHOR_INTERVAL_SECONDS)


async def run_tree_anchor_loop(chain_manager: "ChainManager", get_db_fn):
    """
    Sprint 5: Background task that anchors hourly Merkle trees to blockchain.
    Runs per-tenant, using each tenant's preferred chain.
    """
    await asyncio.sleep(30)

    while True:
        try:
            # Read tenant list in the event loop thread
            conn = get_db_fn()
            try:
                tenants = [dict(t) for t in conn.execute("SELECT * FROM tenants").fetchall()]
            finally:
                conn.close()

            for tenant in tenants:
                client = chain_manager.get_tenant_client(tenant)
                if not client:
                    continue

                # Pass get_db_fn so the sync thread creates its own connection
                results = await client.anchor_trees(get_db_fn, tenant["tenant_id"])
                for r in results:
                    print(
                        f"[TREE-ANCHOR] tenant={tenant['tenant_id']} "
                        f"tree[{r['tree_index']}] chain={r['chain']} "
                        f"tx={r['tx_hash'][:18]}...",
                        flush=True,
                    )
        except Exception as e:
            print(f"[TREE-ANCHOR] Background loop error: {e}", flush=True)

        await asyncio.sleep(ANCHOR_INTERVAL_SECONDS)
