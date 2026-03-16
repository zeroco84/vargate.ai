"""
Vargate Blockchain Client — Sepolia Merkle Anchor
Replaces the local Hardhat blockchain client with a Sepolia testnet client
that submits Merkle tree roots to the MerkleAuditAnchor smart contract.

Satisfies AGCS AG-2.2 (immutable on-chain anchoring) and AG-2.3
(O(log n) inclusion proofs via Merkle tree).

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

RPC_URL = os.getenv("SEPOLIA_RPC_URL", os.getenv("RPC_URL", ""))
DEPLOYER_PRIVATE_KEY = os.getenv("DEPLOYER_PRIVATE_KEY", "")
CONTRACT_INFO_FILE = os.getenv(
    "MERKLE_CONTRACT_FILE", "/shared/MerkleAuditAnchor.json"
)
ANCHOR_INTERVAL_SECONDS = int(os.getenv("ANCHOR_INTERVAL_SECONDS", "3600"))
ANCHOR_MODE = os.getenv("ANCHOR_MODE", "full")  # Fix 7: 'full' or 'incremental'
SYSTEM_ID = os.getenv("SYSTEM_ID", "vargate-v1")
SEPOLIA_EXPLORER = "https://sepolia.etherscan.io"


# ── Fix 8 (AG-3.4): Signer abstraction ──────────────────────────────────────

class SignerBackend:
    """
    Protocol for transaction signing backends.
    Swap implementations to move from env-var keys to HSM.
    """

    def sign_transaction(self, w3, transaction: dict):
        """Sign a transaction dict. Returns a SignedTransaction."""
        raise NotImplementedError

    def get_address(self) -> str:
        """Return the signer's Ethereum address."""
        raise NotImplementedError


class EnvVarSigner(SignerBackend):
    """
    Default signer: reads private key from DEPLOYER_PRIVATE_KEY env var.
    Suitable for development and testnet usage.

    WARNING: Not suitable for production with real assets.
    Private key is held in memory as plaintext.
    """

    def __init__(self, private_key: str = ""):
        self._key = private_key or DEPLOYER_PRIVATE_KEY
        if self._key and not self._key.startswith("0x"):
            self._key = f"0x{self._key}"
        self._account = None

    def init_account(self, w3):
        """Lazily initialize the account from the private key."""
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
    """
    Stub: PKCS#11 HSM-backed signer for production use.

    TODO: Implement using python-pkcs11 or similar library.
    Requires FIPS 140-2 Level 3 HSM for AGCS AG-3.4 Tier 3 certification.
    SoftHSM2 (used in Stage 6) does NOT satisfy AG-3.4 for Tier 3.

    See DEPLOY.md "Production Key Management" section for implementation guide.
    """

    def __init__(self, hsm_slot: int = 0, hsm_pin: str = "", key_label: str = ""):
        self.hsm_slot = hsm_slot
        self.hsm_pin = hsm_pin
        self.key_label = key_label

    def sign_transaction(self, w3, transaction: dict):
        raise NotImplementedError(
            "HsmSigner requires PKCS#11 integration. See DEPLOY.md HSM section."
        )

    def get_address(self) -> str:
        raise NotImplementedError(
            "HsmSigner requires PKCS#11 integration. See DEPLOY.md HSM section."
        )


class BlockchainClient:
    """
    Connects to Sepolia via web3.py. Submits Merkle root anchors to
    MerkleAuditAnchor and supports on-chain verification.

    Fix 8: Accepts an optional SignerBackend for key management.
    Defaults to EnvVarSigner (reads DEPLOYER_PRIVATE_KEY from env).
    """

    def __init__(self, signer: Optional[SignerBackend] = None):
        self.w3 = None
        self.contract = None
        self.signer = signer or EnvVarSigner()
        self.contract_address: Optional[str] = None
        self._connected = False

    # ── Initialisation ───────────────────────────────────────────────────

    def connect(self) -> bool:
        """Attempt to connect to Sepolia and load the contract."""
        try:
            from web3 import Web3

            if not RPC_URL:
                print("[ANCHOR] No RPC_URL / SEPOLIA_RPC_URL configured.", flush=True)
                return False

            # Support both HTTP and WSS providers
            if RPC_URL.startswith("wss://") or RPC_URL.startswith("ws://"):
                provider = Web3.WebSocketProvider(RPC_URL)
            else:
                provider = Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 30})

            self.w3 = Web3(provider)

            if not self.w3.is_connected():
                print(f"[ANCHOR] Cannot connect to RPC: {RPC_URL}", flush=True)
                return False

            # Load contract info
            if not os.path.exists(CONTRACT_INFO_FILE):
                print(
                    f"[ANCHOR] Contract info not found: {CONTRACT_INFO_FILE}",
                    flush=True,
                )
                return False

            with open(CONTRACT_INFO_FILE) as f:
                info = json.load(f)

            contract_address = info.get("address", "")
            abi = info.get("abi", [])

            if not contract_address or not abi:
                print("[ANCHOR] Invalid contract info file.", flush=True)
                return False

            self.contract_address = Web3.to_checksum_address(contract_address)
            self.contract = self.w3.eth.contract(
                address=self.contract_address, abi=abi
            )

            # Fix 8: Initialize signer with web3 instance
            try:
                self.signer.init_account(self.w3)
            except Exception:
                pass  # HsmSigner won't have init_account — that's ok

            signer_addr = self.signer.get_address()
            if not signer_addr:
                print("[ANCHOR] No signing key configured.", flush=True)
                return False

            chain_id = self.w3.eth.chain_id
            print(
                f"[ANCHOR] Connected to chain {chain_id}. "
                f"Contract: {self.contract_address}  "
                f"Deployer: {signer_addr}",
                flush=True,
            )
            self._connected = True
            return True

        except Exception as e:
            print(f"[ANCHOR] Connection failed: {e}", flush=True)
            self._connected = False
            return False

    @property
    def connected(self) -> bool:
        if not self._connected or not self.w3:
            return False
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    # ── Anchor submission ────────────────────────────────────────────────

    def _anchor_now_sync(self, conn: sqlite3.Connection) -> dict:
        """
        Synchronous core: build Merkle tree, submit root to Sepolia contract.
        Contains blocking web3 RPC calls (gas estimation, send_raw_transaction,
        wait_for_transaction_receipt). Must be run via asyncio.to_thread().

        Fix 7: Supports ANCHOR_MODE='incremental' — only anchors records newer
        than the last successful anchor's to_record.
        """
        if not self.connected:
            raise RuntimeError("Blockchain not connected")

        # Fix 7: Determine record range based on anchor mode
        if ANCHOR_MODE == "incremental":
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
            # Full mode: all records
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

        # 2. Build Merkle tree
        tree = MerkleTree(leaves)
        merkle_root_hex = tree.root

        # Convert to bytes32
        root_bytes = bytes.fromhex(merkle_root_hex)
        if len(root_bytes) < 32:
            root_bytes = root_bytes.ljust(32, b"\x00")
        elif len(root_bytes) > 32:
            root_bytes = root_bytes[:32]

        # Fix 4C (AG-2.2): Look up previous Merkle root for hash-chaining
        prev_row = conn.execute(
            "SELECT merkle_root FROM merkle_anchor_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if prev_row:
            prev_merkle_root_hex = prev_row["merkle_root"] if isinstance(prev_row, sqlite3.Row) else prev_row[0]
        else:
            prev_merkle_root_hex = GENESIS_ROOT

        # Compute root chain hash: SHA-256(prev_root_bytes + current_root_bytes)
        prev_root_bytes_raw = bytes.fromhex(prev_merkle_root_hex)
        root_chain_hash = hashlib.sha256(prev_root_bytes_raw + bytes.fromhex(merkle_root_hex)).hexdigest()

        # Convert prev root to bytes32 for contract
        prev_root_bytes32 = prev_root_bytes_raw
        if len(prev_root_bytes32) < 32:
            prev_root_bytes32 = prev_root_bytes32.ljust(32, b"\x00")
        elif len(prev_root_bytes32) > 32:
            prev_root_bytes32 = prev_root_bytes32[:32]

        # 3. Build and sign transaction
        nonce = self.w3.eth.get_transaction_count(self.signer.get_address())
        chain_id = self.w3.eth.chain_id

        # Build the contract call (Fix 4B: includes prevMerkleRoot)
        fn = self.contract.functions.submitAnchor(
            root_bytes,
            prev_root_bytes32,
            record_count,
            from_record,
            to_record,
            SYSTEM_ID,
        )

        # Estimate gas
        try:
            gas_estimate = fn.estimate_gas({"from": self.signer.get_address()})
            gas_limit = int(gas_estimate * 1.3)  # 30% buffer
        except Exception as e:
            print(f"[ANCHOR] Gas estimation failed, using fallback: {e}", flush=True)
            gas_limit = 200_000

        # Get current gas price (EIP-1559 or legacy)
        try:
            latest_block = self.w3.eth.get_block("latest")
            base_fee = latest_block.get("baseFeePerGas", 0)
            if base_fee:
                # EIP-1559
                max_priority = self.w3.eth.max_priority_fee
                max_fee = base_fee * 2 + max_priority
                tx = fn.build_transaction(
                    {
                        "from": self.signer.get_address(),
                        "nonce": nonce,
                        "gas": gas_limit,
                        "maxFeePerGas": max_fee,
                        "maxPriorityFeePerGas": max_priority,
                        "chainId": chain_id,
                    }
                )
            else:
                gas_price = self.w3.eth.gas_price
                tx = fn.build_transaction(
                    {
                        "from": self.signer.get_address(),
                        "nonce": nonce,
                        "gas": gas_limit,
                        "gasPrice": gas_price,
                        "chainId": chain_id,
                    }
                )
        except Exception:
            # Fallback to legacy gas pricing
            gas_price = self.w3.eth.gas_price
            tx = fn.build_transaction(
                {
                    "from": self.signer.get_address(),
                    "nonce": nonce,
                    "gas": gas_limit,
                    "gasPrice": int(gas_price * 1.2),
                    "chainId": chain_id,
                }
            )

        # 4. Sign and send
        # Fix 8: Use signer abstraction for transaction signing
        signed = self.signer.sign_transaction(self.w3, tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)

        # 5. Wait for receipt (up to 120s) — THIS IS THE MAIN BLOCKER
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt.status != 1:
            raise RuntimeError(
                f"Transaction reverted. tx_hash={tx_hash.hex()}"
            )

        # 6. Extract anchor index from event
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

        # 7. Write to local anchor_log (with legacy chain_tip_hash compatibility)
        anchored_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO anchor_log
               (anchor_index, chain_tip_hash, merkle_root, record_count,
                from_record, to_record, tx_hash, block_number, anchored_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                anchor_index,
                merkle_root_hex,  # chain_tip_hash = merkle_root for compat
                merkle_root_hex,
                record_count,
                from_record,
                to_record,
                tx_hash_hex,
                receipt.blockNumber,
                anchored_at,
            ),
        )

        # Fix 4C: Write to merkle_anchor_log with prev_merkle_root and root_chain_hash
        conn.execute(
            """INSERT INTO merkle_anchor_log
               (anchor_index, merkle_root, record_count, from_record, to_record,
                tx_hash, block_number, anchored_at, prev_merkle_root, root_chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                anchor_index,
                merkle_root_hex,
                record_count,
                from_record,
                to_record,
                tx_hash_hex,
                receipt.blockNumber,
                anchored_at,
                prev_merkle_root_hex,
                root_chain_hash,
            ),
        )
        conn.commit()

        print(
            f"[ANCHOR] Merkle root={merkle_root_hex[:16]}... "
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
        }

    async def anchor_now(self, conn: sqlite3.Connection) -> dict:
        """Async wrapper — runs sync web3 calls in a thread to avoid blocking the event loop."""
        return await asyncio.to_thread(self._anchor_now_sync, conn)

    # ── Verification ─────────────────────────────────────────────────────

    def _verify_latest_sync(self, conn: sqlite3.Connection) -> dict:
        """
        Synchronous core: compare the latest on-chain anchor against a
        freshly-computed Merkle root from current SQLite records.
        Contains blocking RPC call (getLatestAnchor).

        Fix 7: In incremental mode, compare against the tree built from only
        the anchor's record range. In full mode, compare against all records.
        """
        if not self.connected:
            return {"error": "blockchain unavailable"}

        try:
            # Get latest anchor from contract (blocking RPC)
            anchor_data, anchor_index = self.contract.functions.getLatestAnchor().call()
            on_chain_root = anchor_data[0].hex()  # merkleRoot (bytes32)
            on_chain_count = anchor_data[1]  # recordCount
            on_chain_from = anchor_data[2]  # fromRecord
            on_chain_to = anchor_data[3]  # toRecord
        except Exception as e:
            return {
                "error": f"No anchors on-chain or call failed: {e}",
                "match": False,
            }

        # Fix 7: Build tree from the correct record range
        if ANCHOR_MODE == "incremental":
            # Build tree from only the anchor's record range
            rows = conn.execute(
                "SELECT record_hash FROM audit_log WHERE id >= ? AND id <= ? ORDER BY id ASC",
                (on_chain_from, on_chain_to),
            ).fetchall()
            leaves = [r["record_hash"] if isinstance(r, sqlite3.Row) else r[0] for r in rows]
            tree = MerkleTree(leaves)
        else:
            # Full mode: build from all records
            tree = MerkleTree.from_db(conn)

        computed_root = tree.root

        # Normalise: on-chain bytes32 may have leading zeros stripped
        on_chain_clean = on_chain_root.lstrip("0") or "0"
        computed_clean = computed_root.lstrip("0") or "0"
        match = on_chain_clean == computed_clean

        # Get last anchor from local log
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
            "last_anchor_tx": last_anchor["tx_hash"] if last_anchor else None,
            "last_anchor_time": last_anchor["anchored_at"] if last_anchor else None,
        }

    async def verify_latest(self, conn: sqlite3.Connection) -> dict:
        """Async wrapper — runs sync RPC + tree rebuild in a thread."""
        return await asyncio.to_thread(self._verify_latest_sync, conn)

    # ── View helpers ─────────────────────────────────────────────────────

    def get_anchor_count(self) -> int:
        """Sync — single fast RPC call, acceptable from sync context."""
        if not self.connected:
            return 0
        try:
            return self.contract.functions.getAnchorCount().call()
        except Exception:
            return 0

    def _get_latest_anchor_sync(self) -> Optional[dict]:
        """Synchronous core: fetch latest anchor from contract (blocking RPC)."""
        if not self.connected:
            return None
        try:
            anchor_data, index = self.contract.functions.getLatestAnchor().call()
            return {
                "index": index,
                "merkle_root": anchor_data[0].hex(),
                "record_count": anchor_data[1],
                "from_record": anchor_data[2],
                "to_record": anchor_data[3],
                "block_number": anchor_data[4],
                "timestamp": anchor_data[5],
                "system_id": anchor_data[6],
            }
        except Exception:
            return None

    async def get_latest_anchor(self) -> Optional[dict]:
        """Async wrapper — runs sync RPC in a thread."""
        return await asyncio.to_thread(self._get_latest_anchor_sync)

    def get_deployer_address(self) -> Optional[str]:
        addr = self.signer.get_address()
        return addr if addr else None


# ── Background anchor loop ───────────────────────────────────────────────────

async def run_anchor_loop(client: BlockchainClient, get_db_fn, post_anchor_fn=None):
    """
    Background asyncio task that anchors every ANCHOR_INTERVAL_SECONDS.
    Uses get_db_fn() to get a fresh SQLite connection each cycle.
    post_anchor_fn(conn, result) is called after each successful anchor
    for Fix 3 (AG-3.2) audit record writing.
    """
    # Wait a bit on startup for records to accumulate
    await asyncio.sleep(15)

    while True:
        try:
            if client.connected:
                conn = get_db_fn()
                try:
                    count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                    if count > 0:
                        result = await client.anchor_now(conn)
                        # Fix 3 (AG-3.2): Write anchor into the audit chain
                        if post_anchor_fn and result:
                            post_anchor_fn(conn, result)
                    else:
                        print("[ANCHOR] No records to anchor yet.", flush=True)
                finally:
                    conn.close()
        except Exception as e:
            print(f"[ANCHOR] Background loop error: {e}", flush=True)

        await asyncio.sleep(ANCHOR_INTERVAL_SECONDS)

