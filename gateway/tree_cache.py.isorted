"""
Vargate TreeCache — Merkle tree cache with lazy rebuild.
Stage 7C Fix 2: Avoids rebuilding the full Merkle tree on every
GET /anchor/proof or GET /anchor/verify request.

The cache is invalidated when new audit records are written.
Reads are O(1) when the cache is warm. Rebuilds only when
max(audit_log.id) has increased since the last build.
"""

import asyncio
import sqlite3
from typing import Optional

from merkle import MerkleTree


class TreeCache:
    """
    Module-level singleton that caches the MerkleTree built from audit_log.
    Thread-safe via asyncio.Lock — safe to call from multiple endpoints.
    """

    def __init__(self):
        self._tree: Optional[MerkleTree] = None
        self._built_at_record_id: int = 0
        self._lock = asyncio.Lock()

    async def get(self, conn: sqlite3.Connection) -> MerkleTree:
        """
        Return the cached MerkleTree, rebuilding only if new records exist.
        """
        async with self._lock:
            max_id = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0] or 0
            if self._tree is None or max_id > self._built_at_record_id:
                self._tree = MerkleTree.from_db(conn)
                self._built_at_record_id = max_id
            return self._tree

    def invalidate(self):
        """
        Mark the cache as stale. Called from write_audit_record() after
        every new record is written. The next get() call will rebuild.
        """
        self._tree = None
        self._built_at_record_id = 0

    @property
    def is_warm(self) -> bool:
        """True if the cache holds a valid tree."""
        return self._tree is not None

    @property
    def built_at_record_id(self) -> int:
        """The max audit_log.id when the cache was last built."""
        return self._built_at_record_id


# Module-level singleton — import and use this directly.
tree_cache = TreeCache()
