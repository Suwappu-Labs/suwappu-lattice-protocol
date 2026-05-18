"""
SQLite-backed persistent store for CommitmentLog records.

Persists record data as JSON so that the in-memory MerkleLog can be
reconstructed on restart by replaying records in chain order.  Also
persists the log operator keypair (vk/sk) so the same signing identity
is used across restarts.

LTP-A-032 (Phase 2): the operator signing key `sk` is wrapped via
`ltp.keyvault.KeyVault` before persistence. Legacy rows written
before Phase 2 (raw `sk` BLOB column) are transparently migrated on
the next `load_operator_keypair()` call. Use
`python -m ltp.tools.migrate_keyvault <db>` for explicit bulk
migration.

Thread-safe via a per-instance lock (same pattern as SQLiteShardStore).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from typing import Optional

from ..keyvault import KeyVault

__all__ = ["CommitmentLogStore"]

_LOG = logging.getLogger(__name__)

# Domain separator passed as AAD when wrapping the operator sk.
# Anchors the wrapped blob to this storage site so a blob lifted
# from one table cannot be unwrapped at another KeyVault call site.
_AAD_OPERATOR_SK = b"ltp.storage.log_store:operator_sk"
_WRAP_VERSION = 1


class CommitmentLogStore:
    """SQLite backend for CommitmentLog persistence.

    Stores:
      1. Ordered record entries as JSON (all CommitmentRecord fields)
      2. Operator keypair (vk, wrapped sk) for consistent MerkleLog signing

    On startup, CommitmentLog loads all records in chain order and replays
    them into a fresh MerkleLog to reconstruct the Merkle tree + STHs.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        vault: Optional[KeyVault] = None,
    ) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._vault = vault  # lazily resolved on first wrap/unwrap
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")  # crash-safe for append-only log
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS log_records (
                chain_index  INTEGER PRIMARY KEY,
                entity_id    TEXT    NOT NULL UNIQUE,
                leaf_index   INTEGER NOT NULL,
                record_json  TEXT    NOT NULL
            )
        """)
        # log_operator schema:
        #   vk           — raw verification key (public; not sensitive)
        #   sk           — legacy plaintext sk column. Nullable. New writes
        #                  leave this NULL; legacy rows are migrated to
        #                  sk_wrapped on the next load.
        #   sk_wrapped   — KeyVault-wrapped sk (nonce || ct || tag).
        #                  Authoritative once wrap_version is non-NULL.
        #   wrap_version — INTEGER, 1 for the AEAD wrap defined above.
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS log_operator (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                vk            BLOB    NOT NULL,
                sk            BLOB,
                sk_wrapped    BLOB,
                wrap_version  INTEGER
            )
        """)
        # Migrate legacy schema (sk NOT NULL, no sk_wrapped column).
        self._migrate_legacy_schema_if_needed()
        self._conn.commit()

    # ------------------------------------------------------------------
    # Vault accessor (lazy)
    # ------------------------------------------------------------------

    def _get_vault(self) -> KeyVault:
        if self._vault is None:
            self._vault = KeyVault.from_environment()
        return self._vault

    def _migrate_legacy_schema_if_needed(self) -> None:
        """If an older log_operator table is present (no sk_wrapped column),
        add the new columns. SQLite ALTER TABLE only supports ADD COLUMN,
        which is exactly what we need."""
        cols = {
            row[1]
            for row in self._conn.execute(
                "PRAGMA table_info(log_operator)"
            ).fetchall()
        }
        if "sk_wrapped" not in cols:
            self._conn.execute("ALTER TABLE log_operator ADD COLUMN sk_wrapped BLOB")
        if "wrap_version" not in cols:
            self._conn.execute(
                "ALTER TABLE log_operator ADD COLUMN wrap_version INTEGER"
            )

    # ------------------------------------------------------------------
    # Operator keypair API
    # ------------------------------------------------------------------

    def store_operator_keypair(self, vk: bytes, sk: bytes) -> None:
        """Persist the log operator keypair (upsert).

        `vk` is stored raw (it's public). `sk` is wrapped via KeyVault
        before insert and stored in `sk_wrapped`. The plaintext `sk`
        column is left NULL on new writes.
        """
        if not isinstance(sk, (bytes, bytearray)):
            raise TypeError("sk must be bytes")
        sk_wrapped = self._get_vault().wrap(bytes(sk), aad=_AAD_OPERATOR_SK)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO log_operator "
                "(id, vk, sk, sk_wrapped, wrap_version) "
                "VALUES (1, ?, NULL, ?, ?)",
                (vk, sk_wrapped, _WRAP_VERSION),
            )
            self._conn.commit()

    def load_operator_keypair(self) -> Optional[tuple[bytes, bytes]]:
        """Load persisted operator keypair. Returns (vk, sk) or None.

        Read order:
          1. sk_wrapped (if wrap_version is non-NULL) — unwrap and return.
          2. Legacy plain sk — transparently migrate: wrap, overwrite,
             return. A WARNING is logged. Run
             `python -m ltp.tools.migrate_keyvault <db>` to perform
             bulk migration explicitly.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT vk, sk, sk_wrapped, wrap_version "
                "FROM log_operator WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        vk, legacy_sk, sk_wrapped, wrap_version = row
        if sk_wrapped is not None and wrap_version is not None:
            sk = self._get_vault().unwrap(sk_wrapped, aad=_AAD_OPERATOR_SK)
            return (vk, sk)
        if legacy_sk is None:
            return None
        _LOG.warning(
            "CommitmentLogStore: migrating legacy plaintext operator sk "
            "to wrapped form (LTP-A-032). Run "
            "`python -m ltp.tools.migrate_keyvault %s` for explicit "
            "bulk migration.",
            self._db_path,
        )
        self._migrate_row_inplace(legacy_sk)
        return (vk, legacy_sk)

    def _migrate_row_inplace(self, legacy_sk: bytes) -> None:
        """Wrap a legacy plaintext sk and overwrite the row.

        Called both transparently from load_operator_keypair and
        explicitly from the migrate_keyvault CLI.
        """
        sk_wrapped = self._get_vault().wrap(bytes(legacy_sk), aad=_AAD_OPERATOR_SK)
        with self._lock:
            self._conn.execute(
                "UPDATE log_operator "
                "SET sk = NULL, sk_wrapped = ?, wrap_version = ? "
                "WHERE id = 1",
                (sk_wrapped, _WRAP_VERSION),
            )
            self._conn.commit()

    def migrate_operator_keypair(self) -> bool:
        """Idempotent migration entry-point for the CLI.

        Returns True if a legacy row was migrated, False if there was
        nothing to migrate (no operator row, or already wrapped).
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT sk, sk_wrapped FROM log_operator WHERE id = 1"
            ).fetchone()
        if row is None:
            return False
        legacy_sk, sk_wrapped = row
        if sk_wrapped is not None:
            return False
        if legacy_sk is None:
            return False
        self._migrate_row_inplace(legacy_sk)
        return True

    # ------------------------------------------------------------------
    # Records API (unchanged)
    # ------------------------------------------------------------------

    def append_record(
        self,
        chain_index: int,
        entity_id: str,
        leaf_index: int,
        record_dict: dict,
    ) -> None:
        """Persist a new log record as JSON."""
        record_json = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO log_records (chain_index, entity_id, leaf_index, record_json) "
                "VALUES (?, ?, ?, ?)",
                (chain_index, entity_id, leaf_index, record_json),
            )
            self._conn.commit()

    def load_all_records(self) -> list[tuple[str, int, dict]]:
        """Load all records ordered by chain_index.

        Returns list of (entity_id, leaf_index, record_dict).
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT entity_id, leaf_index, record_json "
                "FROM log_records ORDER BY chain_index"
            ).fetchall()
        return [(r[0], r[1], json.loads(r[2])) for r in rows]

    @property
    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM log_records").fetchone()
        return row[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __repr__(self) -> str:
        return f"CommitmentLogStore(db={self._db_path!r}, count={self.count})"
