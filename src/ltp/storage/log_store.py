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

# Domain separator passed as AAD when wrapping the operator sk / dk.
# Anchors the wrapped blob to this storage site so a blob lifted
# from one table cannot be unwrapped at another KeyVault call site.
_AAD_OPERATOR_SK = b"ltp.storage.log_store:operator_sk"
_AAD_OPERATOR_DK = b"ltp.storage.log_store:operator_dk"
# Wrap version history:
#   1 — sk wrapped only (vk + sk_wrapped). Phase 2.
#   2 — sk + dk wrapped; ek persisted raw (it's public). Phase 4c.
_WRAP_VERSION_PHASE2 = 1
_WRAP_VERSION_PHASE4C = 2
_WRAP_VERSION = _WRAP_VERSION_PHASE4C


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
        # log_operator schema (Phase 4c):
        #   vk           — raw verification key (public; not sensitive)
        #   sk           — legacy plaintext sk column. Nullable for v2 rows.
        #   sk_wrapped   — KeyVault-wrapped sk (nonce || ct || tag).
        #   ek           — raw encapsulation key (public; v2 only).
        #   dk_wrapped   — KeyVault-wrapped dk (v2 only).
        #   wrap_version — 1 (Phase 2: sk only) or 2 (Phase 4c: all four).
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS log_operator (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                vk            BLOB    NOT NULL,
                sk            BLOB,
                sk_wrapped    BLOB,
                ek            BLOB,
                dk_wrapped    BLOB,
                wrap_version  INTEGER
            )
        """)
        # Migrate legacy schemas (pre-Phase-2 sk NOT NULL; Phase-2 without
        # ek/dk_wrapped columns).
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
        """Bring legacy log_operator schemas to the Phase 2 shape.

        Two legacy cases handled (Codex P1):

          1. Pre-Phase-2 schema has `sk BLOB NOT NULL` and no
             `sk_wrapped` / `wrap_version` columns. New writes to this
             schema would set `sk = NULL` and trigger
             `sqlite3.IntegrityError`. Solution: rebuild the table
             without the NOT NULL constraint, preserving any existing
             row, and add the new columns.

          2. A row created in case 1 may already have been augmented
             with the new columns (e.g. by a previous instance that
             skipped the rebuild). We still need to relax `sk NOT NULL`
             so subsequent migrations can set `sk = NULL`. Treat this
             the same as case 1 — rebuild if the NOT NULL is present.
        """
        info = self._conn.execute("PRAGMA table_info(log_operator)").fetchall()
        # PRAGMA table_info returns rows of (cid, name, type, notnull, dflt, pk)
        cols = {row[1]: row for row in info}
        sk_is_not_null = "sk" in cols and bool(cols["sk"][3])
        needs_new_cols = "sk_wrapped" not in cols or "wrap_version" not in cols

        if sk_is_not_null:
            # Rebuild the table with a relaxed schema. SQLite does not
            # support ALTER COLUMN to drop NOT NULL, so we go through a
            # rename-create-copy-drop dance inside a transaction.
            self._conn.execute(
                "ALTER TABLE log_operator RENAME TO log_operator_legacy"
            )
            self._conn.execute("""
                CREATE TABLE log_operator (
                    id            INTEGER PRIMARY KEY CHECK (id = 1),
                    vk            BLOB    NOT NULL,
                    sk            BLOB,
                    sk_wrapped    BLOB,
                    ek            BLOB,
                    dk_wrapped    BLOB,
                    wrap_version  INTEGER
                )
            """)
            # Carry forward the single legacy row, if any.
            self._conn.execute(
                "INSERT INTO log_operator (id, vk, sk) "
                "SELECT id, vk, sk FROM log_operator_legacy"
            )
            self._conn.execute("DROP TABLE log_operator_legacy")
            return

        # Schema already has nullable `sk`; just add columns if missing.
        if "sk_wrapped" not in cols:
            self._conn.execute(
                "ALTER TABLE log_operator ADD COLUMN sk_wrapped BLOB"
            )
        if "wrap_version" not in cols:
            self._conn.execute(
                "ALTER TABLE log_operator ADD COLUMN wrap_version INTEGER"
            )
        # Phase 4c additions (Q4 — persist all four).
        if "ek" not in cols:
            self._conn.execute(
                "ALTER TABLE log_operator ADD COLUMN ek BLOB"
            )
        if "dk_wrapped" not in cols:
            self._conn.execute(
                "ALTER TABLE log_operator ADD COLUMN dk_wrapped BLOB"
            )

    # ------------------------------------------------------------------
    # Operator keypair API
    # ------------------------------------------------------------------

    def store_operator_keypair(
        self,
        vk: bytes,
        sk: bytes,
        ek: Optional[bytes] = None,
        dk: Optional[bytes] = None,
    ) -> None:
        """Persist the log operator keypair (upsert).

        `vk` and `ek` are stored raw (public material). `sk` and `dk`
        (when provided) are KeyVault-wrapped before insert. Plaintext
        columns are left NULL on new writes.

        Backward compat: callers that pass only `(vk, sk)` produce a
        Phase 2-shaped row (no ek/dk persisted, wrap_version=1).
        Callers that pass all four produce a Phase 4c row
        (wrap_version=2). The CommitmentLog operator-reload path uses
        the 4-arg form so the full identity survives restarts (Q4).
        """
        if not isinstance(sk, (bytes, bytearray)):
            raise TypeError("sk must be bytes")
        sk_wrapped = self._get_vault().wrap(bytes(sk), aad=_AAD_OPERATOR_SK)
        full = ek is not None and dk is not None
        if full:
            if not isinstance(dk, (bytes, bytearray)):
                raise TypeError("dk must be bytes")
            dk_wrapped = self._get_vault().wrap(bytes(dk), aad=_AAD_OPERATOR_DK)
            ek_bytes = bytes(ek)
            wrap_version = _WRAP_VERSION_PHASE4C
        else:
            dk_wrapped = None
            ek_bytes = None
            wrap_version = _WRAP_VERSION_PHASE2
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO log_operator "
                "(id, vk, sk, sk_wrapped, ek, dk_wrapped, wrap_version) "
                "VALUES (1, ?, NULL, ?, ?, ?, ?)",
                (vk, sk_wrapped, ek_bytes, dk_wrapped, wrap_version),
            )
            self._conn.commit()

    def load_operator_keypair(self) -> Optional[tuple[bytes, bytes]]:
        """Legacy 2-tuple load. Returns (vk, sk) or None.

        Read order:
          1. sk_wrapped (if wrap_version is non-NULL) — unwrap and return.
          2. Legacy plain sk — transparently migrate, then return.

        Existing callers that only need vk/sk keep this signature; the
        Phase 4c CommitmentLog reload path uses
        :meth:`load_operator_keypair_full` for the (vk, sk, ek, dk)
        tuple needed to rebuild the full HSM-backed identity.
        """
        full = self.load_operator_keypair_full()
        if full is None:
            return None
        vk, sk, _ek, _dk = full
        return (vk, sk)

    def load_operator_keypair_full(
        self,
    ) -> Optional[tuple[bytes, bytes, Optional[bytes], Optional[bytes]]]:
        """Phase 4c 4-tuple load. Returns (vk, sk, ek_or_None, dk_or_None).

        `ek` / `dk` are None for legacy v1 rows that pre-date Phase 4c.
        The caller (CommitmentLog) generates fresh values in that case
        and persists them via :meth:`store_operator_keypair`.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT vk, sk, sk_wrapped, ek, dk_wrapped, wrap_version "
                "FROM log_operator WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        vk, legacy_sk, sk_wrapped, ek, dk_wrapped, wrap_version = row
        if sk_wrapped is not None and wrap_version is not None:
            sk = self._get_vault().unwrap(sk_wrapped, aad=_AAD_OPERATOR_SK)
            dk = None
            if dk_wrapped is not None:
                dk = self._get_vault().unwrap(dk_wrapped, aad=_AAD_OPERATOR_DK)
            return (vk, sk, ek, dk)
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
        return (vk, legacy_sk, None, None)

    def _migrate_row_inplace(self, legacy_sk: bytes) -> None:
        """Wrap a legacy plaintext sk and overwrite the row.

        Called both transparently from load_operator_keypair and
        explicitly from the migrate_keyvault CLI. Reads + wraps + writes
        under a single critical section so a concurrent
        store_operator_keypair cannot interleave a new vk between read
        and write (Codex P2).
        """
        sk_wrapped = self._get_vault().wrap(bytes(legacy_sk), aad=_AAD_OPERATOR_SK)
        with self._lock:
            # Re-check the row under the lock: if a concurrent writer
            # already wrapped (or replaced) the row, our wrapped bytes
            # are stale — bail out and let the newer row win.
            row = self._conn.execute(
                "SELECT sk, sk_wrapped FROM log_operator WHERE id = 1"
            ).fetchone()
            if row is None:
                return  # row deleted underneath us
            cur_sk, cur_wrapped = row
            if cur_wrapped is not None:
                return  # already migrated by another writer
            if cur_sk is None or bytes(cur_sk) != bytes(legacy_sk):
                # Underlying sk changed between our read and write;
                # do not overwrite with stale wrapped bytes.
                _LOG.warning(
                    "CommitmentLogStore: legacy sk changed during "
                    "migration; aborting in-place wrap. Re-run "
                    "load_operator_keypair to migrate the new value."
                )
                return
            self._conn.execute(
                "UPDATE log_operator "
                "SET sk = NULL, sk_wrapped = ?, wrap_version = ? "
                "WHERE id = 1",
                (sk_wrapped, _WRAP_VERSION_PHASE2),
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
