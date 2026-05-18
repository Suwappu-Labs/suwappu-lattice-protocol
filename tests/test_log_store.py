"""Tests for CommitmentLogStore operator-sk wrapping (LTP-A-032 Phase 2).

Verifies:
- store_operator_keypair writes wrapped sk; plain sk column is NULL.
- load_operator_keypair round-trips the original sk.
- Tampering the wrapped blob raises on load.
- Wrong KEK fails to unwrap.
- Legacy plaintext rows are transparently migrated on load (with WARNING).
- migrate_operator_keypair() is idempotent.
- migrate_keyvault CLI migrates a legacy DB.
- Round-trip with vk + sk preserves equality.
- Existing record-append behaviour is unaffected.
"""

from __future__ import annotations

import base64
import logging
import os
import sqlite3
import tempfile

import pytest

from ltp.keyvault import KeyVault, KeyVaultError
from ltp.storage.log_store import CommitmentLogStore
from ltp.tools.migrate_keyvault import migrate_one


@pytest.fixture(autouse=True)
def _kek_env(monkeypatch):
    """Each test runs with a deterministic env-var KEK."""
    monkeypatch.setenv(
        "LTP_KEY_ENCRYPTION_KEY",
        base64.b64encode(b"\x42" * 32).decode("ascii"),
    )
    monkeypatch.delenv("LTP_ENV", raising=False)


@pytest.fixture
def tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# wrap on store / unwrap on load
# ---------------------------------------------------------------------------


def test_store_writes_wrapped_sk_not_plaintext(tmp_db):
    sk = os.urandom(4032)
    vk = b"\x11" * 1952
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(vk, sk)
    store.close()

    # Inspect raw SQLite to confirm the plain sk column is NULL and
    # sk_wrapped does not equal plaintext sk.
    conn = sqlite3.connect(tmp_db)
    row = conn.execute(
        "SELECT vk, sk, sk_wrapped, wrap_version FROM log_operator WHERE id=1"
    ).fetchone()
    conn.close()
    assert row[0] == vk
    assert row[1] is None  # plain sk column NULL on new writes
    assert row[2] is not None
    assert row[2] != sk  # wrapped, not plaintext
    assert len(row[2]) == len(sk) + 40  # nonce(24) + tag(16) overhead
    assert row[3] == 1  # wrap_version


def test_load_roundtrips_sk(tmp_db):
    sk = os.urandom(4032)
    vk = b"\x22" * 1952
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(vk, sk)
    got = store.load_operator_keypair()
    store.close()
    assert got == (vk, sk)


def test_load_returns_none_when_empty(tmp_db):
    store = CommitmentLogStore(tmp_db)
    assert store.load_operator_keypair() is None
    store.close()


def test_tampered_wrapped_blob_fails_on_load(tmp_db):
    sk = os.urandom(4032)
    vk = b"\x33" * 1952
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(vk, sk)
    store.close()

    # Flip one bit in the wrapped blob.
    conn = sqlite3.connect(tmp_db)
    wrapped = bytearray(
        conn.execute("SELECT sk_wrapped FROM log_operator WHERE id=1").fetchone()[0]
    )
    wrapped[30] ^= 0xFF
    conn.execute("UPDATE log_operator SET sk_wrapped = ? WHERE id=1", (bytes(wrapped),))
    conn.commit()
    conn.close()

    store2 = CommitmentLogStore(tmp_db)
    with pytest.raises(KeyVaultError, match="authentication failed"):
        store2.load_operator_keypair()
    store2.close()


def test_wrong_kek_fails_to_load(tmp_db, monkeypatch):
    sk = os.urandom(4032)
    vk = b"\x44" * 1952
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(vk, sk)
    store.close()

    # Rotate to a different KEK; load should fail.
    monkeypatch.setenv(
        "LTP_KEY_ENCRYPTION_KEY",
        base64.b64encode(b"\x99" * 32).decode("ascii"),
    )
    store2 = CommitmentLogStore(tmp_db)
    with pytest.raises(KeyVaultError, match="authentication failed"):
        store2.load_operator_keypair()
    store2.close()


# ---------------------------------------------------------------------------
# legacy-row transparent migration
# ---------------------------------------------------------------------------


def _write_legacy_row(db_path: str, vk: bytes, sk: bytes) -> None:
    """Simulate a pre-Phase-2 row: plaintext sk in the legacy column,
    using the TRUE pre-Phase-2 schema with `sk BLOB NOT NULL` (Codex P2 —
    earlier fixture used a nullable sk, which masked the constraint bug)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_operator ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), "
        "vk BLOB NOT NULL, "
        "sk BLOB NOT NULL"
        ")"
    )
    conn.execute(
        "INSERT OR REPLACE INTO log_operator (id, vk, sk) VALUES (1, ?, ?)",
        (vk, sk),
    )
    conn.commit()
    conn.close()


def test_legacy_row_transparently_migrates_on_load(tmp_db, caplog):
    sk = os.urandom(4032)
    vk = b"\x55" * 1952
    _write_legacy_row(tmp_db, vk, sk)

    with caplog.at_level(logging.WARNING):
        store = CommitmentLogStore(tmp_db)
        got = store.load_operator_keypair()
    assert got == (vk, sk)
    assert any("migrating legacy" in rec.message for rec in caplog.records)

    # After migration, the plain sk column must be NULL and the wrapped
    # column populated.
    raw = store._conn.execute(
        "SELECT sk, sk_wrapped, wrap_version FROM log_operator WHERE id=1"
    ).fetchone()
    store.close()
    assert raw[0] is None
    assert raw[1] is not None and raw[1] != sk
    assert raw[2] == 1


def test_migrate_operator_keypair_is_idempotent(tmp_db):
    sk = os.urandom(4032)
    vk = b"\x66" * 1952
    _write_legacy_row(tmp_db, vk, sk)

    store = CommitmentLogStore(tmp_db)
    assert store.migrate_operator_keypair() is True
    # Second call: nothing to migrate.
    assert store.migrate_operator_keypair() is False
    # And round-trip still works.
    assert store.load_operator_keypair() == (vk, sk)
    store.close()


def test_migrate_operator_keypair_no_row(tmp_db):
    store = CommitmentLogStore(tmp_db)
    assert store.migrate_operator_keypair() is False
    store.close()


def test_cli_migrate_one_succeeds_on_legacy(tmp_db):
    sk = os.urandom(4032)
    vk = b"\x77" * 1952
    _write_legacy_row(tmp_db, vk, sk)

    assert migrate_one(tmp_db) is True
    # After CLI migration, opening a fresh store loads correctly.
    store = CommitmentLogStore(tmp_db)
    assert store.load_operator_keypair() == (vk, sk)
    store.close()


def test_cli_migrate_one_noop_on_fresh_store(tmp_db):
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(b"vk", os.urandom(4032))
    store.close()
    assert migrate_one(tmp_db) is False


# ---------------------------------------------------------------------------
# records API unchanged
# ---------------------------------------------------------------------------


def test_records_api_unaffected(tmp_db):
    store = CommitmentLogStore(tmp_db)
    store.append_record(0, "entity-1", 0, {"foo": "bar"})
    store.append_record(1, "entity-2", 1, {"baz": 42})
    assert store.count == 2
    records = store.load_all_records()
    assert records[0] == ("entity-1", 0, {"foo": "bar"})
    assert records[1] == ("entity-2", 1, {"baz": 42})
    store.close()


def test_legacy_schema_with_sk_not_null_rebuilds(tmp_db):
    """Regression for Codex P1: pre-Phase-2 schema had
    `sk BLOB NOT NULL`. _migrate_legacy_schema_if_needed must rebuild
    the table so subsequent writes can set sk = NULL without
    sqlite3.IntegrityError."""
    sk = os.urandom(4032)
    vk = b"\x88" * 1952
    _write_legacy_row(tmp_db, vk, sk)  # schema has NOT NULL

    # Construction of CommitmentLogStore must rebuild the schema.
    store = CommitmentLogStore(tmp_db)
    # Confirm sk column is now nullable.
    cols = {row[1]: row for row in store._conn.execute(
        "PRAGMA table_info(log_operator)").fetchall()}
    assert cols["sk"][3] == 0  # notnull flag is 0
    # And the legacy row survived the rebuild.
    got = store.load_operator_keypair()
    assert got == (vk, sk)
    store.close()


def test_store_replaces_existing_row_under_legacy_not_null(tmp_db):
    """Regression for Codex P1: storing a fresh keypair to a DB whose
    schema started as NOT NULL must succeed (no IntegrityError)."""
    sk_old = os.urandom(4032)
    vk_old = b"\x77" * 1952
    _write_legacy_row(tmp_db, vk_old, sk_old)

    store = CommitmentLogStore(tmp_db)
    # Replace the row with a fresh keypair.
    sk_new = os.urandom(4032)
    vk_new = b"\x99" * 1952
    store.store_operator_keypair(vk_new, sk_new)
    assert store.load_operator_keypair() == (vk_new, sk_new)
    # Underlying sk column is NULL on the new row.
    raw_sk = store._conn.execute(
        "SELECT sk FROM log_operator WHERE id=1"
    ).fetchone()[0]
    assert raw_sk is None
    store.close()


def test_migration_aborts_if_underlying_sk_changes(tmp_db, caplog):
    """Regression for Codex P2: if a concurrent writer changes sk
    between the migration's read and its wrap, the migration must NOT
    overwrite with stale wrapped bytes."""
    import logging
    sk_a = os.urandom(4032)
    sk_b = os.urandom(4032)
    _write_legacy_row(tmp_db, b"vk", sk_a)

    store = CommitmentLogStore(tmp_db)
    # Inject a race: change sk between the read and the in-place wrap.
    # Easiest reproduction: call _migrate_row_inplace with a stale sk.
    # First, mutate the underlying row.
    store._conn.execute("UPDATE log_operator SET sk = ? WHERE id=1", (sk_b,))
    store._conn.commit()
    with caplog.at_level(logging.WARNING):
        store._migrate_row_inplace(sk_a)  # stale value
    assert any("legacy sk changed" in rec.message for rec in caplog.records)
    # The underlying row was NOT overwritten with the stale wrap.
    raw = store._conn.execute(
        "SELECT sk, sk_wrapped FROM log_operator WHERE id=1"
    ).fetchone()
    assert raw[0] == sk_b  # plaintext sk remains the newer value
    assert raw[1] is None  # no wrapped blob was written
    store.close()


def test_cli_rejects_missing_db_path(tmp_path):
    """Regression for Codex P2: typoed paths must error, not silently
    create a new SQLite file and report a no-op."""
    from ltp.tools.migrate_keyvault import migrate_one, MigrationError
    nonexistent = str(tmp_path / "does-not-exist.db")
    with pytest.raises(MigrationError, match="does not exist"):
        migrate_one(nonexistent)
    # And no new file was created.
    assert not os.path.exists(nonexistent)


def test_aad_domain_separation(tmp_db):
    """A wrapped blob from log_store cannot be unwrapped with a different AAD.
    Regression test for the per-site AAD discipline."""
    sk = os.urandom(4032)
    store = CommitmentLogStore(tmp_db)
    store.store_operator_keypair(b"vk", sk)
    raw_wrapped = store._conn.execute(
        "SELECT sk_wrapped FROM log_operator WHERE id=1"
    ).fetchone()[0]
    store.close()

    vault = KeyVault.from_environment()
    # Right AAD unwraps; wrong AAD fails.
    assert vault.unwrap(raw_wrapped, aad=b"ltp.storage.log_store:operator_sk") == sk
    with pytest.raises(KeyVaultError):
        vault.unwrap(raw_wrapped, aad=b"some.other.site")
