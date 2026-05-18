"""CLI: bulk-migrate legacy plaintext operator sk to KeyVault-wrapped form.

Usage:
    python -m ltp.tools.migrate_keyvault <db_path> [<db_path> ...]

Idempotent. Exits 0 if every database is either already migrated or has
no operator row. Exits 1 if any database fails to open or wrap. Reads
the KEK via the standard `KeyVault.from_environment()` chain (env var,
OS keychain, HSM-derived, fail-closed in production).

Closes LTP-A-032 for any database written before Phase 2 of the
KeyVault rollout.
"""

from __future__ import annotations

import argparse
import logging
import sys

from ..storage.log_store import CommitmentLogStore

_LOG = logging.getLogger(__name__)


def migrate_one(db_path: str) -> bool:
    """Migrate a single database. Returns True on a real migration,
    False when the row was already wrapped or absent.
    """
    store = CommitmentLogStore(db_path)
    try:
        migrated = store.migrate_operator_keypair()
    finally:
        store.close()
    if migrated:
        _LOG.info("migrated operator sk in %s", db_path)
    else:
        _LOG.info("no-op for %s (already wrapped or no operator row)", db_path)
    return migrated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ltp.tools.migrate_keyvault")
    parser.add_argument(
        "db_path",
        nargs="+",
        help="One or more CommitmentLogStore SQLite databases to migrate.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose logging."
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    rc = 0
    for db in args.db_path:
        try:
            migrate_one(db)
        except Exception as exc:  # noqa: BLE001 — CLI top level
            _LOG.error("migration failed for %s: %s", db, exc)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
