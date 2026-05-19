"""ReplayDB — SQLite-backed event deduplication for the gateway VM."""

from __future__ import annotations

import sqlite3
import time
from typing import Optional


class ReplayDB:
    """Per-source-chain event deduplication using SQLite.

    Each processed event is recorded by its event_id (deterministic hash
    of chain_id + tx_hash + log_index). Duplicate events are rejected
    before any commitment is created.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_events (
                event_id    TEXT PRIMARY KEY,
                tx_hash     TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                processed_at REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def is_processed(self, event_id: str) -> bool:
        """Check if an event has already been processed."""
        row = self._conn.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return row is not None

    def mark_processed(self, event_id: str, *, tx_hash: str, block_number: int) -> None:
        """Record an event as processed. Idempotent — duplicates are ignored."""
        self._conn.execute(
            """
            INSERT OR IGNORE INTO processed_events
                (event_id, tx_hash, block_number, processed_at)
            VALUES (?, ?, ?, ?)
            """,
            (event_id, tx_hash, block_number, time.time()),
        )
        self._conn.commit()

    def get(self, event_id: str) -> Optional[dict]:
        """Fetch a processed event record, or None if not found."""
        row = self._conn.execute(
            "SELECT event_id, tx_hash, block_number, processed_at "
            "FROM processed_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "event_id": row[0],
            "tx_hash": row[1],
            "block_number": row[2],
            "processed_at": row[3],
        }

    def count(self) -> int:
        """Return the number of processed events."""
        row = self._conn.execute("SELECT COUNT(*) FROM processed_events").fetchone()
        return row[0]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
