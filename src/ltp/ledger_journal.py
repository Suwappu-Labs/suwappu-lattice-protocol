"""
Durable double-entry journal for the stablecoin ledger.

``ltp.incentives.StablecoinLedger`` keeps balances in process memory. That
is fast and correct *within* one process, and it fails in a way the
solvency invariant cannot see: restart the service and a customer's spent
balance reappears, the same on-chain deposit credits again, and
``check_solvency()`` returns True throughout — because it checks the
process against itself, never against the world. Both halves of that were
reproduced against the in-memory ledger before this module was written.

This module is the fix, and it follows the shape production ledgers
actually use (see ``docs/economics/BILLING_LEDGER_GAP_ANALYSIS.md`` for
the sourced argument):

  1. **Entries, not balances.** The system of record is an append-only
     journal of ``transactions`` and their ``entries``. Balances are
     *derived*. Nothing UPDATEs a balance as its primary act, so there is
     always an artifact to replay and to reconcile against.

  2. **Balanced or absent.** Every transaction asserts
     ``sum(debits) == sum(credits)``, per currency, inside the same SQL
     transaction that writes it. A partial write cannot survive: the
     entry pair either both exist or neither does.

  3. **Corrections by reversal.** ``reverse()`` posts an opposite-signed
     transaction pointing at the original. Nothing is ever UPDATEd or
     DELETEd, so a refund is distinguishable from a fraudulent credit.

  4. **A cache with a drift detector.** Reading a balance by summing all
     entries is O(n), so balances are cached as four counters
     (pending/posted × debit/credit) written in the *same* SQL
     transaction as the entry. ``detect_drift()`` recomputes from the
     journal and disables cache reads for any account that diverges — a
     cache without that check is a mutable balance column with extra
     steps.

  5. **Idempotency as a durable table.** ``(scope, key)`` unique, storing
     the request-parameter hash and the cached response, with a lock
     column, a ``recovery_point`` for resuming a partially-completed
     operation, and a documented retention window. A set of seen ids in
     memory is duplicate suppression, not idempotency: it does not
     survive restart, is not shared across replicas, and cannot replay
     the original response.

Storage is stdlib ``sqlite3`` — no new dependency, ACID, and the schema
is deliberately plain SQL so a Postgres backing is a swap rather than a
rewrite. The concurrency ceiling is SQLite's (one writer at a time);
that is a real limit, and it is documented rather than hidden.

Not re-exported from ``ltp.__init__`` (private per
``docs/STABILITY_PROMISES.md``).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

__all__ = [
    "JournalError",
    "UnbalancedTransaction",
    "DuplicateExternalRef",
    "IdempotencyConflict",
    "AccountKind",
    "Posting",
    "AccountBalance",
    "DriftReport",
    "IdempotencyRecord",
    "LedgerJournal",
    "ASSET_CUSTODY",
]

# The single debit-normal account: stablecoin the deployment actually
# holds. Every credit-normal account below is a claim against it, so
# `assets == liabilities` is the money-was-neither-created-nor-destroyed
# assertion, runnable at any moment.
ASSET_CUSTODY = "assets:custody"

# Industry default for API-call idempotency (Stripe prunes at ~24h).
# Usage-event dedup wants a much longer window (~32 days); that is a
# different problem and gets a different scope.
DEFAULT_KEY_RETENTION_SECONDS = 24 * 3600


class JournalError(Exception):
    """Base for journal failures."""


class UnbalancedTransaction(JournalError):
    """Debits did not equal credits. The transaction was not written."""


class DuplicateExternalRef(JournalError):
    """An external reference (e.g. tx_hash:log_index) was already posted.

    Raised by the uniqueness constraint on the entry itself, so
    double-crediting an on-chain deposit is impossible by construction
    rather than by convention.
    """


class IdempotencyConflict(JournalError):
    """A concurrent request holds this idempotency key (HTTP 409), or the
    key was reused with different parameters."""


class AccountKind:
    """Normality of an account. Debit-normal assets, credit-normal claims."""

    DEBIT = "debit"
    CREDIT = "credit"


@dataclass(frozen=True)
class Posting:
    """One side of a transaction: an amount against an account."""

    account: str
    amount_micro: int
    direction: str  # AccountKind.DEBIT | AccountKind.CREDIT

    def __post_init__(self) -> None:
        if self.amount_micro < 0:
            raise JournalError("posting amounts are unsigned; use direction")
        if self.direction not in (AccountKind.DEBIT, AccountKind.CREDIT):
            raise JournalError(f"bad direction: {self.direction!r}")
        if not self.account:
            raise JournalError("posting needs an account")


@dataclass(frozen=True)
class AccountBalance:
    """Derived balance, split the way production ledgers split it.

    Four counters rather than one net figure: authorized-but-uncleared
    has to stay distinguishable from settled, and debit/credit totals are
    separately reconcilable against an external record.
    """

    account: str
    kind: str
    posted_debits: int
    posted_credits: int
    pending_debits: int
    pending_credits: int

    @property
    def posted(self) -> int:
        """Settled balance, signed by the account's normality."""
        if self.kind == AccountKind.DEBIT:
            return self.posted_debits - self.posted_credits
        return self.posted_credits - self.posted_debits

    @property
    def available(self) -> int:
        """Posted minus uncleared holds — what may still be spent.

        A hold is recorded in whichever direction *decreases* the
        account's normal balance, so it is that direction which must be
        subtracted here: a pending debit against a customer's
        credit-normal balance is money already spoken for.
        """
        if self.kind == AccountKind.DEBIT:
            return self.posted - (self.pending_credits - self.pending_debits)
        return self.posted - (self.pending_debits - self.pending_credits)


@dataclass(frozen=True)
class DriftReport:
    """One account whose cached balance disagreed with the journal."""

    account: str
    cached_posted: int
    recomputed_posted: int

    @property
    def delta(self) -> int:
        return self.cached_posted - self.recomputed_posted


@dataclass(frozen=True)
class IdempotencyRecord:
    """A stored idempotency result: the original outcome, replayable."""

    scope: str
    key: str
    params_hash: str
    recovery_point: str
    response_code: int | None
    response_body: Any | None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account     TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('debit','credit')),
    currency    TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    REAL NOT NULL,
    description   TEXT NOT NULL,
    currency      TEXT NOT NULL,
    -- Set on a correcting transaction; points at what it reverses.
    reverses_id   INTEGER REFERENCES transactions(id),
    -- External idempotency anchor, e.g. "<tx_hash>:<log_index>".
    external_ref  TEXT,
    -- The other party to the movement, when it is someone the journal
    -- does not hold an account for -- a node being paid out, say. Lets
    -- per-counterparty totals be a query instead of a description parse.
    counterparty  TEXT
);

-- Double-crediting an on-chain deposit is impossible by construction,
-- not by a convention someone can forget.
CREATE UNIQUE INDEX IF NOT EXISTS transactions_external_ref
    ON transactions (external_ref) WHERE external_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id  INTEGER NOT NULL REFERENCES transactions(id),
    account         TEXT NOT NULL REFERENCES accounts(account),
    amount_micro    INTEGER NOT NULL CHECK (amount_micro >= 0),
    direction       TEXT NOT NULL CHECK (direction IN ('debit','credit')),
    state           TEXT NOT NULL CHECK (state IN ('pending','posted')),
    created_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS entries_account ON entries (account);
CREATE INDEX IF NOT EXISTS entries_transaction ON entries (transaction_id);
CREATE INDEX IF NOT EXISTS transactions_counterparty
    ON transactions (counterparty) WHERE counterparty IS NOT NULL;

-- Cached balances. Written in the SAME sql transaction as the entries,
-- and policed by detect_drift().
CREATE TABLE IF NOT EXISTS balance_cache (
    account         TEXT PRIMARY KEY REFERENCES accounts(account),
    posted_debits   INTEGER NOT NULL DEFAULT 0,
    posted_credits  INTEGER NOT NULL DEFAULT 0,
    pending_debits  INTEGER NOT NULL DEFAULT 0,
    pending_credits INTEGER NOT NULL DEFAULT 0,
    -- Flipped to 0 by detect_drift(); reads then fall back to the journal.
    trusted         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope           TEXT NOT NULL,
    key             TEXT NOT NULL,
    params_hash     TEXT NOT NULL,
    recovery_point  TEXT NOT NULL,
    response_code   INTEGER,
    response_body   TEXT,
    locked_at       REAL,
    created_at      REAL NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE INDEX IF NOT EXISTS idempotency_created ON idempotency_keys (created_at);

-- Durable state that is deliberately NOT part of the books: counters and
-- flags that must survive a restart but are not claims on custody, and so
-- must never appear in the solvency identity. Kept in the same database so
-- one file is one consistent snapshot.
CREATE TABLE IF NOT EXISTS memos (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    updated_at  REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


def _params_hash(params: Any) -> str:
    """Stable hash of request parameters, for reuse detection."""
    encoded = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class LedgerJournal:
    """An append-only double-entry journal backed by SQLite.

    ``path=":memory:"`` gives an ephemeral journal for tests; a file path
    gives durability across restarts, which is the entire point.
    """

    def __init__(
        self,
        path: str = ":memory:",
        currency: str = "USDC",
        key_retention_seconds: int = DEFAULT_KEY_RETENTION_SECONDS,
    ) -> None:
        self.currency = currency
        self.key_retention_seconds = key_retention_seconds
        # check_same_thread=False: the service runs the deposit poller and
        # the gateway against one journal. Writes are serialized by _lock
        # (SQLite allows a single writer regardless), so this is safe.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        # Durability over throughput: a billing ledger that loses the last
        # transaction on power-loss is the failure this module exists for.
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.commit()
        self._lock = threading.RLock()
        self.ensure_account(ASSET_CUSTODY, AccountKind.DEBIT)

    def _migrate(self) -> None:
        """Bring an older journal file up to the current schema.

        ``CREATE TABLE IF NOT EXISTS`` is a no-op on a database that
        already has the table, so a column added after a journal was
        first written has to be added explicitly. Additive only: this
        never drops or rewrites a column, because the whole premise of
        the module is that written history stays written.
        """
        columns = {
            row["name"] for row in self._db.execute("PRAGMA table_info(transactions)").fetchall()
        }
        if "counterparty" not in columns:
            self._db.execute("ALTER TABLE transactions ADD COLUMN counterparty TEXT")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS transactions_counterparty "
                "ON transactions (counterparty) WHERE counterparty IS NOT NULL"
            )

    # --- Accounts ---

    def ensure_account(self, account: str, kind: str) -> None:
        """Create ``account`` if absent. Idempotent; never changes kind."""
        if kind not in (AccountKind.DEBIT, AccountKind.CREDIT):
            raise JournalError(f"bad account kind: {kind!r}")
        with self._lock:
            row = self._db.execute(
                "SELECT kind FROM accounts WHERE account = ?", (account,)
            ).fetchone()
            if row is not None:
                if row["kind"] != kind:
                    raise JournalError(
                        f"account {account!r} already exists as {row['kind']}-normal"
                    )
                return
            self._db.execute(
                "INSERT INTO accounts (account, kind, currency, created_at) VALUES (?, ?, ?, ?)",
                (account, kind, self.currency, time.time()),
            )
            self._db.execute("INSERT INTO balance_cache (account) VALUES (?)", (account,))
            self._db.commit()

    def account_kind(self, account: str) -> str:
        row = self._db.execute("SELECT kind FROM accounts WHERE account = ?", (account,)).fetchone()
        if row is None:
            raise JournalError(f"unknown account: {account!r}")
        return row["kind"]

    # --- Posting ---

    def post(
        self,
        description: str,
        postings: Iterable[Posting],
        *,
        external_ref: str | None = None,
        state: str = "posted",
        reverses_id: int | None = None,
        counterparty: str | None = None,
    ) -> int:
        """Write one balanced transaction. Returns its id.

        Debits must equal credits or nothing is written —
        ``UnbalancedTransaction`` leaves the journal untouched. The
        balance cache is updated inside the same SQL transaction, so the
        cache cannot survive a rollback of the entries it summarizes.
        """
        postings = list(postings)
        if not postings:
            raise JournalError("a transaction needs at least one posting")
        if state not in ("pending", "posted"):
            raise JournalError(f"bad entry state: {state!r}")

        debits = sum(p.amount_micro for p in postings if p.direction == AccountKind.DEBIT)
        credits = sum(p.amount_micro for p in postings if p.direction == AccountKind.CREDIT)
        if debits != credits:
            raise UnbalancedTransaction(f"debits {debits} != credits {credits} for {description!r}")

        now = time.time()
        with self._lock:
            for p in postings:
                if (
                    self._db.execute(
                        "SELECT 1 FROM accounts WHERE account = ?", (p.account,)
                    ).fetchone()
                    is None
                ):
                    raise JournalError(f"unknown account: {p.account!r}")
            try:
                with self._db:  # BEGIN … COMMIT, rollback on exception
                    cur = self._db.execute(
                        "INSERT INTO transactions "
                        "(created_at, description, currency, reverses_id, external_ref, "
                        " counterparty) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            now,
                            description,
                            self.currency,
                            reverses_id,
                            external_ref,
                            counterparty,
                        ),
                    )
                    txn_id = int(cur.lastrowid)
                    for p in postings:
                        self._db.execute(
                            "INSERT INTO entries "
                            "(transaction_id, account, amount_micro, direction, "
                            " state, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                            (txn_id, p.account, p.amount_micro, p.direction, state, now),
                        )
                        column = (
                            f"{state}_{'debits' if p.direction == AccountKind.DEBIT else 'credits'}"
                        )
                        self._db.execute(
                            f"UPDATE balance_cache SET {column} = {column} + ? WHERE account = ?",
                            (p.amount_micro, p.account),
                        )
            except sqlite3.IntegrityError as exc:
                if external_ref is not None and "external_ref" in str(exc):
                    raise DuplicateExternalRef(
                        f"external_ref {external_ref!r} already posted"
                    ) from None
                raise JournalError(str(exc)) from None
            return txn_id

    def reverse(self, transaction_id: int, description: str | None = None) -> int:
        """Correct a transaction by posting its mirror image.

        Never an UPDATE or a DELETE: the original stays in the journal and
        the correction is visible as its own event, which is what makes a
        refund distinguishable from a fabricated credit.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT account, amount_micro, direction, state FROM entries "
                "WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchall()
            if not rows:
                raise JournalError(f"no such transaction: {transaction_id}")
            flipped = [
                Posting(
                    account=r["account"],
                    amount_micro=r["amount_micro"],
                    direction=(
                        AccountKind.CREDIT
                        if r["direction"] == AccountKind.DEBIT
                        else AccountKind.DEBIT
                    ),
                )
                for r in rows
            ]
            return self.post(
                description or f"reversal of transaction {transaction_id}",
                flipped,
                state=rows[0]["state"],
                reverses_id=transaction_id,
            )

    # --- Derived balances ---

    def balance(self, account: str) -> AccountBalance:
        """Balance for ``account``, from the cache when it is trusted."""
        with self._lock:
            kind = self.account_kind(account)
            row = self._db.execute(
                "SELECT * FROM balance_cache WHERE account = ?", (account,)
            ).fetchone()
            if row is not None and row["trusted"]:
                return AccountBalance(
                    account=account,
                    kind=kind,
                    posted_debits=row["posted_debits"],
                    posted_credits=row["posted_credits"],
                    pending_debits=row["pending_debits"],
                    pending_credits=row["pending_credits"],
                )
            return self.recompute_balance(account)

    def recompute_balance(self, account: str) -> AccountBalance:
        """Balance summed from the journal itself, ignoring the cache."""
        with self._lock:
            kind = self.account_kind(account)
            totals = {
                ("posted", "debit"): 0,
                ("posted", "credit"): 0,
                ("pending", "debit"): 0,
                ("pending", "credit"): 0,
            }
            for r in self._db.execute(
                "SELECT state, direction, SUM(amount_micro) AS total FROM entries "
                "WHERE account = ? GROUP BY state, direction",
                (account,),
            ):
                totals[(r["state"], r["direction"])] = r["total"] or 0
            return AccountBalance(
                account=account,
                kind=kind,
                posted_debits=totals[("posted", "debit")],
                posted_credits=totals[("posted", "credit")],
                pending_debits=totals[("pending", "debit")],
                pending_credits=totals[("pending", "credit")],
            )

    def posted_total(
        self,
        account: str,
        direction: str,
        *,
        counterparty: str | None = None,
        paired_with: str | None = None,
    ) -> int:
        """Sum posted entries on ``account`` in ``direction``.

        Optionally narrowed to transactions carrying ``counterparty``,
        and/or to those that also post to ``paired_with``. That second
        filter is what separates movements that share an account but not
        a meaning -- a bond debited into the insurance pool is a slash,
        the same bond debited back into custody is a refund.

        Always recomputed from ``entries``; this is a history question,
        and the balance cache only knows totals.
        """
        if direction not in (AccountKind.DEBIT, AccountKind.CREDIT):
            raise JournalError(f"bad direction: {direction!r}")
        sql = [
            "SELECT COALESCE(SUM(e.amount_micro), 0) AS total FROM entries e",
            "JOIN transactions t ON t.id = e.transaction_id",
            "WHERE e.account = ? AND e.direction = ? AND e.state = 'posted'",
        ]
        params: list[Any] = [account, direction]
        if counterparty is not None:
            sql.append("AND t.counterparty = ?")
            params.append(counterparty)
        if paired_with is not None:
            sql.append(
                "AND EXISTS (SELECT 1 FROM entries p "
                "WHERE p.transaction_id = t.id AND p.account = ?)"
            )
            params.append(paired_with)
        with self._lock:
            row = self._db.execute(" ".join(sql), params).fetchone()
        return int(row["total"])

    def accounts(self) -> list[str]:
        return [
            r["account"] for r in self._db.execute("SELECT account FROM accounts ORDER BY account")
        ]

    # --- Integrity ---

    def detect_drift(self, *, distrust: bool = True) -> list[DriftReport]:
        """Recompute every cached balance and report divergence.

        With ``distrust=True`` any diverging account has its cache marked
        untrusted, so subsequent reads fall through to the journal. A
        cache nobody audits is just a mutable balance column.
        """
        drifted: list[DriftReport] = []
        with self._lock:
            for account in self.accounts():
                row = self._db.execute(
                    "SELECT * FROM balance_cache WHERE account = ?", (account,)
                ).fetchone()
                if row is None:
                    continue
                kind = self.account_kind(account)
                cached = AccountBalance(
                    account=account,
                    kind=kind,
                    posted_debits=row["posted_debits"],
                    posted_credits=row["posted_credits"],
                    pending_debits=row["pending_debits"],
                    pending_credits=row["pending_credits"],
                )
                truth = self.recompute_balance(account)
                if cached.posted != truth.posted:
                    drifted.append(
                        DriftReport(
                            account=account,
                            cached_posted=cached.posted,
                            recomputed_posted=truth.posted,
                        )
                    )
                    if distrust:
                        self._db.execute(
                            "UPDATE balance_cache SET trusted = 0 WHERE account = ?",
                            (account,),
                        )
            if drifted and distrust:
                self._db.commit()
        return drifted

    def check_solvency(self) -> bool:
        """Assets equal claims — money was neither created nor destroyed.

        Deliberately reads through ``recompute_balance`` rather than the
        cache. An integrity check that trusts the cache cannot see a
        journal that has been tampered with underneath it: the forged
        entry never touches the cached counters, so a cache-backed check
        reports healthy while the entries say otherwise. That was a real
        bug in an earlier version of this method, caught by the test that
        forges an entry — which is why that test exists.

        O(entries) by construction. This is an audit operation, not a
        request-path read; ``balance()`` is the fast path.

        Unlike an in-memory scalar comparison this is a statement about a
        durable artifact: it survives restart and can be recomputed from
        the journal by anyone holding the file.
        """
        with self._lock:
            assets = self.recompute_balance(ASSET_CUSTODY).posted
            claims = sum(
                self.recompute_balance(a).posted
                for a in self.accounts()
                if self.account_kind(a) == AccountKind.CREDIT
            )
            return assets == claims

    # --- Idempotency ---

    def begin_idempotent(
        self, scope: str, key: str, params: Any, *, recovery_point: str = "started"
    ) -> IdempotencyRecord | None:
        """Claim ``(scope, key)``, or return the stored original result.

        Returns ``None`` when this caller now owns the key and should do
        the work. Returns the existing ``IdempotencyRecord`` when the
        request already completed — replay its response rather than
        re-executing, which is what makes a retry safe.

        Raises ``IdempotencyConflict`` if another caller currently holds
        the key (answer 409), or if the key is being reused with
        different parameters.
        """
        now = time.time()
        digest = _params_hash(params)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM idempotency_keys WHERE scope = ? AND key = ?",
                (scope, key),
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO idempotency_keys "
                    "(scope, key, params_hash, recovery_point, locked_at, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (scope, key, digest, recovery_point, now, now),
                )
                self._db.commit()
                return None
            if row["params_hash"] != digest:
                raise IdempotencyConflict(f"key {scope}/{key} reused with different parameters")
            if row["response_code"] is not None:
                return self._record(row)
            if row["locked_at"] is not None:
                raise IdempotencyConflict(f"key {scope}/{key} is in flight")
            self._db.execute(
                "UPDATE idempotency_keys SET locked_at = ? WHERE scope = ? AND key = ?",
                (now, scope, key),
            )
            self._db.commit()
            return None

    def set_recovery_point(self, scope: str, key: str, recovery_point: str) -> None:
        """Checkpoint a partially-completed operation.

        This is the column a set of seen ids cannot have: it distinguishes
        "never started" from "foreign mutation done, local commit
        pending", so a retry resumes instead of re-charging.
        """
        with self._lock:
            self._db.execute(
                "UPDATE idempotency_keys SET recovery_point = ? WHERE scope = ? AND key = ?",
                (recovery_point, scope, key),
            )
            self._db.commit()

    def complete_idempotent(
        self, scope: str, key: str, response_code: int, response_body: Any
    ) -> None:
        """Store the outcome — success *or* failure — and release the lock.

        Failures are stored deliberately: replaying the original 500 is
        the contract, because a retry that silently succeeds where the
        first attempt failed is a second charge.
        """
        with self._lock:
            self._db.execute(
                "UPDATE idempotency_keys SET response_code = ?, response_body = ?, "
                "recovery_point = 'finished', locked_at = NULL "
                "WHERE scope = ? AND key = ?",
                (response_code, json.dumps(response_body, default=str), scope, key),
            )
            self._db.commit()

    def idempotency_record(self, scope: str, key: str) -> IdempotencyRecord | None:
        row = self._db.execute(
            "SELECT * FROM idempotency_keys WHERE scope = ? AND key = ?", (scope, key)
        ).fetchone()
        return self._record(row) if row is not None else None

    def reap_idempotency_keys(self, *, now: float | None = None) -> int:
        """Delete keys past the retention window. Returns how many went.

        The window is a correctness parameter the client has to know
        about: a retry after it has elapsed is a *new* request, and will
        execute again.
        """
        cutoff = (now if now is not None else time.time()) - self.key_retention_seconds
        with self._lock:
            cur = self._db.execute("DELETE FROM idempotency_keys WHERE created_at < ?", (cutoff,))
            self._db.commit()
            return cur.rowcount

    def abandoned_keys(self, *, older_than_seconds: float = 300.0) -> list[IdempotencyRecord]:
        """Keys locked long ago and never completed — the completer's work.

        A client that died after a foreign mutation but before the local
        commit leaves exactly this, and nothing else in the system knows
        the operation is half-done.
        """
        cutoff = time.time() - older_than_seconds
        rows = self._db.execute(
            "SELECT * FROM idempotency_keys WHERE locked_at IS NOT NULL "
            "AND locked_at < ? AND response_code IS NULL",
            (cutoff,),
        ).fetchall()
        return [self._record(r) for r in rows]

    @staticmethod
    def _record(row: sqlite3.Row) -> IdempotencyRecord:
        body = row["response_body"]
        return IdempotencyRecord(
            scope=row["scope"],
            key=row["key"],
            params_hash=row["params_hash"],
            recovery_point=row["recovery_point"],
            response_code=row["response_code"],
            response_body=json.loads(body) if body is not None else None,
        )

    # --- Lifecycle ---

    # --- Memos ------------------------------------------------------------

    def memo_set(self, namespace: str, key: str, value: Any) -> None:
        """Store JSON-serializable durable state outside the books.

        For state that must survive a restart but is not a claim on
        custody -- an offense counter, an eviction flag. Putting such
        things in ``entries`` would corrupt the solvency identity, and
        leaving them in memory loses them, so they get their own table.
        """
        with self._lock:
            self._db.execute(
                "INSERT INTO memos (namespace, key, value_json, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT (namespace, key) "
                "DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                (namespace, key, json.dumps(value, sort_keys=True), time.time()),
            )
            self._db.commit()

    def memo_get(self, namespace: str, key: str, default: Any = None) -> Any:
        """Read one memo, or ``default`` when it was never written."""
        row = self._db.execute(
            "SELECT value_json FROM memos WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        return default if row is None else json.loads(row["value_json"])

    def memo_namespace(self, namespace: str) -> dict[str, Any]:
        """Every memo in ``namespace``, keyed as stored."""
        rows = self._db.execute(
            "SELECT key, value_json FROM memos WHERE namespace = ?", (namespace,)
        ).fetchall()
        return {row["key"]: json.loads(row["value_json"]) for row in rows}

    def close(self) -> None:
        with self._lock:
            self._db.close()
