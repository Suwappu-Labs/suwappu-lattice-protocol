"""Durable backing for :class:`ltp.incentives.StablecoinLedger`.

The in-memory ledger is a correct accounting model with no memory. Restart
it and a customer's spent balance comes back, every on-chain deposit still
inside the watcher's lookback window is credited a second time, and
``check_solvency()`` returns ``True`` throughout -- because it compares the
process against itself and never against the world.

This module fixes that without changing the ledger's API. Every balance
movement is mirrored into a :class:`~ltp.ledger_journal.LedgerJournal` as a
balanced double-entry transaction *before* it touches memory, and the
in-memory figures are rebuilt from the journal on construction. The
practical inversion is the point:

    the dictionaries become a cache, and the journal becomes the ledger.

That is the same relationship the journal already maintains between its own
``balance_cache`` and its ``entries`` table, one level up -- and it comes
with the same obligation, which :meth:`DurableStablecoinLedger.detect_drift`
discharges: a cache nobody audits is a mutable balance column with extra
steps.

Chart of accounts
-----------------

One debit-normal asset account for custody, credit-normal claims against
it for everything the ledger owes:

===============================  ========  =========================
Account                          Kind      Claim
===============================  ========  =========================
``assets:custody``               debit     stablecoins actually held
``pool:operator``                credit    unpaid operator rewards
``pool:insurance``               credit    slashing insurance
``pool:treasury``                credit    protocol treasury
``bond:<node_id>``               credit    that node's refundable bond
``customer:<customer_id>``       credit    that customer's prepaid balance
===============================  ========  =========================

Solvency is then the ordinary balance-sheet identity -- custody equals the
sum of the claims -- and, unlike the in-memory check, it is answered by
replaying entries rather than by re-reading the numbers under audit.

Known limits
------------

* **SQLite's single writer.** Every mutation serializes through one
  connection. Fine for a single gateway; the schema stays plain SQL so
  Postgres is a swap rather than a rewrite.
* **Two stores, one lock.** Memory is updated after the journal commits,
  under the ledger's reentrant lock. A crash between the two loses nothing
  -- the journal is authoritative and replay repairs memory -- but an
  exception from the in-memory apply reverses the journal transaction
  rather than leaving the two disagreeing.
* **Payouts leave.** ``pay_from_pool`` credits custody, matching the base
  class: the money is gone from this ledger's perspective the moment it is
  paid. Tracking it further is the payout rail's job, not the journal's.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import TypeVar

from .incentives import (
    IncentiveConfig,
    LedgerError,
    NodeIncentiveAccount,
    StablecoinLedger,
)
from .ledger_journal import (
    ASSET_CUSTODY,
    AccountKind,
    DriftReport,
    LedgerJournal,
    Posting,
)

logger = logging.getLogger(__name__)

__all__ = [
    "POOL_INSURANCE",
    "POOL_OPERATOR",
    "POOL_TREASURY",
    "NODE_MEMO_NAMESPACE",
    "DurableStablecoinLedger",
    "bond_account",
    "customer_account",
]

POOL_OPERATOR = "pool:operator"
POOL_INSURANCE = "pool:insurance"
POOL_TREASURY = "pool:treasury"

_BOND_PREFIX = "bond:"
_CUSTOMER_PREFIX = "customer:"

#: Namespace for per-node state that is durable but not double-entry.
NODE_MEMO_NAMESPACE = "node"

#: Account fields the engine writes directly, which the books cannot hold.
#:
#: ``bond_micro``, ``paid_total_micro`` and ``slashed_total_micro`` are all
#: derivable from entries, so they are replayed rather than memoized. These
#: three are not: an accrued claim is money *owed* but not yet funded, and an
#: offense count or an eviction flag is not a claim on custody at all. Putting
#: any of them in ``entries`` would corrupt the solvency identity -- but
#: leaving them in memory loses them, and a lost ``evicted`` flag silently
#: un-evicts a node that was expelled for cause.
_MEMO_FIELDS = ("earned_claim_micro", "audit_offense_count", "evicted")

T = TypeVar("T")


def bond_account(node_id: str) -> str:
    """Journal account holding ``node_id``'s bond."""
    return f"{_BOND_PREFIX}{node_id}"


def customer_account(customer_id: str) -> str:
    """Journal account holding ``customer_id``'s prepaid balance."""
    return f"{_CUSTOMER_PREFIX}{customer_id}"


class _DurableNodeAccount(NodeIncentiveAccount):
    """A node account whose non-derivable fields write through to disk.

    The settlement engine mutates ``acct.earned_claim_micro`` and
    ``acct.evicted`` directly -- it never routes them through a ledger
    method -- so the ledger cannot intercept them by overriding one.
    Intercepting ``__setattr__`` catches those writes wherever they come
    from, which is the only way to persist them without reaching into the
    engine and changing how it accrues.

    Persistence is deliberately attached *after* construction: the
    dataclass initializer assigns the defaults, and persisting those would
    overwrite the very values being restored.
    """

    _store: LedgerJournal | None = None

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        store = self.__dict__.get("_store")
        if store is not None and name in _MEMO_FIELDS:
            store.memo_set(NODE_MEMO_NAMESPACE, self.node_id, self._memo_state())

    def _memo_state(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in _MEMO_FIELDS}

    def _restore(self, memo: dict[str, object] | None) -> None:
        """Load memoized fields, then start persisting further writes."""
        for field, value in (memo or {}).items():
            if field in _MEMO_FIELDS:
                super().__setattr__(field, value)

    def _attach(self, store: LedgerJournal) -> None:
        super().__setattr__("_store", store)


def _debit(account: str, amount_micro: int) -> Posting:
    return Posting(account=account, amount_micro=amount_micro, direction=AccountKind.DEBIT)


def _credit(account: str, amount_micro: int) -> Posting:
    return Posting(account=account, amount_micro=amount_micro, direction=AccountKind.CREDIT)


class DurableStablecoinLedger(StablecoinLedger):
    """A :class:`StablecoinLedger` whose balances survive a restart.

    Drop-in for the in-memory ledger: same constructor keyword, same
    methods, same return types. The only additions are
    :meth:`detect_drift`, :meth:`audit_solvency` and the ``journal``
    attribute.

    >>> ledger = DurableStablecoinLedger(path="/var/lib/ltp/ledger.db")
    >>> ledger.customer_deposit("acme", 5_000_000)
    5000000
    >>> ledger.close()
    >>> DurableStablecoinLedger(path="/var/lib/ltp/ledger.db").customer_balance("acme")
    5000000
    """

    def __init__(
        self,
        config: IncentiveConfig | None = None,
        *,
        path: str = ":memory:",
        journal: LedgerJournal | None = None,
        currency: str = "USDC",
    ) -> None:
        super().__init__(config)
        if journal is not None and path != ":memory:":
            raise LedgerError("pass either a journal or a path, not both")
        self.journal = journal or LedgerJournal(path=path, currency=currency)
        self._owns_journal = journal is None
        for pool in (POOL_OPERATOR, POOL_INSURANCE, POOL_TREASURY):
            self.journal.ensure_account(pool, AccountKind.CREDIT)
        self._replay()

    # --- Journal plumbing -------------------------------------------------

    def _apply(
        self,
        description: str,
        postings: Iterable[Posting],
        apply: Callable[[], T],
        *,
        external_ref: str | None = None,
        counterparty: str | None = None,
    ) -> T:
        """Journal a movement, then mirror it into memory.

        The journal commits first because it is the authority: a crash
        after the commit is repaired by replay, whereas a crash after an
        in-memory update that never reached disk is exactly the data loss
        this module exists to prevent. If the in-memory apply raises
        anyway, the journal transaction is reversed rather than left
        describing a movement that did not happen -- a correction, never
        a deletion, so the attempt stays visible in history.
        """
        postings = [p for p in postings if p.amount_micro > 0]
        with self._lock:
            if not postings:
                # A zero-amount movement is a legal no-op for the caller
                # (`pay_from_pool` against an empty pool, refunding an
                # unknown customer). Writing an empty transaction for it
                # would add rows that say nothing.
                return apply()
            txn_id = self.journal.post(
                description,
                postings,
                external_ref=external_ref,
                counterparty=counterparty,
            )
            try:
                return apply()
            except BaseException:
                self.journal.reverse(txn_id, f"reversal: in-memory apply failed for {description}")
                raise

    def _fee_split(self, amount_micro: int) -> tuple[int, int, int]:
        """``(operator, insurance, treasury)`` -- mirrors the base class."""
        cfg = self.config
        insurance = amount_micro * cfg.fee_insurance_share_bps // 10_000
        treasury = amount_micro * cfg.fee_treasury_share_bps // 10_000
        return amount_micro - insurance - treasury, insurance, treasury

    def _split_postings(self, amount_micro: int) -> list[Posting]:
        operator, insurance, treasury = self._fee_split(amount_micro)
        return [
            _credit(POOL_OPERATOR, operator),
            _credit(POOL_INSURANCE, insurance),
            _credit(POOL_TREASURY, treasury),
        ]

    # --- Accounts ---------------------------------------------------------

    def account(self, node_id: str) -> NodeIncentiveAccount:
        """Fetch (or restore) a node's account.

        Overridden so a lazily-created account arrives carrying whatever
        it had before the last restart -- an accrued claim, an offense
        count, an eviction -- rather than as a blank slate.
        """
        with self._lock:
            acct = self._accounts.get(node_id)
            if acct is None:
                acct = _DurableNodeAccount(node_id=node_id)
                acct._restore(self.journal.memo_get(NODE_MEMO_NAMESPACE, node_id))
                acct._attach(self.journal)
                self._accounts[node_id] = acct
            return acct

    # --- Replay -----------------------------------------------------------

    def _replay(self) -> None:
        """Rebuild every in-memory figure from the journal."""
        j = self.journal
        self.operator_pool_micro = j.balance(POOL_OPERATOR).posted
        self.insurance_pool_micro = j.balance(POOL_INSURANCE).posted
        self.treasury_micro = j.balance(POOL_TREASURY).posted

        custody = j.balance(ASSET_CUSTODY)
        # Every deposit debits custody and every withdrawal credits it, so
        # the two counters the base class keeps by hand are already here.
        self._total_deposited = custody.posted_debits
        self._total_withdrawn = custody.posted_credits

        self._accounts.clear()
        self._customer_balances.clear()
        # A node can have durable state without a bond account -- one
        # evicted after forfeiting its whole bond, say -- so both sources
        # are walked, not just the books.
        for node_id in j.memo_namespace(NODE_MEMO_NAMESPACE):
            self.account(node_id)
        for name in j.accounts():
            if name.startswith(_BOND_PREFIX):
                node_id = name[len(_BOND_PREFIX) :]
                acct = self.account(node_id)
                acct.bond_micro = j.balance(name).posted
                acct.paid_total_micro = j.posted_total(
                    POOL_OPERATOR, AccountKind.DEBIT, counterparty=node_id
                )
                # A bond debited into insurance is a slash or a forfeit; the
                # same bond debited into custody is a refund. The pairing
                # filter is what tells them apart.
                acct.slashed_total_micro = j.posted_total(
                    name, AccountKind.DEBIT, paired_with=POOL_INSURANCE
                )
            elif name.startswith(_CUSTOMER_PREFIX):
                customer_id = name[len(_CUSTOMER_PREFIX) :]
                balance = j.balance(name).posted
                if balance:
                    self._customer_balances[customer_id] = balance

        logger.info(
            "ledger replayed from journal: %d accounts, %d customers, custody %d micro",
            len(self._accounts),
            len(self._customer_balances),
            custody.posted,
        )

    # --- Inflows ----------------------------------------------------------

    def deposit_fee(self, amount_micro: int) -> tuple[int, int, int]:
        if amount_micro < 0:
            raise LedgerError("fee deposit must be non-negative")
        return self._apply(
            "fee deposit",
            [_debit(ASSET_CUSTODY, amount_micro), *self._split_postings(amount_micro)],
            lambda: super(DurableStablecoinLedger, self).deposit_fee(amount_micro),
        )

    def fund_incentive_budget(self, amount_micro: int) -> None:
        if amount_micro < 0:
            raise LedgerError("budget funding must be non-negative")
        self._apply(
            "incentive budget funding",
            [_debit(ASSET_CUSTODY, amount_micro), _credit(POOL_OPERATOR, amount_micro)],
            lambda: super(DurableStablecoinLedger, self).fund_incentive_budget(amount_micro),
        )

    def post_bond(self, node_id: str, amount_micro: int) -> None:
        if amount_micro < 0:
            raise LedgerError("bond must be non-negative")
        self.journal.ensure_account(bond_account(node_id), AccountKind.CREDIT)
        self._apply(
            "bond posted",
            [_debit(ASSET_CUSTODY, amount_micro), _credit(bond_account(node_id), amount_micro)],
            lambda: super(DurableStablecoinLedger, self).post_bond(node_id, amount_micro),
            counterparty=node_id,
        )

    # --- Customer accounts ------------------------------------------------

    def customer_deposit(
        self,
        customer_id: str,
        amount_micro: int,
        *,
        external_ref: str | None = None,
    ) -> int:
        """Credit a prepaid balance, optionally anchored to ``external_ref``.

        ``external_ref`` is the durable replacement for the deposit
        watcher's in-memory seen-set: pass ``"<tx_hash>:<log_index>"`` and
        a replayed on-chain deposit raises
        :class:`~ltp.ledger_journal.DuplicateExternalRef` instead of
        crediting a second time. A transaction carrying two transfers is
        correctly two events, not a duplicate.
        """
        if not customer_id:
            raise LedgerError("customer_id must be non-empty")
        if amount_micro < 0:
            raise LedgerError("deposit must be non-negative")
        account = customer_account(customer_id)
        self.journal.ensure_account(account, AccountKind.CREDIT)
        return self._apply(
            "customer deposit",
            [_debit(ASSET_CUSTODY, amount_micro), _credit(account, amount_micro)],
            lambda: super(DurableStablecoinLedger, self).customer_deposit(
                customer_id, amount_micro
            ),
            external_ref=external_ref,
            counterparty=customer_id,
        )

    def customer_debit_to_fees(self, customer_id: str, amount_micro: int) -> tuple[int, int, int]:
        if amount_micro < 0:
            raise LedgerError("debit must be non-negative")
        with self._lock:
            # Validated before journaling, on the same lock hold the base
            # class uses, so a rejected debit writes nothing at all.
            balance = self._customer_balances.get(customer_id, 0)
            if balance < amount_micro:
                raise LedgerError(
                    f"insufficient customer balance: have {balance}, need {amount_micro}"
                )
            return self._apply(
                "inference billing",
                [
                    _debit(customer_account(customer_id), amount_micro),
                    *self._split_postings(amount_micro),
                ],
                lambda: super(DurableStablecoinLedger, self).customer_debit_to_fees(
                    customer_id, amount_micro
                ),
                counterparty=customer_id,
            )

    def customer_refund(self, customer_id: str) -> int:
        with self._lock:
            refund = self._customer_balances.get(customer_id, 0)
            return self._apply(
                "customer refund",
                [_debit(customer_account(customer_id), refund), _credit(ASSET_CUSTODY, refund)],
                lambda: super(DurableStablecoinLedger, self).customer_refund(customer_id),
                counterparty=customer_id,
            )

    # --- Internal movements -----------------------------------------------

    def pay_from_pool(self, node_id: str, amount_micro: int) -> int:
        if amount_micro < 0:
            raise LedgerError("payment must be non-negative")
        with self._lock:
            # Clamp here so the journal records what is actually paid; the
            # base class then re-clamps the already-clamped figure to the
            # same value.
            paid = min(amount_micro, self.operator_pool_micro)
            self.journal.ensure_account(bond_account(node_id), AccountKind.CREDIT)
            return self._apply(
                "operator payout",
                [_debit(POOL_OPERATOR, paid), _credit(ASSET_CUSTODY, paid)],
                lambda: super(DurableStablecoinLedger, self).pay_from_pool(node_id, paid),
                counterparty=node_id,
            )

    def slash_bond(self, node_id: str, amount_micro: int) -> int:
        if amount_micro < 0:
            raise LedgerError("slash must be non-negative")
        with self._lock:
            slashed = min(amount_micro, self.account(node_id).bond_micro)
            self.journal.ensure_account(bond_account(node_id), AccountKind.CREDIT)
            return self._apply(
                "bond slashed to insurance",
                [_debit(bond_account(node_id), slashed), _credit(POOL_INSURANCE, slashed)],
                lambda: super(DurableStablecoinLedger, self).slash_bond(node_id, slashed),
                counterparty=node_id,
            )

    def refund_bond(self, node_id: str) -> int:
        with self._lock:
            refund = self.account(node_id).bond_micro
            self.journal.ensure_account(bond_account(node_id), AccountKind.CREDIT)
            return self._apply(
                "bond refunded",
                [_debit(bond_account(node_id), refund), _credit(ASSET_CUSTODY, refund)],
                lambda: super(DurableStablecoinLedger, self).refund_bond(node_id),
                counterparty=node_id,
            )

    def forfeit_bond_to_insurance(self, node_id: str) -> int:
        with self._lock:
            forfeited = self.account(node_id).bond_micro
            self.journal.ensure_account(bond_account(node_id), AccountKind.CREDIT)
            return self._apply(
                "bond forfeited to insurance",
                [_debit(bond_account(node_id), forfeited), _credit(POOL_INSURANCE, forfeited)],
                lambda: super(DurableStablecoinLedger, self).forfeit_bond_to_insurance(node_id),
                counterparty=node_id,
            )

    # --- Audit ------------------------------------------------------------

    def detect_drift(self, *, distrust: bool = True) -> list[DriftReport]:
        """Reconcile the in-memory figures against the journal.

        Returns one report per account whose cached figure disagrees --
        empty when the cache is faithful. The journal's own cache is
        audited first, so a drift report here means *this* class's
        dictionaries diverged, not the journal's counters.
        """
        with self._lock:
            reports = list(self.journal.detect_drift(distrust=distrust))
            expected: dict[str, int] = {
                POOL_OPERATOR: self.operator_pool_micro,
                POOL_INSURANCE: self.insurance_pool_micro,
                POOL_TREASURY: self.treasury_micro,
            }
            for node_id, acct in self._accounts.items():
                expected[bond_account(node_id)] = acct.bond_micro
            for customer_id, balance in self._customer_balances.items():
                expected[customer_account(customer_id)] = balance
            known = set(self.journal.accounts())
            for account, cached in expected.items():
                truth = self.journal.recompute_balance(account).posted if account in known else 0
                if cached != truth:
                    reports.append(
                        DriftReport(
                            account=account,
                            cached_posted=cached,
                            recomputed_posted=truth,
                        )
                    )
        for report in reports:
            logger.error(
                "ledger drift on %s: cached %d, journal %d (delta %d)",
                report.account,
                report.cached_posted,
                report.recomputed_posted,
                report.delta,
            )
        return reports

    def audit_solvency(self) -> bool:
        """Solvency answered from the journal rather than from memory.

        :meth:`check_solvency` compares the in-memory buckets against the
        in-memory deposit counters -- self-consistent, and blind to a
        journal that says something else. This replays entries instead, so
        a forged or lost movement shows up.
        """
        with self._lock:
            return self.journal.check_solvency()

    def close(self) -> None:
        """Close the journal, if this ledger opened it."""
        if self._owns_journal:
            self.journal.close()
