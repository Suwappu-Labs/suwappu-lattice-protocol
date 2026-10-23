"""Tests for the durable backing of ``StablecoinLedger``.

These are written to break the thing, not to confirm it: state is
corrupted behind the ledger's back, entries are forged directly into the
journal, mutators are made to fail after their transaction has committed,
and threads are pushed at each other with a hostile switch interval. A
test that only replays the happy path would have missed both bugs found
while writing the journal itself.
"""

from __future__ import annotations

import sqlite3
import sys
import threading

import pytest

from ltp.incentives import IncentiveConfig, LedgerError, MeteredWorkReport, StableNodeIncentive
from ltp.ledger_durable import (
    NODE_MEMO_NAMESPACE,
    POOL_INSURANCE,
    POOL_OPERATOR,
    POOL_TREASURY,
    DurableStablecoinLedger,
    bond_account,
    customer_account,
)
from ltp.ledger_journal import (
    ASSET_CUSTODY,
    AccountKind,
    DuplicateExternalRef,
    LedgerJournal,
    Posting,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "ledger.db")


def _fresh(db_path, **kwargs):
    return DurableStablecoinLedger(path=db_path, **kwargs)


# ---------------------------------------------------------------------------
# The defect this module exists to fix
# ---------------------------------------------------------------------------


class TestSurvivesRestart:
    def test_spent_balance_does_not_come_back(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000)
        ledger.customer_debit_to_fees("acme", 1_000_000)
        ledger.close()

        assert _fresh(db_path).customer_balance("acme") == 4_000_000

    def test_every_bucket_survives(self, db_path):
        ledger = _fresh(db_path)
        ledger.deposit_fee(1_000_000)
        ledger.fund_incentive_budget(3_000_000)
        ledger.post_bond("node-a", 2_000_000)
        ledger.customer_deposit("acme", 5_000_000)
        ledger.customer_debit_to_fees("acme", 1_000_000)
        ledger.pay_from_pool("node-a", 500_000)
        ledger.slash_bond("node-a", 250_000)
        before = (
            ledger.operator_pool_micro,
            ledger.insurance_pool_micro,
            ledger.treasury_micro,
            ledger.customer_balance("acme"),
            ledger.account("node-a").bond_micro,
            ledger.account("node-a").paid_total_micro,
            ledger.account("node-a").slashed_total_micro,
            ledger.total_held_micro,
        )
        ledger.close()

        restored = _fresh(db_path)
        after = (
            restored.operator_pool_micro,
            restored.insurance_pool_micro,
            restored.treasury_micro,
            restored.customer_balance("acme"),
            restored.account("node-a").bond_micro,
            restored.account("node-a").paid_total_micro,
            restored.account("node-a").slashed_total_micro,
            restored.total_held_micro,
        )
        assert after == before
        assert restored.check_solvency()
        assert restored.audit_solvency()

    def test_deposit_and_withdrawal_totals_are_rederived(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000)
        ledger.customer_refund("acme")
        ledger.close()

        restored = _fresh(db_path)
        # Solvency is held == deposited - withdrawn; if either counter came
        # back wrong the identity breaks even though every bucket is zero.
        assert restored.total_held_micro == 0
        assert restored.check_solvency()
        assert restored._total_deposited == 5_000_000
        assert restored._total_withdrawn == 5_000_000

    def test_paid_and_slashed_totals_are_not_confused_with_refunds(self, db_path):
        ledger = _fresh(db_path)
        ledger.post_bond("node-a", 4_000_000)
        ledger.slash_bond("node-a", 1_000_000)
        ledger.refund_bond("node-a")  # debits the same account, into custody
        ledger.close()

        acct = _fresh(db_path).account("node-a")
        assert acct.slashed_total_micro == 1_000_000  # not 4_000_000
        assert acct.bond_micro == 0


class TestNonBookState:
    """Claims, offense counts and eviction are durable too."""

    def test_accrued_claim_survives(self, db_path):
        ledger = _fresh(db_path)
        ledger.account("node-a").earned_claim_micro = 750_000
        ledger.close()

        assert _fresh(db_path).account("node-a").earned_claim_micro == 750_000

    def test_eviction_survives(self, db_path):
        ledger = _fresh(db_path)
        acct = ledger.account("node-a")
        acct.evicted = True
        acct.audit_offense_count = 3
        ledger.close()

        restored = _fresh(db_path).account("node-a")
        assert restored.evicted is True
        assert restored.audit_offense_count == 3

    def test_evicted_node_with_no_bond_is_still_restored(self, db_path):
        """A node that forfeited everything has no bond account left."""
        ledger = _fresh(db_path)
        ledger.post_bond("node-a", 1_000_000)
        ledger.forfeit_bond_to_insurance("node-a")
        ledger.account("node-a").evicted = True
        ledger.close()

        restored = _fresh(db_path)
        assert restored.account("node-a").evicted is True
        assert "node-a" in {a.node_id for a in restored.accounts()}

    def test_claims_are_not_claims_on_custody(self, db_path):
        """An accrued claim must not appear in the solvency identity.

        It is money owed but not yet funded. Booking it as a liability
        would report insolvency for every network that has ever accrued.
        """
        ledger = _fresh(db_path)
        ledger.account("node-a").earned_claim_micro = 999_000_000
        assert ledger.check_solvency()
        assert ledger.audit_solvency()
        assert ledger.total_held_micro == 0


# ---------------------------------------------------------------------------
# Deposit replay
# ---------------------------------------------------------------------------


class TestExternalRef:
    def test_replayed_deposit_is_refused(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000, external_ref="0xabc:0")
        with pytest.raises(DuplicateExternalRef):
            ledger.customer_deposit("acme", 5_000_000, external_ref="0xabc:0")
        assert ledger.customer_balance("acme") == 5_000_000

    def test_replay_survives_a_restart(self, db_path):
        """The in-memory seen-set was the thing that did not survive."""
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000, external_ref="0xabc:0")
        ledger.close()

        restored = _fresh(db_path)
        with pytest.raises(DuplicateExternalRef):
            restored.customer_deposit("acme", 5_000_000, external_ref="0xabc:0")
        assert restored.customer_balance("acme") == 5_000_000

    def test_two_transfers_in_one_tx_are_two_events(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 1_000_000, external_ref="0xabc:0")
        ledger.customer_deposit("acme", 2_000_000, external_ref="0xabc:1")
        assert ledger.customer_balance("acme") == 3_000_000


# ---------------------------------------------------------------------------
# Failure atomicity
# ---------------------------------------------------------------------------


class TestNothingMovesOnFailure:
    def test_overdraft_writes_no_transaction(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 1_000_000)
        before = _txn_count(ledger)
        with pytest.raises(LedgerError):
            ledger.customer_debit_to_fees("acme", 2_000_000)
        assert _txn_count(ledger) == before
        assert ledger.customer_balance("acme") == 1_000_000
        assert ledger.audit_solvency()

    def test_duplicate_ref_writes_no_transaction(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 1_000_000, external_ref="0xabc:0")
        before = _txn_count(ledger)
        with pytest.raises(DuplicateExternalRef):
            ledger.customer_deposit("acme", 1_000_000, external_ref="0xabc:0")
        assert _txn_count(ledger) == before

    def test_failed_apply_is_reversed_not_erased(self, db_path, monkeypatch):
        """If memory refuses the movement, the journal corrects itself."""
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 1_000_000)
        before = _txn_count(ledger)

        def boom(*_args, **_kwargs):
            raise RuntimeError("in-memory apply failed")

        monkeypatch.setattr(
            "ltp.incentives.StablecoinLedger.fund_incentive_budget", boom, raising=True
        )
        with pytest.raises(RuntimeError):
            ledger.fund_incentive_budget(5_000_000)

        # Two rows, not zero: the attempt and its reversal. History is
        # corrected, never deleted.
        assert _txn_count(ledger) == before + 2
        assert ledger.journal.balance(POOL_OPERATOR).posted == 0
        assert ledger.audit_solvency()

    def test_zero_amount_movements_write_nothing(self, db_path):
        ledger = _fresh(db_path)
        before = _txn_count(ledger)
        assert ledger.pay_from_pool("node-a", 1_000_000) == 0  # empty pool
        assert ledger.customer_refund("nobody") == 0
        assert ledger.slash_bond("node-a", 500_000) == 0
        assert _txn_count(ledger) == before


# ---------------------------------------------------------------------------
# The auditors
# ---------------------------------------------------------------------------


class TestDrift:
    def test_corrupted_memory_is_caught(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000)
        ledger.fund_incentive_budget(1_000_000)

        assert ledger.detect_drift() == []
        ledger._customer_balances["acme"] = 9_999_999  # behind the ledger's back

        reports = ledger.detect_drift()
        assert [r.account for r in reports] == [customer_account("acme")]
        assert reports[0].delta == 9_999_999 - 5_000_000

    def test_pool_drift_is_caught(self, db_path):
        ledger = _fresh(db_path)
        ledger.fund_incentive_budget(1_000_000)
        ledger.operator_pool_micro += 1
        assert [r.account for r in ledger.detect_drift()] == [POOL_OPERATOR]

    def test_phantom_in_memory_account_is_caught(self, db_path):
        """Memory claiming a bond the journal never recorded."""
        ledger = _fresh(db_path)
        ledger.account("ghost").bond_micro = 4_000_000
        reports = ledger.detect_drift()
        assert [r.account for r in reports] == [bond_account("ghost")]
        assert reports[0].recomputed_posted == 0


class TestSolvencyAudit:
    def test_forged_entry_is_caught_by_the_audit(self, db_path):
        """The in-memory check cannot see this; that is the whole point."""
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 5_000_000)
        assert ledger.audit_solvency()

        _forge_credit(ledger.journal, customer_account("acme"), 1_000_000)

        assert ledger.audit_solvency() is False
        # Memory is self-consistent and still reports healthy -- which is
        # exactly why the audit has to replay entries instead.
        assert ledger.check_solvency() is True

    def test_pools_and_bonds_are_all_claims_on_custody(self, db_path):
        ledger = _fresh(db_path)
        ledger.deposit_fee(1_000_000)
        ledger.post_bond("node-a", 2_000_000)
        ledger.customer_deposit("acme", 3_000_000)
        j = ledger.journal
        custody = j.balance(ASSET_CUSTODY).posted
        claims = sum(
            j.balance(a).posted
            for a in (
                POOL_OPERATOR,
                POOL_INSURANCE,
                POOL_TREASURY,
                bond_account("node-a"),
                customer_account("acme"),
            )
        )
        assert custody == claims == 6_000_000
        assert ledger.audit_solvency()


# ---------------------------------------------------------------------------
# Compatibility with everything already built on the ledger
# ---------------------------------------------------------------------------


class TestDropInCompatibility:
    def test_settlement_engine_runs_unchanged(self, db_path):
        ledger = _fresh(db_path, config=IncentiveConfig())
        ledger.fund_incentive_budget(10_000_000)
        engine = StableNodeIncentive(ledger)
        engine.accrue_report(
            MeteredWorkReport(
                node_id="node-a",
                epoch=1,
                bytes_stored=10**9,
                seconds_stored=3600,
                bytes_served=10**8,
                audits_passed=10,
                audits_total=10,
            )
        )
        claim = ledger.account("node-a").earned_claim_micro
        assert claim > 0

        snapshot = engine.settle_epoch(1)
        assert snapshot.total_paid_micro == min(claim, 10_000_000)
        assert ledger.check_solvency()
        assert ledger.audit_solvency()

    def test_settlement_survives_a_restart_mid_epoch(self, db_path):
        """Accrue, crash, restart, settle. The claim must still be owed."""
        ledger = _fresh(db_path)
        ledger.fund_incentive_budget(10_000_000)
        StableNodeIncentive(ledger).accrue_report(
            MeteredWorkReport(
                node_id="node-a",
                epoch=1,
                bytes_stored=10**9,
                seconds_stored=3600,
                bytes_served=10**8,
                audits_passed=10,
                audits_total=10,
            )
        )
        claim = ledger.account("node-a").earned_claim_micro
        assert claim > 0
        ledger.close()

        restored = _fresh(db_path)
        assert restored.account("node-a").earned_claim_micro == claim
        snapshot = StableNodeIncentive(restored).settle_epoch(1)
        assert snapshot.total_paid_micro == min(claim, 10_000_000)
        assert restored.account("node-a").paid_total_micro == snapshot.total_paid_micro
        assert restored.audit_solvency()

    def test_evicted_node_stays_evicted_across_restart(self, db_path):
        ledger = _fresh(db_path)
        ledger.account("node-a").evicted = True
        ledger.close()

        restored = _fresh(db_path)
        accrued = StableNodeIncentive(restored).compensate("node-a", 10**9, 3600, 10**8)
        assert accrued == 0

    def test_shared_journal_is_not_closed_by_the_ledger(self, db_path):
        journal = LedgerJournal(path=db_path)
        ledger = DurableStablecoinLedger(journal=journal)
        ledger.customer_deposit("acme", 1_000_000)
        ledger.close()
        assert journal.balance(customer_account("acme")).posted == 1_000_000
        journal.close()

    def test_journal_and_path_together_are_refused(self, db_path):
        with pytest.raises(LedgerError):
            DurableStablecoinLedger(journal=LedgerJournal(), path=db_path)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_deposits_and_debits_stay_exact(self, db_path):
        ledger = _fresh(db_path)
        ledger.customer_deposit("acme", 10_000_000)

        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        errors: list[BaseException] = []

        def deposit():
            try:
                for _ in range(50):
                    ledger.customer_deposit("acme", 1_000)
            except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
                errors.append(exc)

        def debit():
            try:
                for _ in range(50):
                    ledger.customer_debit_to_fees("acme", 1_000)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        try:
            threads = [threading.Thread(target=deposit) for _ in range(2)]
            threads += [threading.Thread(target=debit) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old_interval)

        assert errors == []
        # 100 deposits in, 100 debits out, netting to the opening balance.
        assert ledger.customer_balance("acme") == 10_000_000
        assert ledger.detect_drift() == []
        assert ledger.audit_solvency()
        assert ledger.check_solvency()

    def test_concurrent_state_survives_a_restart(self, db_path):
        ledger = _fresh(db_path)
        for i in range(20):
            ledger.customer_deposit("acme", 1_000, external_ref=f"0xabc:{i}")
        expected = ledger.customer_balance("acme")
        ledger.close()
        assert _fresh(db_path).customer_balance("acme") == expected


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _txn_count(ledger: DurableStablecoinLedger) -> int:
    return int(ledger.journal._db.execute("SELECT COUNT(*) AS n FROM transactions").fetchone()["n"])


def _forge_credit(journal: LedgerJournal, account: str, amount_micro: int) -> None:
    """Write a single unbalanced entry straight into the journal.

    Deliberately bypasses ``post()`` -- this is what tampering looks like,
    and the audit has to notice it without any help from the API.
    """
    db: sqlite3.Connection = journal._db
    cur = db.execute(
        "INSERT INTO transactions (created_at, description, currency) VALUES (0, 'forged', ?)",
        (journal.currency,),
    )
    db.execute(
        "INSERT INTO entries (transaction_id, account, amount_micro, direction, state, created_at) "
        "VALUES (?, ?, ?, ?, 'posted', 0)",
        (int(cur.lastrowid), account, amount_micro, AccountKind.CREDIT),
    )
    db.commit()


def test_posting_helpers_reject_negative_amounts():
    with pytest.raises(Exception):
        Posting(account=POOL_OPERATOR, amount_micro=-1, direction=AccountKind.DEBIT)
