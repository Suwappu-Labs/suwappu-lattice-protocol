"""Tests for the durable double-entry journal.

The point of this module is that it survives things the in-memory ledger
did not, so the tests are written to *break* it: corrupt the cache behind
the detector's back, forge an entry under the solvency check, replay a
deposit, restart mid-flight. A test that can only pass is not evidence.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading

import pytest

from ltp.ledger_journal import (
    ASSET_CUSTODY,
    AccountKind,
    DuplicateExternalRef,
    IdempotencyConflict,
    JournalError,
    LedgerJournal,
    Posting,
    UnbalancedTransaction,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "ledger.db")


@pytest.fixture
def journal(db_path):
    j = LedgerJournal(db_path)
    j.ensure_account("customer:alice", AccountKind.CREDIT)
    j.ensure_account("pool:operator", AccountKind.CREDIT)
    yield j
    j.close()


def _deposit(j, amount, account="customer:alice", ref=None):
    return j.post(
        "deposit",
        [
            Posting(ASSET_CUSTODY, amount, AccountKind.DEBIT),
            Posting(account, amount, AccountKind.CREDIT),
        ],
        external_ref=ref,
    )


class TestBalancedOrAbsent:
    def test_balanced_transaction_posts(self, journal):
        _deposit(journal, 5_000_000)
        assert journal.balance("customer:alice").posted == 5_000_000
        assert journal.balance(ASSET_CUSTODY).posted == 5_000_000

    def test_unbalanced_transaction_is_refused(self, journal):
        with pytest.raises(UnbalancedTransaction):
            journal.post(
                "mint from nothing",
                [Posting("customer:alice", 999, AccountKind.CREDIT)],
            )

    def test_unbalanced_transaction_leaves_nothing_behind(self, journal):
        """The refusal must not leak a half-written transaction row."""
        before = journal._db.execute("SELECT COUNT(*) c FROM transactions").fetchone()["c"]
        with pytest.raises(UnbalancedTransaction):
            journal.post(
                "mint",
                [
                    Posting(ASSET_CUSTODY, 10, AccountKind.DEBIT),
                    Posting("customer:alice", 11, AccountKind.CREDIT),
                ],
            )
        after = journal._db.execute("SELECT COUNT(*) c FROM transactions").fetchone()["c"]
        assert before == after

    def test_unknown_account_is_refused(self, journal):
        with pytest.raises(JournalError):
            journal.post(
                "typo",
                [
                    Posting(ASSET_CUSTODY, 5, AccountKind.DEBIT),
                    Posting("customer:nobody", 5, AccountKind.CREDIT),
                ],
            )


class TestDurability:
    """The defect this module exists for, pinned as a regression."""

    def test_spent_balance_stays_spent_across_restart(self, db_path):
        j = LedgerJournal(db_path)
        j.ensure_account("customer:alice", AccountKind.CREDIT)
        j.ensure_account("pool:operator", AccountKind.CREDIT)
        _deposit(j, 5_000_000)
        j.post(
            "inference bill",
            [
                Posting("customer:alice", 1_000_000, AccountKind.DEBIT),
                Posting("pool:operator", 1_000_000, AccountKind.CREDIT),
            ],
        )
        j.close()

        reopened = LedgerJournal(db_path)
        # The in-memory ledger reported the full 5.00 here — the spend
        # vanished with the process.
        assert reopened.balance("customer:alice").posted == 4_000_000
        assert reopened.check_solvency()
        reopened.close()

    def test_deposit_cannot_be_credited_twice_across_restart(self, db_path):
        ref = "0xdeadbeef:0"
        j = LedgerJournal(db_path)
        j.ensure_account("customer:alice", AccountKind.CREDIT)
        _deposit(j, 5_000_000, ref=ref)
        j.close()

        reopened = LedgerJournal(db_path)
        reopened.ensure_account("customer:alice", AccountKind.CREDIT)
        with pytest.raises(DuplicateExternalRef):
            _deposit(reopened, 5_000_000, ref=ref)
        assert reopened.balance("customer:alice").posted == 5_000_000
        reopened.close()

    def test_dedup_key_is_tx_hash_plus_log_index(self, journal):
        """Two transfers in one tx are distinct events, not a duplicate."""
        _deposit(journal, 1_000, ref="0xabc:0")
        _deposit(journal, 2_000, ref="0xabc:1")
        assert journal.balance("customer:alice").posted == 3_000
        with pytest.raises(DuplicateExternalRef):
            _deposit(journal, 2_000, ref="0xabc:1")


class TestCorrectionsByReversal:
    def test_reversal_nets_to_zero_and_keeps_both_events(self, journal):
        txn = _deposit(journal, 1_000_000)
        journal.reverse(txn)
        assert journal.balance("customer:alice").posted == 0
        rows = journal._db.execute("SELECT COUNT(*) c FROM transactions").fetchone()
        assert rows["c"] == 2, "the original must survive the correction"

    def test_reversal_points_at_the_original(self, journal):
        txn = _deposit(journal, 500)
        rev = journal.reverse(txn)
        row = journal._db.execute(
            "SELECT reverses_id FROM transactions WHERE id = ?", (rev,)
        ).fetchone()
        assert row["reverses_id"] == txn


class TestDriftDetector:
    def test_clean_journal_reports_no_drift(self, journal):
        _deposit(journal, 1_000)
        assert journal.detect_drift() == []

    def test_corrupted_cache_is_detected_and_distrusted(self, journal):
        """Teeth: poison the cache behind the detector's back."""
        _deposit(journal, 1_000)
        journal._db.execute(
            "UPDATE balance_cache SET posted_credits = posted_credits + 70 "
            "WHERE account = 'customer:alice'"
        )
        journal._db.commit()

        drift = journal.detect_drift()
        assert len(drift) == 1
        assert drift[0].account == "customer:alice"
        assert drift[0].delta == 70

        # Reads now fall through to the journal, which is still correct.
        assert journal.balance("customer:alice").posted == 1_000

    def test_detect_drift_can_report_without_distrusting(self, journal):
        _deposit(journal, 1_000)
        journal._db.execute(
            "UPDATE balance_cache SET posted_credits = 999 WHERE account = 'customer:alice'"
        )
        journal._db.commit()
        assert journal.detect_drift(distrust=False)
        row = journal._db.execute(
            "SELECT trusted FROM balance_cache WHERE account = 'customer:alice'"
        ).fetchone()
        assert row["trusted"] == 1


class TestSolvency:
    def test_balanced_journal_is_solvent(self, journal):
        _deposit(journal, 5_000_000)
        journal.post(
            "bill",
            [
                Posting("customer:alice", 10, AccountKind.DEBIT),
                Posting("pool:operator", 10, AccountKind.CREDIT),
            ],
        )
        assert journal.check_solvency()

    def test_forged_entry_breaks_solvency(self, journal):
        """Teeth: the check must fail when the journal itself is doctored."""
        txn = _deposit(journal, 1_000)
        journal._db.execute(
            "INSERT INTO entries (transaction_id, account, amount_micro, "
            "direction, state, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (txn, "customer:alice", 500, AccountKind.CREDIT, "posted", 0.0),
        )
        journal._db.commit()
        assert not journal.check_solvency()

    def test_payout_out_of_custody_stays_solvent(self, journal):
        _deposit(journal, 1_000)
        journal.post(
            "payout",
            [
                Posting("customer:alice", 400, AccountKind.DEBIT),
                Posting(ASSET_CUSTODY, 400, AccountKind.CREDIT),
            ],
        )
        assert journal.balance(ASSET_CUSTODY).posted == 600
        assert journal.check_solvency()


class TestPendingAndPosted:
    def test_pending_entries_do_not_move_posted(self, journal):
        journal.post(
            "hold",
            [
                Posting(ASSET_CUSTODY, 100, AccountKind.DEBIT),
                Posting("customer:alice", 100, AccountKind.CREDIT),
            ],
            state="pending",
        )
        b = journal.balance("customer:alice")
        assert b.posted == 0
        assert b.pending_credits == 100

    def test_available_subtracts_uncleared_holds(self, journal):
        """A hold reduces what is still spendable.

        An earlier version of this test asserted `x or y`, which passes
        whichever way the sign goes — and it was hiding a real sign error
        in `available`, where a hold *increased* the spendable balance.
        Asserted exactly now.
        """
        _deposit(journal, 1_000)
        journal.post(
            "hold against balance",
            [
                Posting("customer:alice", 300, AccountKind.DEBIT),
                Posting("pool:operator", 300, AccountKind.CREDIT),
            ],
            state="pending",
        )
        b = journal.balance("customer:alice")
        assert b.posted == 1_000, "a hold must not move the settled balance"
        assert b.available == 700, "a hold must reduce what is spendable"

    def test_available_on_a_debit_normal_account(self, journal):
        """Same rule, mirrored: a pending credit reserves custody assets."""
        _deposit(journal, 1_000)
        journal.post(
            "reserve for payout",
            [
                Posting("pool:operator", 250, AccountKind.DEBIT),
                Posting(ASSET_CUSTODY, 250, AccountKind.CREDIT),
            ],
            state="pending",
        )
        custody = journal.balance(ASSET_CUSTODY)
        assert custody.posted == 1_000
        assert custody.available == 750


class TestIdempotency:
    def test_first_claim_returns_none(self, journal):
        assert journal.begin_idempotent("pay", "k", {"a": 1}) is None

    def test_in_flight_duplicate_conflicts(self, journal):
        journal.begin_idempotent("pay", "k", {"a": 1})
        with pytest.raises(IdempotencyConflict):
            journal.begin_idempotent("pay", "k", {"a": 1})

    def test_parameter_reuse_is_detected(self, journal):
        journal.begin_idempotent("pay", "k", {"a": 1})
        with pytest.raises(IdempotencyConflict):
            journal.begin_idempotent("pay", "k", {"a": 2})

    def test_completed_request_replays_its_response(self, journal):
        journal.begin_idempotent("pay", "k", {"a": 1})
        journal.complete_idempotent("pay", "k", 200, {"ok": True})
        rec = journal.begin_idempotent("pay", "k", {"a": 1})
        assert rec is not None
        assert rec.response_code == 200
        assert rec.response_body == {"ok": True}

    def test_stored_failures_replay_too(self, journal):
        """Replaying a 500 is the contract, not a bug.

        A retry that silently succeeds where the first attempt failed is
        a second charge.
        """
        journal.begin_idempotent("pay", "k", {"a": 1})
        journal.complete_idempotent("pay", "k", 500, {"error": "boom"})
        rec = journal.begin_idempotent("pay", "k", {"a": 1})
        assert rec.response_code == 500

    def test_survives_restart(self, db_path):
        j = LedgerJournal(db_path)
        j.begin_idempotent("pay", "k", {"a": 1})
        j.complete_idempotent("pay", "k", 200, {"ok": True})
        j.close()
        reopened = LedgerJournal(db_path)
        rec = reopened.begin_idempotent("pay", "k", {"a": 1})
        assert rec is not None and rec.response_code == 200
        reopened.close()

    def test_recovery_point_records_partial_progress(self, journal):
        journal.begin_idempotent("pay", "k", {"a": 1})
        journal.set_recovery_point("pay", "k", "charge_created")
        assert journal.idempotency_record("pay", "k").recovery_point == "charge_created"

    def test_reaper_deletes_only_expired_keys(self, journal):
        journal.begin_idempotent("pay", "old", {"a": 1})
        journal.complete_idempotent("pay", "old", 200, None)
        journal.begin_idempotent("pay", "new", {"a": 1})
        # Pretend we are a day and a half in the future.
        import time as _t

        removed = journal.reap_idempotency_keys(now=_t.time() + 36 * 3600)
        assert removed == 2
        assert journal.idempotency_record("pay", "old") is None

    def test_abandoned_keys_surface_for_the_completer(self, journal):
        journal.begin_idempotent("pay", "stuck", {"a": 1})
        journal._db.execute("UPDATE idempotency_keys SET locked_at = 0 WHERE key = 'stuck'")
        journal._db.commit()
        stuck = journal.abandoned_keys()
        assert [r.key for r in stuck] == ["stuck"]


class TestConcurrency:
    def test_parallel_posts_all_land_and_stay_solvent(self, journal):
        """Every accepted transaction must appear exactly once."""
        errors: list[Exception] = []

        def worker(n: int) -> None:
            try:
                for i in range(20):
                    journal.post(
                        f"w{n}-{i}",
                        [
                            Posting(ASSET_CUSTODY, 10, AccountKind.DEBIT),
                            Posting("customer:alice", 10, AccountKind.CREDIT),
                        ],
                    )
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old)

        assert not errors, errors
        # Exact accounting, not just "still solvent".
        assert journal.balance("customer:alice").posted == 4 * 20 * 10
        assert journal.check_solvency()
        assert journal.detect_drift() == []
