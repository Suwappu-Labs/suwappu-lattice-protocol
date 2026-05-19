"""Stress scenarios 1 & 10: Replay protection."""

import pytest

from tests.stress.conftest import make_raw_log, make_service


class TestScenario1_DuplicateEvents:
    """Same event emitted twice — gateway rejects replay on second attempt."""

    def test_exact_duplicate_rejected(self, stress_kp):
        log = make_raw_log("0xdup", 100, 0)
        svc = make_service(stress_kp, raw_logs=[log])

        r1 = svc.tick()
        assert r1.events_accepted == 1

        r2 = svc.tick()
        assert r2.events_observed == 1
        assert r2.events_rejected == 1
        assert r2.events_accepted == 0

    def test_100_duplicates_all_rejected(self, stress_kp):
        log = make_raw_log("0xdup100", 100, 0)
        # current_block must be high enough that safe_block (current - finality_depth)
        # stays ahead of the cursor for 100+ ticks.
        svc = make_service(stress_kp, raw_logs=[log], current_block=1000)

        svc.tick()  # first: accepted
        for i in range(100):
            r = svc.tick()
            assert r.events_rejected == 1, f"duplicate {i + 1} should be rejected"
            assert r.events_accepted == 0

    def test_different_log_index_is_not_duplicate(self, stress_kp):
        """Same tx_hash but different log_index = different event."""
        log1 = make_raw_log("0xmulti", 100, 0)
        log2 = make_raw_log("0xmulti", 100, 1)  # different log_index

        svc = make_service(stress_kp, raw_logs=[log1])
        r1 = svc.tick()
        assert r1.events_accepted == 1

        # Replace logs with log2
        svc._listener._fetch_logs = lambda fb, tb: [log2]
        r2 = svc.tick()
        assert r2.events_accepted == 1  # different event_id


class TestScenario10_ReplayedTxHashDifferentPayload:
    """Same TX hash with different payload — gateway detects via event_id."""

    def test_same_tx_hash_different_payload(self, stress_kp):
        log1 = make_raw_log("0xsame_tx", 100, 0, payload_hash="sha3-256:payload_A")
        log2 = make_raw_log("0xsame_tx", 100, 0, payload_hash="sha3-256:payload_B")

        # event_id = H(chain_id + tx_hash + log_index) — same for both
        svc = make_service(stress_kp, raw_logs=[log1])
        r1 = svc.tick()
        assert r1.events_accepted == 1

        svc._listener._fetch_logs = lambda fb, tb: [log2]
        r2 = svc.tick()
        assert r2.events_rejected == 1  # same event_id → replay
