"""Stress scenarios 5, 6: Bad payloads and malformed commitments."""

from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log, make_service


class TestScenario5_BadPayloads:
    """Malformed event data — gateway rejects at validation."""

    def test_empty_payload_hash_rejected(self, stress_kp):
        log = make_raw_log("0xbad1", 100, 0, payload_hash="")
        svc = make_service(stress_kp, raw_logs=[log])
        r = svc.tick()
        assert r.events_rejected == 1

    def test_no_algo_prefix_rejected(self, stress_kp):
        log = make_raw_log("0xbad2", 100, 0, payload_hash="notahash")
        svc = make_service(stress_kp, raw_logs=[log])
        r = svc.tick()
        assert r.events_rejected == 1

    def test_empty_sender_rejected(self, stress_kp):
        log = make_raw_log("0xbad3", 100, 0, sender="")
        svc = make_service(stress_kp, raw_logs=[log])
        r = svc.tick()
        assert r.events_rejected == 1

    def test_empty_recipient_rejected(self, stress_kp):
        log = make_raw_log("0xbad4", 100, 0, recipient="")
        svc = make_service(stress_kp, raw_logs=[log])
        r = svc.tick()
        assert r.events_rejected == 1

    def test_valid_payload_accepted(self, stress_kp):
        """Control: properly formed event passes."""
        log = make_raw_log("0xgood", 100, 0, payload_hash="sha3-256:valid")
        svc = make_service(stress_kp, raw_logs=[log])
        r = svc.tick()
        assert r.events_accepted == 1


class TestScenario6_MalformedCommitments:
    """Devnet contract rejects malformed commitment — anchor_fn raises."""

    def test_contract_revert_enters_retry_then_fails(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        delivered = [False]

        def one_shot_fetch(fb, tb):
            if not delivered[0]:
                delivered[0] = True
                return [make_raw_log("0xmalformed", 100, 0)]
            return []

        anchor_fn = MagicMock(side_effect=RuntimeError("Transaction reverted"))
        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            max_retries=2,
        )

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=one_shot_fetch,
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        svc.tick()  # fail → retry
        assert svc.retry_queue_size >= 1

        for _ in range(10):
            svc.tick()
            if svc.retry_queue_size == 0:
                break
        assert svc.retry_queue_size == 0
