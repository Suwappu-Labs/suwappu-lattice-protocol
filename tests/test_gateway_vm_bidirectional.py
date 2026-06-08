"""Bidirectional integration tests: Base Sepolia ↔ SUWAPPU.

Tests both directions of the gateway pipeline with independent configs,
replay DBs, and attestation writers.
"""

from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def base_to_suwappu_kp():
    return KeyPair.generate("base-to-suwappu-gateway")


@pytest.fixture(scope="module")
def suwappu_to_base_kp():
    return KeyPair.generate("suwappu-to-base-gateway")


def _make_raw_log(tx_hash, block_number, contract_address):
    return {
        "transactionHash": tx_hash,
        "blockNumber": block_number,
        "logIndex": 0,
        "address": contract_address,
        "event": "AnchorCreated",
        "args": {
            "sender": "0xsender",
            "recipient": "0xrecipient",
            "payloadHash": "sha3-256:data",
            "amount": 1_000_000,
            "nonce": 0,
        },
    }


class TestBaseSepoliaToSUWAPPU:
    """Base Sepolia (84532) → SUWAPPU Testnet (103115120)."""

    def test_base_event_anchored_to_suwappu(self, base_to_suwappu_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x79eF1B7914f98C5C1404617449AB1f377c475996",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        base_log = _make_raw_log(
            "0xbase_tx_001",
            100,
            "0x79eF1B7914f98C5C1404617449AB1f377c475996",
        )
        anchor_fn = MagicMock(return_value="0xsuwappu_anchor_tx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=base_to_suwappu_kp,
            fetch_logs=lambda fb, tb: [base_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()
        assert result.events_accepted == 1

        att = anchor_fn.call_args[0][0]
        assert att.source_chain_id == 84532
        assert att.dest_chain_id == 103115120
        assert att.verify(base_to_suwappu_kp.vk)


class TestSUWAPPUToBaseSepolia:
    """SUWAPPU Testnet (103115120) → Base Sepolia (84532)."""

    def test_suwappu_event_anchored_to_base(self, suwappu_to_base_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=103115120,
            source_bridge_contract="0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
            finality_depth=6,
            dest_chain_id=84532,
            replay_db_path=":memory:",
        )

        suwappu_log = _make_raw_log(
            "0xsuwappu_tx_001",
            500,
            "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
        )
        anchor_fn = MagicMock(return_value="0xbase_anchor_tx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=suwappu_to_base_kp,
            fetch_logs=lambda fb, tb: [suwappu_log],
            get_source_block_number=lambda: 600,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()
        assert result.events_accepted == 1

        att = anchor_fn.call_args[0][0]
        assert att.source_chain_id == 103115120
        assert att.dest_chain_id == 84532
        assert att.verify(suwappu_to_base_kp.vk)


class TestBidirectionalIsolation:
    """Both directions running simultaneously don't interfere."""

    def test_independent_replay_dbs(self, base_to_suwappu_kp, suwappu_to_base_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        base_config = GatewayVMConfig(
            source_chain_id=84532,
            source_bridge_contract="0x79eF1B7914f98C5C1404617449AB1f377c475996",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )
        suwappu_config = GatewayVMConfig(
            source_chain_id=103115120,
            source_bridge_contract="0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
            finality_depth=6,
            dest_chain_id=84532,
            replay_db_path=":memory:",
        )

        base_log = _make_raw_log("0xshared_hash", 100, "0x79eF1B7914f98C5C1404617449AB1f377c475996")
        suwappu_log = _make_raw_log("0xshared_hash", 100, "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4")

        base_anchor = MagicMock(return_value="0xb")
        suwappu_anchor = MagicMock(return_value="0xg")

        svc_base = GatewayVMService(
            config=base_config,
            operator_keypair=base_to_suwappu_kp,
            fetch_logs=lambda fb, tb: [base_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=base_anchor,
            is_signer_authorized=lambda: True,
        )
        svc_suwappu = GatewayVMService(
            config=suwappu_config,
            operator_keypair=suwappu_to_base_kp,
            fetch_logs=lambda fb, tb: [suwappu_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=suwappu_anchor,
            is_signer_authorized=lambda: True,
        )

        r_base = svc_base.tick()
        r_suwappu = svc_suwappu.tick()

        # Both accept independently — same tx_hash on different chains is not a replay
        assert r_base.events_accepted == 1
        assert r_suwappu.events_accepted == 1
        assert base_anchor.call_count == 1
        assert suwappu_anchor.call_count == 1
