"""Bidirectional integration tests: Base Sepolia ↔ GSX.

Tests both directions of the gateway pipeline with independent configs,
replay DBs, and attestation writers.
"""

from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def base_to_gsx_kp():
    return KeyPair.generate("base-to-gsx-gateway")


@pytest.fixture(scope="module")
def gsx_to_base_kp():
    return KeyPair.generate("gsx-to-base-gateway")


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


class TestBaseSepoliaToGSX:
    """Base Sepolia (84532) → GSX Testnet (103115120)."""

    def test_base_event_anchored_to_gsx(self, base_to_gsx_kp):
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
        anchor_fn = MagicMock(return_value="0xgsx_anchor_tx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=base_to_gsx_kp,
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
        assert att.verify(base_to_gsx_kp.vk)


class TestGSXToBaseSepolia:
    """GSX Testnet (103115120) → Base Sepolia (84532)."""

    def test_gsx_event_anchored_to_base(self, gsx_to_base_kp):
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

        gsx_log = _make_raw_log(
            "0xgsx_tx_001",
            500,
            "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
        )
        anchor_fn = MagicMock(return_value="0xbase_anchor_tx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=gsx_to_base_kp,
            fetch_logs=lambda fb, tb: [gsx_log],
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
        assert att.verify(gsx_to_base_kp.vk)


class TestBidirectionalIsolation:
    """Both directions running simultaneously don't interfere."""

    def test_independent_replay_dbs(self, base_to_gsx_kp, gsx_to_base_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        base_config = GatewayVMConfig(
            source_chain_id=84532,
            source_bridge_contract="0x79eF1B7914f98C5C1404617449AB1f377c475996",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )
        gsx_config = GatewayVMConfig(
            source_chain_id=103115120,
            source_bridge_contract="0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
            finality_depth=6,
            dest_chain_id=84532,
            replay_db_path=":memory:",
        )

        base_log = _make_raw_log("0xshared_hash", 100, "0x79eF1B7914f98C5C1404617449AB1f377c475996")
        gsx_log = _make_raw_log("0xshared_hash", 100, "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4")

        base_anchor = MagicMock(return_value="0xb")
        gsx_anchor = MagicMock(return_value="0xg")

        svc_base = GatewayVMService(
            config=base_config,
            operator_keypair=base_to_gsx_kp,
            fetch_logs=lambda fb, tb: [base_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=base_anchor,
            is_signer_authorized=lambda: True,
        )
        svc_gsx = GatewayVMService(
            config=gsx_config,
            operator_keypair=gsx_to_base_kp,
            fetch_logs=lambda fb, tb: [gsx_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=gsx_anchor,
            is_signer_authorized=lambda: True,
        )

        r_base = svc_base.tick()
        r_gsx = svc_gsx.tick()

        # Both accept independently — same tx_hash on different chains is not a replay
        assert r_base.events_accepted == 1
        assert r_gsx.events_accepted == 1
        assert base_anchor.call_count == 1
        assert gsx_anchor.call_count == 1
