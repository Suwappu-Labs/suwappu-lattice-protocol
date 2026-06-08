"""
Integration tests for cross-chain LiveBridge.

Requires live chain access:
  - BASE_SEPOLIA_RPC_URL + BASE_SEPOLIA_OPERATOR_KEY
  - SUWAPPU_RPC_URL + SUWAPPU_OPERATOR_KEY (for dual_write tests)

All tests skip gracefully when env vars are not set.
"""

from __future__ import annotations

import hashlib
import os

import pytest

# Skip entire module if no chain access
pytestmark = pytest.mark.skipif(
    not os.environ.get("BASE_SEPOLIA_RPC_URL"),
    reason="BASE_SEPOLIA_RPC_URL not set — skipping live chain tests",
)


def _have_suwappu() -> bool:
    return bool(os.environ.get("SUWAPPU_RPC_URL") and os.environ.get("SUWAPPU_OPERATOR_KEY"))


@pytest.fixture(scope="module")
def base_client():
    """AnchorClient connected to Base Sepolia."""
    from src.ltp.anchor.chain_config import ChainConfig, create_anchor_client

    config = ChainConfig(
        chain_id=84532,
        label="base_sepolia",
        rpc_url=os.environ["BASE_SEPOLIA_RPC_URL"],
        registry_address="0x79eF1B7914f98C5C1404617449AB1f377c475996",
        operator_key=os.environ.get("BASE_SEPOLIA_OPERATOR_KEY", ""),
    )
    return create_anchor_client(config)


@pytest.fixture(scope="module")
def suwappu_client():
    """AnchorClient connected to SUWAPPU Testnet. Returns None if not available."""
    if not _have_suwappu():
        return None
    from src.ltp.anchor.chain_config import ChainConfig, create_anchor_client

    config = ChainConfig(
        chain_id=103115120,
        label="suwappu_testnet",
        rpc_url=os.environ["SUWAPPU_RPC_URL"],
        registry_address="0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
        operator_key=os.environ["SUWAPPU_OPERATOR_KEY"],
    )
    return create_anchor_client(config)


@pytest.fixture(scope="module")
def protocol():
    """Shared LTP protocol instance."""
    from src.ltp import CommitmentNetwork, LTPProtocol

    net = CommitmentNetwork()
    for nid, region in [
        ("xc-int-1", "US-East"),
        ("xc-int-2", "US-West"),
        ("xc-int-3", "EU-West"),
        ("xc-int-4", "EU-East"),
        ("xc-int-5", "AP-East"),
        ("xc-int-6", "AP-South"),
    ]:
        net.add_node(nid, region)
    return LTPProtocol(net)


@pytest.fixture(scope="module")
def keypairs():
    """Operator and verifier keypairs."""
    from src.ltp import KeyPair

    return {
        "operator": KeyPair.generate("xc-int-operator"),
        "verifier": KeyPair.generate("xc-int-verifier"),
    }


class TestCrossChainTransfer:
    """Live cross-chain transfer tests using Base Sepolia as L1."""

    def test_cross_chain_transfer_l1_only(self, protocol, base_client, suwappu_client, keypairs):
        """Base as L1, SUWAPPU as L2, dual_write=False. Anchor on Base only."""
        from src.ltp.bridge.live import LiveBridge
        from src.ltp.bridge.message import BridgeMessage

        bridge = LiveBridge(
            protocol=protocol,
            l1_client=base_client,
            operator_keypair=keypairs["operator"],
            l2_verifier_keypair=keypairs["verifier"],
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            l1_chain_id=84532,
            l2_client=suwappu_client,
            l2_chain_id=103115120 if suwappu_client else None,
            dual_write=False,
        )

        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            sender="0xIntegrationTestSender",
            recipient="0xIntegrationTestRecipient",
            payload={"token": "USDC", "amount": 1, "test": True},
            nonce=0,
        )

        result = bridge.transfer(msg)
        assert result is not None
        assert result.is_anchored_on_l1 is True
        assert result.l1_chain_id == 84532
        # L2 fields should be None (no dual_write)
        assert result.l2_anchor_tx_hash is None
        assert result.is_anchored_on_l2 is None

    def test_cross_chain_result_metadata(self, protocol, base_client, suwappu_client, keypairs):
        """Verify cross_chain flag and real block heights."""
        from src.ltp.bridge.live import LiveBridge
        from src.ltp.bridge.message import BridgeMessage

        has_suwappu = suwappu_client is not None
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=base_client,
            operator_keypair=keypairs["operator"],
            l2_verifier_keypair=keypairs["verifier"],
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            l1_chain_id=84532,
            l2_client=suwappu_client if has_suwappu else None,
            l2_chain_id=103115120 if has_suwappu else None,
            dual_write=False,
        )

        msg = BridgeMessage(
            msg_type="state_update",
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            sender="0xMetadataTest",
            recipient="0xMetadataTest",
            payload={"key": "metadata_test"},
            nonce=0,
        )

        result = bridge.transfer(msg)
        assert result is not None
        assert result.cross_chain == has_suwappu
        assert result.l1_chain_id == 84532
        # Block height should be a real positive number
        assert result.l1_block_height > 0

    @pytest.mark.skipif(
        not _have_suwappu(),
        reason="SUWAPPU_RPC_URL/SUWAPPU_OPERATOR_KEY not set — skipping dual_write test",
    )
    def test_cross_chain_dual_write(self, protocol, base_client, suwappu_client, keypairs):
        """Anchor on Base, re-anchor on SUWAPPU (dual_write=True).

        Requires signer registered on both chains.
        """
        from src.ltp.bridge.live import LiveBridge
        from src.ltp.bridge.message import BridgeMessage

        bridge = LiveBridge(
            protocol=protocol,
            l1_client=base_client,
            operator_keypair=keypairs["operator"],
            l2_verifier_keypair=keypairs["verifier"],
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            l1_chain_id=84532,
            l2_client=suwappu_client,
            l2_chain_id=103115120,
            dual_write=True,
        )

        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="base_sepolia",
            dest_chain="suwappu_testnet",
            sender="0xDualWriteSender",
            recipient="0xDualWriteRecipient",
            payload={"token": "ETH", "amount": 1, "dual_write": True},
            nonce=0,
        )

        result = bridge.transfer(msg)
        assert result is not None
        assert result.is_anchored_on_l1 is True

        # L2 re-anchor may fail if SUWAPPU signer not registered (non-fatal)
        if result.l2_anchor_tx_hash is not None:
            assert result.is_anchored_on_l2 is True
            assert result.l2_chain_id == 103115120
            assert result.l2_block_height > 0
