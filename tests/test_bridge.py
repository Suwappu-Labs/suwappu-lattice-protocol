"""
Integration tests for the ETP Bridge — L1↔L2 cross-chain transfer.

End-to-end scenario:
  1. Alice locks 100 USDC on L1 (Ethereum)
  2. L1Anchor commits the lock event
  3. Relayer seals the key to L2 verifier
  4. L2Materializer on Optimism verifies + reconstructs
  5. Bridge mints 100 USDC to Alice on L2
  6. Replay attempt → REJECTED
  7. Tampered packet → FAILS
"""

from enum import IntEnum
from unittest.mock import MagicMock

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge import (
    BridgeMessage,
    L1Anchor,
    L2Materializer,
    Relayer,
    RelayPacket,
)
from src.ltp.bridge.live import LiveBridge, LiveBridgeResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def l1_operator() -> KeyPair:
    """L1 bridge operator keypair (signs commitment records)."""
    return KeyPair.generate("l1-operator")


@pytest.fixture(scope="session")
def l2_verifier() -> KeyPair:
    """L2 verifier keypair (unseals lattice keys)."""
    return KeyPair.generate("l2-verifier")


@pytest.fixture
def bridge_network() -> CommitmentNetwork:
    """Shared commitment network (simulates DA layer)."""
    net = CommitmentNetwork()
    for node_id, region in [
        ("bridge-us-1", "US-East"),
        ("bridge-us-2", "US-West"),
        ("bridge-eu-1", "EU-West"),
        ("bridge-eu-2", "EU-East"),
        ("bridge-ap-1", "AP-East"),
        ("bridge-ap-2", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return net


@pytest.fixture
def bridge_protocol(bridge_network: CommitmentNetwork) -> LTPProtocol:
    return LTPProtocol(bridge_network)


@pytest.fixture
def l1_anchor(bridge_protocol: LTPProtocol, l1_operator: KeyPair) -> L1Anchor:
    return L1Anchor(bridge_protocol, l1_operator, chain_id="ethereum")


@pytest.fixture
def relayer(bridge_protocol: LTPProtocol) -> Relayer:
    return Relayer(bridge_protocol)


@pytest.fixture
def l2_materializer(bridge_protocol: LTPProtocol, l2_verifier: KeyPair) -> L2Materializer:
    return L2Materializer(
        bridge_protocol,
        l2_verifier,
        chain_id="optimism",
        required_confirmations=1,
    )


def _make_lock_message(nonce: int = 0) -> BridgeMessage:
    """Create a standard token_lock bridge message."""
    return BridgeMessage(
        msg_type="token_lock",
        source_chain="ethereum",
        dest_chain="optimism",
        sender="0xAliceSenderAddress",
        recipient="0xAliceRecipientAddress",
        payload={"token": "USDC", "amount": 100, "decimals": 6},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBridgeEndToEnd:
    """Full lock → relay → materialize → mint flow."""

    def test_happy_path(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Alice locks 100 USDC on L1, receives them on L2."""
        msg = _make_lock_message(nonce=0)

        # Phase 1: COMMIT on L1
        commitment, cek = l1_anchor.commit_message(msg)
        assert commitment.entity_id
        assert commitment.merkle_proof is not None
        assert commitment.source_block == 1

        # Phase 2: LATTICE (relay)
        packet = relayer.relay(commitment, cek, l2_verifier)
        assert len(packet.sealed_key) > 1000  # ~1.3KB
        assert packet.source_chain == "ethereum"
        assert packet.dest_chain == "optimism"
        assert packet.nonce == 0

        # Phase 3: MATERIALIZE on L2
        l2_materializer.set_l1_block_height(10)  # Sufficient finality
        result = l2_materializer.materialize(packet)

        assert result is not None
        assert result.msg_type == "token_lock"
        assert result.payload["token"] == "USDC"
        assert result.payload["amount"] == 100
        assert result.sender == "0xAliceSenderAddress"
        assert result.recipient == "0xAliceRecipientAddress"
        assert result.nonce == 0

    def test_multiple_messages(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Multiple sequential bridge messages with increasing nonces."""
        l2_materializer.set_l1_block_height(100)

        for nonce in range(3):
            msg = _make_lock_message(nonce=nonce)
            commitment, cek = l1_anchor.commit_message(msg)
            packet = relayer.relay(commitment, cek, l2_verifier)
            result = l2_materializer.materialize(packet)

            assert result is not None
            assert result.nonce == nonce
            assert result.payload["amount"] == 100


class TestReplayProtection:
    """Nonce-based replay attack prevention."""

    def test_l1_nonce_replay_rejected(self, l1_anchor: L1Anchor):
        """Same nonce on L1 → commit fails."""
        msg1 = _make_lock_message(nonce=0)
        l1_anchor.commit_message(msg1)

        msg2 = _make_lock_message(nonce=0)
        with pytest.raises(ValueError, match="replay"):
            l1_anchor.commit_message(msg2)

    def test_l2_nonce_replay_rejected(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Same packet replayed on L2 → materialization fails."""
        l2_materializer.set_l1_block_height(100)

        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # First materialization succeeds
        result1 = l2_materializer.materialize(packet)
        assert result1 is not None

        # Replay → rejected
        result2 = l2_materializer.materialize(packet)
        assert result2 is None


class TestChainValidation:
    """Cross-chain routing validation."""

    def test_wrong_source_chain(self, l1_anchor: L1Anchor):
        """Message with wrong source_chain → L1 rejects."""
        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="arbitrum",  # Wrong — anchor is "ethereum"
            dest_chain="optimism",
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 50},
            nonce=0,
        )
        with pytest.raises(ValueError, match="source_chain"):
            l1_anchor.commit_message(msg)

    def test_wrong_dest_chain(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_verifier: KeyPair,
        bridge_protocol: LTPProtocol,
    ):
        """Packet routed to wrong L2 chain → materializer rejects."""
        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="arbitrum",  # Not "optimism"
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 50},
            nonce=0,
        )
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Materializer is for "optimism", packet says "arbitrum"
        materializer = L2Materializer(bridge_protocol, l2_verifier, chain_id="optimism")
        materializer.set_l1_block_height(100)
        result = materializer.materialize(packet)
        assert result is None


class TestFinalityChecks:
    """L1 finality confirmation requirements."""

    def test_insufficient_finality(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Packet from too-recent L1 block → rejected."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # L2 thinks L1 is at block 0, but packet is from block 1
        l2_materializer.set_l1_block_height(0)
        result = l2_materializer.materialize(packet)
        assert result is None

    def test_sufficient_finality(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Packet with enough confirmations → accepted."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        l2_materializer.set_l1_block_height(100)
        result = l2_materializer.materialize(packet)
        assert result is not None


class TestTampering:
    """Tamper detection at various layers."""

    def test_wrong_receiver_key(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_verifier: KeyPair,
        bridge_protocol: LTPProtocol,
    ):
        """Sealed key opened with wrong private key → fails."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Eve tries to materialize with her own key
        eve = KeyPair.generate("eve-bridge-attacker")
        materializer = L2Materializer(bridge_protocol, eve, chain_id="optimism")
        materializer.set_l1_block_height(100)
        result = materializer.materialize(packet)
        assert result is None

    def test_corrupted_sealed_key(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Bit-flipped sealed key → unseal fails."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Corrupt one byte in the sealed key
        corrupted = bytearray(packet.sealed_key)
        corrupted[500] ^= 0xFF
        corrupted_packet = RelayPacket(
            sealed_key=bytes(corrupted),
            source_chain=packet.source_chain,
            dest_chain=packet.dest_chain,
            nonce=packet.nonce,
            source_block=packet.source_block,
            entity_id=packet.entity_id,
        )

        l2_materializer.set_l1_block_height(100)
        result = l2_materializer.materialize(corrupted_packet)
        assert result is None


class TestMessageSerialization:
    """BridgeMessage canonical serialization round-trip."""

    def test_round_trip(self):
        msg = _make_lock_message(nonce=42)
        data = msg.to_canonical_bytes()
        restored = BridgeMessage.from_bytes(data)

        assert restored.msg_type == msg.msg_type
        assert restored.source_chain == msg.source_chain
        assert restored.dest_chain == msg.dest_chain
        assert restored.sender == msg.sender
        assert restored.recipient == msg.recipient
        assert restored.payload == msg.payload
        assert restored.nonce == msg.nonce
        assert restored.timestamp == msg.timestamp

    def test_canonical_determinism(self):
        """Same message → same bytes every time."""
        msg = _make_lock_message(nonce=7)
        assert msg.to_canonical_bytes() == msg.to_canonical_bytes()


# ---------------------------------------------------------------------------
# Mock AnchorClient for cross-chain LiveBridge tests
# ---------------------------------------------------------------------------


class _MockEntityState(IntEnum):
    """Minimal EntityState mock matching src/ltp/anchor/state.py."""

    UNKNOWN = 0
    COMMITTED = 1
    ANCHORED = 2
    MATERIALIZED = 3


class MockAnchorClient:
    """Lightweight mock of AnchorClient for unit-testing LiveBridge cross-chain logic."""

    def __init__(self, chain_id: int = 1, block_height: int = 100):
        self._chain_id = chain_id
        self._block_height = block_height
        self._anchored: set[bytes] = set()
        self._sequence = 0
        self._anchor_call_count = 0
        self._should_fail = False

    def anchor(self, submission) -> str:
        if self._should_fail:
            raise RuntimeError("MockAnchorClient: anchor failed")
        self._anchored.add(submission.anchor_digest)
        self._sequence = submission.sequence
        self._anchor_call_count += 1
        return f"0x{'ab' * 32}"

    def is_anchored(self, anchor_digest: bytes) -> bool:
        return anchor_digest in self._anchored

    def entity_state(self, entity_id_hash: bytes) -> _MockEntityState:
        return _MockEntityState.ANCHORED

    def signer_sequence(self, vk_hash: bytes) -> int:
        return self._sequence

    def get_block_number(self) -> int:
        return self._block_height


class TestCrossChainLiveBridge:
    """Cross-chain LiveBridge with mock AnchorClients."""

    @pytest.fixture
    def protocol(self):
        net = CommitmentNetwork()
        for nid, region in [
            ("xc-1", "US-East"),
            ("xc-2", "US-West"),
            ("xc-3", "EU-West"),
            ("xc-4", "EU-East"),
            ("xc-5", "AP-East"),
            ("xc-6", "AP-South"),
        ]:
            net.add_node(nid, region)
        return LTPProtocol(net)

    @pytest.fixture
    def operator_kp(self):
        return KeyPair.generate("xc-operator")

    @pytest.fixture
    def verifier_kp(self):
        return KeyPair.generate("xc-verifier")

    @pytest.fixture
    def l1_mock(self):
        return MockAnchorClient(chain_id=103115120, block_height=500)

    @pytest.fixture
    def l2_mock(self):
        return MockAnchorClient(chain_id=84532, block_height=1000)

    def _make_msg(self, nonce: int = 0) -> BridgeMessage:
        return BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="optimism",
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 100},
            nonce=nonce,
        )

    def test_dual_client_l1_only(self, protocol, operator_kp, verifier_kp, l1_mock, l2_mock):
        """Two mocks, dual_write=False: anchor called on L1 only."""
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=l1_mock,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            l1_chain_id=103115120,
            l2_client=l2_mock,
            l2_chain_id=84532,
            dual_write=False,
        )
        result = bridge.transfer(self._make_msg(nonce=0))
        assert result is not None
        assert result.is_anchored_on_l1 is True
        assert result.cross_chain is True
        # L2 fields should be None (no dual_write)
        assert result.l2_anchor_tx_hash is None
        assert result.is_anchored_on_l2 is None
        assert result.l2_entity_state is None
        assert result.l2_block_height is None
        # L2 mock should NOT have been called
        assert l2_mock._anchor_call_count == 0

    def test_dual_client_dual_write(self, protocol, operator_kp, verifier_kp, l1_mock, l2_mock):
        """Two mocks, dual_write=True: anchor called on both chains."""
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=l1_mock,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            l1_chain_id=103115120,
            l2_client=l2_mock,
            l2_chain_id=84532,
            dual_write=True,
        )
        result = bridge.transfer(self._make_msg(nonce=0))
        assert result is not None
        assert result.is_anchored_on_l1 is True
        assert result.is_anchored_on_l2 is True
        assert result.l2_anchor_tx_hash is not None
        assert result.l2_entity_state == int(_MockEntityState.ANCHORED)
        assert result.l2_block_height == 1000
        assert l1_mock._anchor_call_count == 1
        assert l2_mock._anchor_call_count == 1

    def test_cross_chain_result_fields(self, protocol, operator_kp, verifier_kp, l1_mock, l2_mock):
        """Verify cross_chain, chain IDs, and block heights are correct."""
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=l1_mock,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            l1_chain_id=103115120,
            l2_client=l2_mock,
            l2_chain_id=84532,
            dual_write=True,
        )
        result = bridge.transfer(self._make_msg(nonce=0))
        assert result.cross_chain is True
        assert result.l1_chain_id == 103115120
        assert result.l2_chain_id == 84532
        assert result.l1_block_height == 500
        assert result.l2_block_height == 1000
        assert result.source_chain == "ethereum"
        assert result.dest_chain == "optimism"

    def test_l2_reanchor_failure_nonfatal(
        self, protocol, operator_kp, verifier_kp, l1_mock, l2_mock
    ):
        """L2 mock raises on anchor — transfer still succeeds with L1 data."""
        l2_mock._should_fail = True
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=l1_mock,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            l1_chain_id=103115120,
            l2_client=l2_mock,
            l2_chain_id=84532,
            dual_write=True,
        )
        result = bridge.transfer(self._make_msg(nonce=0))
        assert result is not None
        assert result.is_anchored_on_l1 is True
        # L2 failed — fields should be None
        assert result.l2_anchor_tx_hash is None
        assert result.is_anchored_on_l2 is None
        assert result.l2_block_height is None

    def test_sequence_counters_independent(
        self, protocol, operator_kp, verifier_kp, l1_mock, l2_mock
    ):
        """L1 and L2 sequences track independently across multiple transfers."""
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=l1_mock,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            l1_chain_id=103115120,
            l2_client=l2_mock,
            l2_chain_id=84532,
            dual_write=True,
        )
        for nonce in range(3):
            result = bridge.transfer(self._make_msg(nonce=nonce))
            assert result is not None

        # Both should have sequence 3
        assert l1_mock._sequence == 3
        assert l2_mock._sequence == 3
        # Internal counters
        assert bridge._l1_sequence == 3
        assert bridge._l2_sequence == 3

    def test_from_chain_configs_factory(self, protocol, operator_kp, verifier_kp):
        """Construct via from_chain_configs class method."""
        from unittest.mock import MagicMock, patch

        from src.ltp.anchor.chain_config import ChainConfig

        l1_config = ChainConfig(
            chain_id=103115120,
            label="suwappu_testnet",
            rpc_url="http://localhost:8545",
            registry_address="0x" + "ab" * 20,
            operator_key="0x" + "cd" * 32,
        )
        l2_config = ChainConfig(
            chain_id=84532,
            label="base_sepolia",
            rpc_url="http://localhost:8546",
            registry_address="0x" + "ef" * 20,
            operator_key="0x" + "12" * 32,
        )

        mock_l1 = MockAnchorClient(chain_id=103115120)
        mock_l2 = MockAnchorClient(chain_id=84532)

        with patch(
            "src.ltp.anchor.chain_config.create_anchor_client",
            side_effect=[mock_l1, mock_l2],
        ):
            bridge = LiveBridge.from_chain_configs(
                protocol=protocol,
                l1_config=l1_config,
                operator_keypair=operator_kp,
                l2_verifier_keypair=verifier_kp,
                l2_config=l2_config,
                dual_write=True,
            )

        assert bridge._l1_client is mock_l1
        assert bridge._l2_client is mock_l2
        assert bridge._cross_chain is True
        assert bridge._dual_write is True
        assert bridge._l1_chain_id == 103115120
        assert bridge._l2_chain_id == 84532
