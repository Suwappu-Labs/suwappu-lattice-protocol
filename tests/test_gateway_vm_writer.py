"""Tests for AttestationWriter — commitment creation + ML-DSA-65 signing."""

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_keypair():
    return KeyPair.generate("gateway-writer-test")


def _make_event():
    from src.ltp.gateway_vm.events import BridgeEvent

    return BridgeEvent(
        source_chain_id=84532,
        bridge_contract="0x5083",
        tx_hash="0xabc123",
        block_number=100,
        log_index=0,
        event_name="AnchorCreated",
        sender="0xaa",
        recipient="0xbb",
        payload_hash="sha3-256:ff00",
        amount=100,
        nonce=1,
        timestamp=1700000000.0,
    )


class TestAttestationWriter:
    def test_create_attestation(self, gateway_keypair):
        from src.ltp.gateway_vm.writer import AttestationWriter

        writer = AttestationWriter(
            operator_keypair=gateway_keypair,
            dest_chain_id=103115120,
        )
        event = _make_event()
        attestation = writer.create_attestation(event)

        assert attestation.event_id == event.event_id
        assert attestation.source_chain_id == 84532
        assert attestation.dest_chain_id == 103115120
        assert len(attestation.signature) > 0
        assert len(attestation.digest) > 0

    def test_attestation_signature_verifies(self, gateway_keypair):
        from src.ltp.gateway_vm.writer import AttestationWriter

        writer = AttestationWriter(
            operator_keypair=gateway_keypair,
            dest_chain_id=103115120,
        )
        event = _make_event()
        attestation = writer.create_attestation(event)
        assert attestation.verify(gateway_keypair.vk) is True

    def test_attestation_signature_rejects_wrong_key(self, gateway_keypair):
        from src.ltp.gateway_vm.writer import AttestationWriter

        writer = AttestationWriter(
            operator_keypair=gateway_keypair,
            dest_chain_id=103115120,
        )
        event = _make_event()
        attestation = writer.create_attestation(event)

        wrong_kp = KeyPair.generate("wrong-key")
        assert attestation.verify(wrong_kp.vk) is False

    def test_attestation_is_deterministic_for_same_event(self, gateway_keypair):
        from src.ltp.gateway_vm.writer import AttestationWriter

        writer = AttestationWriter(
            operator_keypair=gateway_keypair,
            dest_chain_id=103115120,
        )
        event = _make_event()
        a1 = writer.create_attestation(event)
        a2 = writer.create_attestation(event)
        # Digest is deterministic (same event -> same digest)
        assert a1.digest == a2.digest
        # Signatures may differ (ML-DSA is randomized) but both verify
        assert a1.verify(gateway_keypair.vk)
        assert a2.verify(gateway_keypair.vk)

    def test_requires_keypair(self):
        from src.ltp.gateway_vm.writer import AttestationWriter

        with pytest.raises(TypeError):
            AttestationWriter(operator_keypair=None, dest_chain_id=103115120)
