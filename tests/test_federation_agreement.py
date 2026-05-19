"""
Federation mutual agreement protocol tests.

Tests bilateral signed agreements for VERIFIED -> FEDERATED trust upgrade.
"""

from __future__ import annotations

import struct

import pytest

from src.ltp import KeyPair
from src.ltp.federation import (
    FederationAgreement,
    FederationConfig,
    FederationRegistry,
    NetworkIdentityRecord,
    TrustLevel,
)
from src.ltp.primitives import MLDSA


def _make_signed_sth(sk, seq=1, root="abc", ts=1.0, count=10):
    """Create an STH dict with a real ML-DSA-65 signature."""
    sth = {"sequence": seq, "root_hash": root, "timestamp": ts, "record_count": count}
    payload = struct.pack(">Qd", seq, ts) + str(root).encode()
    sth["signable_payload"] = payload
    sth["signature"] = MLDSA.sign(sk, payload)
    return sth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def net_a_kp() -> KeyPair:
    return KeyPair.generate("net-a-operator")


@pytest.fixture(scope="session")
def net_b_kp() -> KeyPair:
    return KeyPair.generate("net-b-operator")


@pytest.fixture
def nir_a(net_a_kp):
    return NetworkIdentityRecord.create(
        net_a_kp,
        b"\xaa" * 32,
        0,
        "Network A",
        "https://net-a.example.com",
    )


@pytest.fixture
def nir_b(net_b_kp):
    return NetworkIdentityRecord.create(
        net_b_kp,
        b"\xbb" * 32,
        0,
        "Network B",
        "https://net-b.example.com",
    )


# ---------------------------------------------------------------------------
# FederationAgreement
# ---------------------------------------------------------------------------


class TestFederationAgreement:
    def test_initiate_creates_half_signed(self, net_a_kp, nir_a, nir_b):
        agreement = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        assert agreement.initiator_network_id == nir_a.network_id
        assert agreement.responder_network_id == nir_b.network_id
        assert len(agreement.initiator_signature) > 0
        assert agreement.responder_signature == b""

    def test_countersign_creates_fully_signed(self, net_a_kp, net_b_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)
        assert len(full.initiator_signature) > 0
        assert len(full.responder_signature) > 0

    def test_verify_both_passes(self, net_a_kp, net_b_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)
        assert full.verify_both() is True

    def test_half_signed_verify_initiator_only(self, net_a_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        assert half.verify_initiator() is True
        assert half.verify_responder() is False
        assert half.verify_both() is False

    def test_tampered_agreement_rejected(self, net_a_kp, net_b_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        # Tamper with terms
        tampered = FederationAgreement(
            initiator_network_id=full.initiator_network_id,
            responder_network_id=full.responder_network_id,
            initiator_vk=full.initiator_vk,
            responder_vk=full.responder_vk,
            initiator_signature=full.initiator_signature,
            responder_signature=full.responder_signature,
            created_at=full.created_at,
            terms="TAMPERED TERMS",
        )
        assert tampered.verify_both() is False

    def test_wrong_responder_keypair_rejected(self, net_a_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        wrong_kp = KeyPair.generate("wrong-responder")
        with pytest.raises(ValueError, match="does not match"):
            FederationAgreement.countersign(half, wrong_kp)

    def test_agreement_with_terms(self, net_a_kp, net_b_kp, nir_a, nir_b):
        half = FederationAgreement.initiate(
            net_a_kp,
            nir_a,
            nir_b,
            terms="Rate limit: 100 req/min",
        )
        full = FederationAgreement.countersign(half, net_b_kp)
        assert full.terms == "Rate limit: 100 req/min"
        assert full.verify_both() is True


# ---------------------------------------------------------------------------
# FederationRegistry.federate_with_agreement
# ---------------------------------------------------------------------------


class TestFederateWithAgreement:
    def _setup_verified_registry(self, nir_a, nir_b, net_b_kp):
        """Create a registry from A's perspective with B as VERIFIED."""
        reg = FederationRegistry()
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        # Upgrade B to VERIFIED via STH (signed with B's SK)
        reg.verify_sth(nir_b.network_id, _make_signed_sth(net_b_kp.sk), current_epoch=1)
        assert reg.get_network(nir_b.network_id).trust_level == TrustLevel.VERIFIED
        return reg

    def test_verified_to_federated(self, net_a_kp, net_b_kp, nir_a, nir_b):
        reg = self._setup_verified_registry(nir_a, nir_b, net_b_kp)
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        result = reg.federate_with_agreement(full)
        assert result is True
        assert reg.get_network(nir_b.network_id).trust_level == TrustLevel.FEDERATED

    def test_untrusted_network_rejected(self, net_a_kp, net_b_kp, nir_a, nir_b):
        reg = FederationRegistry()
        reg.set_local_network_id(nir_a.network_id)
        reg.register_from_nir(nir_b)
        # B is still UNTRUSTED (no STH verified)

        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        with pytest.raises(ValueError, match="must be at least VERIFIED"):
            reg.federate_with_agreement(full)

    def test_unknown_network_rejected(self, net_a_kp, net_b_kp, nir_a, nir_b):
        reg = FederationRegistry()
        reg.set_local_network_id(nir_a.network_id)
        # Don't register B

        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        with pytest.raises(ValueError, match="not registered"):
            reg.federate_with_agreement(full)

    def test_already_federated_is_idempotent(self, net_a_kp, net_b_kp, nir_a, nir_b):
        reg = self._setup_verified_registry(nir_a, nir_b, net_b_kp)
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        reg.federate_with_agreement(full)
        result = reg.federate_with_agreement(full)  # Second time
        assert result is True  # Idempotent


# ---------------------------------------------------------------------------
# End-to-end Agreement Flow
# ---------------------------------------------------------------------------


class TestAgreementFlow:
    def test_full_flow_nir_to_federation(self, net_a_kp, net_b_kp):
        """End-to-end: create NIRs -> register -> verify STH -> agree -> federate."""
        nir_a = NetworkIdentityRecord.create(
            net_a_kp,
            b"\x11" * 32,
            0,
            "Alpha",
            "https://alpha.net",
        )
        nir_b = NetworkIdentityRecord.create(
            net_b_kp,
            b"\x22" * 32,
            0,
            "Beta",
            "https://beta.net",
        )

        # Network A's registry
        reg_a = FederationRegistry()
        reg_a.set_local_network_id(nir_a.network_id)
        reg_a.register_from_nir(nir_b)
        reg_a.verify_sth(
            nir_b.network_id,
            _make_signed_sth(
                net_b_kp.sk,
                root="xyz",
                count=5,
            ),
            current_epoch=1,
        )

        # Initiate agreement from A
        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        assert half.verify_initiator() is True

        # B counter-signs
        full = FederationAgreement.countersign(half, net_b_kp)
        assert full.verify_both() is True

        # A federates
        reg_a.federate_with_agreement(full)
        assert reg_a.get_network(nir_b.network_id).trust_level == TrustLevel.FEDERATED
        assert reg_a.get_network(nir_b.network_id).is_federated is True


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_self_federation_rejected(self, net_a_kp, nir_a):
        """Cannot federate a network with itself."""
        with pytest.raises(ValueError, match="Cannot federate.*itself"):
            FederationAgreement.initiate(net_a_kp, nir_a, nir_a)

    def test_mismatched_initiator_vk_rejected(self, net_b_kp, nir_a, nir_b):
        """Initiator keypair must match initiator NIR's operator_vk."""
        # net_b_kp doesn't match nir_a's operator
        with pytest.raises(ValueError, match="does not match initiator NIR"):
            FederationAgreement.initiate(net_b_kp, nir_a, nir_b)

    def test_local_network_not_party_rejected(self, net_a_kp, net_b_kp, nir_a, nir_b):
        """federate_with_agreement rejects if local network is not in the agreement."""
        reg = FederationRegistry()
        reg.set_local_network_id("unrelated-network-id")
        reg.register_from_nir(nir_b)

        half = FederationAgreement.initiate(net_a_kp, nir_a, nir_b)
        full = FederationAgreement.countersign(half, net_b_kp)

        with pytest.raises(ValueError, match="not a party"):
            reg.federate_with_agreement(full)
