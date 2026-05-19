"""
End-to-end cross-network shard fetch tests.

Proves the complete federation data plane:
  Two independent networks → commit on A → federate A↔B →
  fetch shards from B → verify encrypted data matches.
"""

from __future__ import annotations

import struct

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.entity import Entity
from src.ltp.federation import (
    CrossNetworkFetcher,
    FederationAgreement,
    FederationAuth,
    FederationConfig,
    FederationRegistry,
    InMemoryFederationTransport,
    NetworkIdentityRecord,
    TrustLevel,
)
from src.ltp.primitives import MLDSA

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def kp_a() -> KeyPair:
    return KeyPair.generate("e2e-net-a")


@pytest.fixture(scope="session")
def kp_b() -> KeyPair:
    return KeyPair.generate("e2e-net-b")


def _make_network(prefix: str, n_nodes: int = 6) -> CommitmentNetwork:
    net = CommitmentNetwork()
    regions = ["US-East", "US-West", "EU-West"]
    for i in range(n_nodes):
        net.add_node(f"{prefix}-{i}", regions[i % len(regions)])
    return net


def _make_nir(kp, root_byte, name, endpoint):
    return NetworkIdentityRecord.create(
        kp,
        bytes([root_byte]) * 32,
        0,
        name,
        endpoint,
    )


def _make_signed_sth(sk, seq=1, root="root", ts=1.0, count=10):
    """Create an STH dict with a real ML-DSA-65 signature."""
    sth = {"sequence": seq, "root_hash": root, "timestamp": ts, "record_count": count}
    payload = struct.pack(">Qd", seq, ts) + str(root).encode()
    sth["signable_payload"] = payload
    sth["signature"] = MLDSA.sign(sk, payload)
    return sth


def _setup_registry(local_nir, remote_nir, remote_sk):
    """Create a FederationRegistry from local's perspective with remote VERIFIED."""
    reg = FederationRegistry(FederationConfig(enabled=True))
    reg.set_local_network_id(local_nir.network_id)
    reg.register_from_nir(remote_nir)
    reg.verify_sth(remote_nir.network_id, _make_signed_sth(remote_sk), current_epoch=1)
    return reg


def _make_agreement(kp_init, kp_resp, nir_init, nir_resp):
    half = FederationAgreement.initiate(kp_init, nir_init, nir_resp)
    return FederationAgreement.countersign(half, kp_resp)


# ---------------------------------------------------------------------------
# Full End-to-End Scenario
# ---------------------------------------------------------------------------


class TestEndToEndCrossNetwork:
    """Complete cross-network data plane: commit on A, fetch from B."""

    def test_full_cross_network_shard_fetch(self, kp_a, kp_b):
        """
        Step 1: Create two independent networks (A and B)
        Step 2: Commit entity on Network A
        Step 3: Create NIRs for both
        Step 4: B registers A, verifies STH → A is VERIFIED
        Step 5: Bilateral federation agreement (A↔B)
        Step 6: B federates with A
        Step 7: B resolves entity → found on A
        Step 8: B fetches shards from A → encrypted data returned
        """
        # Step 1: Two networks
        net_a = _make_network("a")
        net_b = _make_network("b")

        # Step 2: Commit on A
        proto_a = LTPProtocol(net_a)
        content = b"Cross-network end-to-end test payload for federation " * 4
        entity = Entity(content=content, shape="application/octet-stream")
        entity_id, record, cek = proto_a.commit(entity, kp_a, n=6, k=3)

        # Step 3: NIRs
        nir_a = _make_nir(kp_a, 0xAA, "Network A", "https://a.net")
        nir_b = _make_nir(kp_b, 0xBB, "Network B", "https://b.net")

        # Step 4: B's registry with A as VERIFIED
        reg_b = _setup_registry(nir_b, nir_a, kp_a.sk)
        assert reg_b.get_network(nir_a.network_id).trust_level == TrustLevel.VERIFIED

        # Step 5: Bilateral agreement
        agreement = _make_agreement(kp_b, kp_a, nir_b, nir_a)
        assert agreement.verify_both()

        # Step 6: Federate
        reg_b.federate_with_agreement(agreement)
        assert reg_b.get_network(nir_a.network_id).trust_level == TrustLevel.FEDERATED

        # Step 7+8: Fetch via CrossNetworkFetcher
        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)

        fetcher = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: agreement},
        )
        shards = fetcher.fetch_entity_shards(entity_id, [0, 1, 2])

        assert shards is not None
        assert len(shards) >= 1
        # Shards are encrypted bytes
        for idx, data in shards.items():
            assert isinstance(data, bytes)
            assert len(data) > 0
            # Should NOT be raw plaintext
            assert content not in data

    def test_fetched_shards_match_original(self, kp_a, kp_b):
        """Shards fetched cross-network are identical to shards on source."""
        net_a = _make_network("match-a")
        proto_a = LTPProtocol(net_a)
        entity = Entity(content=b"shard match test " * 10, shape="text/plain")
        entity_id, _, _ = proto_a.commit(entity, kp_a, n=6, k=3)

        # Get shards directly from A
        direct_shards = net_a.fetch_encrypted_shards(entity_id, 6, 6)

        # Set up federation from B
        nir_a = _make_nir(kp_a, 0x11, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0x22, "B", "https://b.net")
        reg_b = _setup_registry(nir_b, nir_a, kp_a.sk)
        agreement = _make_agreement(kp_b, kp_a, nir_b, nir_a)
        reg_b.federate_with_agreement(agreement)

        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)

        fetcher = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: agreement},
        )
        fetched_shards = fetcher.fetch_entity_shards(entity_id, list(direct_shards.keys()))

        assert fetched_shards is not None
        # Every fetched shard must match the source
        for idx, data in fetched_shards.items():
            assert data == direct_shards[idx]


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestCrossNetworkEdgeCases:
    def test_fetch_before_federation_rejected(self, kp_a, kp_b):
        """Fetch from a VERIFIED (not FEDERATED) network fails auth."""
        net_a = _make_network("prefed-a")
        proto_a = LTPProtocol(net_a)
        entity = Entity(content=b"prefed test " * 5, shape="text/plain")
        entity_id, _, _ = proto_a.commit(entity, kp_a)

        nir_a = _make_nir(kp_a, 0x33, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0x44, "B", "https://b.net")

        reg_b = _setup_registry(nir_b, nir_a, kp_a.sk)
        # A is VERIFIED but NOT FEDERATED — no agreement

        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)

        # No agreements → fetch fails
        fetcher = CrossNetworkFetcher(reg_b, transport, nir_b, {})
        result = fetcher.fetch_entity_shards(entity_id, [0, 1])
        assert result is None

    def test_fetch_after_trust_revocation(self, kp_a, kp_b):
        """After revoking trust, fetch fails."""
        net_a = _make_network("revoke-a")
        proto_a = LTPProtocol(net_a)
        entity = Entity(content=b"revoke test " * 5, shape="text/plain")
        entity_id, _, _ = proto_a.commit(entity, kp_a)

        nir_a = _make_nir(kp_a, 0x55, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0x66, "B", "https://b.net")

        reg_b = _setup_registry(nir_b, nir_a, kp_a.sk)
        agreement = _make_agreement(kp_b, kp_a, nir_b, nir_a)
        reg_b.federate_with_agreement(agreement)

        # Revoke trust
        reg_b.revoke_trust(nir_a.network_id)
        assert reg_b.get_network(nir_a.network_id).trust_level == TrustLevel.UNTRUSTED

        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)

        # Resolution should skip UNTRUSTED networks (min_trust is VERIFIED)
        fetcher = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: agreement},
        )
        result = fetcher.fetch_entity_shards(entity_id, [0])
        assert result is None

    def test_local_entity_not_cross_fetched(self, kp_a, kp_b):
        """Entity on local network → CrossNetworkFetcher returns None (not cross-network)."""
        net_b = _make_network("local-b")
        proto_b = LTPProtocol(net_b)
        entity = Entity(content=b"local test " * 5, shape="text/plain")
        entity_id, _, _ = proto_b.commit(entity, kp_b)

        nir_a = _make_nir(kp_a, 0x77, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0x88, "B", "https://b.net")

        reg_b = FederationRegistry(FederationConfig(enabled=True))
        reg_b.set_local_network_id(nir_b.network_id)
        reg_b.register_local_entity(entity_id)

        transport = InMemoryFederationTransport()
        fetcher = CrossNetworkFetcher(reg_b, transport, nir_b, {})
        result = fetcher.fetch_entity_shards(entity_id, [0])
        assert result is None  # Local — not a cross-network fetch


# ---------------------------------------------------------------------------
# Two-Way Federation
# ---------------------------------------------------------------------------


class TestTwoWayFederation:
    """Both networks commit entities and fetch from each other."""

    def test_bidirectional_fetch(self, kp_a, kp_b):
        """A fetches from B, B fetches from A — both directions work."""
        net_a = _make_network("bi-a")
        net_b = _make_network("bi-b")

        # Commit on both
        proto_a = LTPProtocol(net_a)
        entity_on_a = Entity(content=b"entity on A " * 10, shape="text/plain")
        eid_a, _, _ = proto_a.commit(entity_on_a, kp_a, n=6, k=3)

        proto_b = LTPProtocol(net_b)
        entity_on_b = Entity(content=b"entity on B " * 10, shape="text/plain")
        eid_b, _, _ = proto_b.commit(entity_on_b, kp_b, n=6, k=3)

        # NIRs
        nir_a = _make_nir(kp_a, 0xCC, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0xDD, "B", "https://b.net")

        # Agreement
        agreement = _make_agreement(kp_a, kp_b, nir_a, nir_b)

        # Transport
        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)
        transport.register_network("https://b.net", net_b)

        # --- B fetches from A ---
        reg_b = _setup_registry(nir_b, nir_a, kp_a.sk)
        reg_b.federate_with_agreement(agreement)

        fetcher_b = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: agreement},
        )
        shards_from_a = fetcher_b.fetch_entity_shards(eid_a, [0, 1, 2])
        assert shards_from_a is not None
        assert len(shards_from_a) >= 1

        # --- A fetches from B ---
        reg_a = _setup_registry(nir_a, nir_b, kp_b.sk)
        reg_a.federate_with_agreement(agreement)

        fetcher_a = CrossNetworkFetcher(
            reg_a,
            transport,
            nir_a,
            {nir_b.network_id: agreement},
        )
        shards_from_b = fetcher_a.fetch_entity_shards(eid_b, [0, 1, 2])
        assert shards_from_b is not None
        assert len(shards_from_b) >= 1


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_wrong_agreement_rejected_by_transport(self, kp_a, kp_b):
        """Agreement with network C cannot authenticate to network B."""
        kp_c = KeyPair.generate("e2e-net-c")
        nir_a = _make_nir(kp_a, 0xE1, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0xE2, "B", "https://b.net")
        nir_c = _make_nir(kp_c, 0xE3, "C", "https://c.net")

        # Agreement between A and C (NOT B)
        agreement_ac = _make_agreement(kp_a, kp_c, nir_a, nir_c)

        net_b = _make_network("wrong-b")
        proto_b = LTPProtocol(net_b)
        entity = Entity(content=b"wrong agreement test " * 5, shape="text/plain")
        entity_id, _, _ = proto_b.commit(entity, kp_b)

        # Transport with network_id for scope checking
        transport = InMemoryFederationTransport()
        transport.register_network("https://b.net", net_b, network_id=nir_b.network_id)

        # Auth with A-C agreement, targeting B's endpoint
        auth = FederationAuth(requester_nir=nir_a, agreement=agreement_ac)
        assert auth.verify() is True  # Signatures are valid
        assert auth.covers_network(nir_b.network_id) is False  # But doesn't cover B

        # Transport should reject — agreement doesn't cover B
        shards = transport.fetch_shards("https://b.net", entity_id, [0], auth)
        assert shards == {}

    def test_auth_covers_network_check(self, kp_a, kp_b):
        """FederationAuth.covers_network validates agreement scope."""
        nir_a = _make_nir(kp_a, 0xF1, "A", "https://a.net")
        nir_b = _make_nir(kp_b, 0xF2, "B", "https://b.net")
        agreement = _make_agreement(kp_a, kp_b, nir_a, nir_b)
        auth = FederationAuth(requester_nir=nir_a, agreement=agreement)

        assert auth.covers_network(nir_a.network_id) is True  # Initiator
        assert auth.covers_network(nir_b.network_id) is True  # Responder
        assert auth.covers_network("unrelated-id") is False  # Not a party
