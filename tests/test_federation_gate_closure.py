"""
Gate closure integration test.

Single scenario exercising all federation components:
  Governance voting + NIR discovery + federation agreement +
  cross-network shard fetching + rate limiting.
"""

from __future__ import annotations

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.enforcement import DecentralizationMetrics, GovernanceTransition
from src.ltp.entity import Entity
from src.ltp.federation import (
    CrossNetworkFetcher,
    FederationAgreement,
    FederationConfig,
    FederationRateLimiter,
    FederationRegistry,
    InMemoryFederationTransport,
    NetworkIdentityRecord,
    StaticDiscoveryService,
    TrustLevel,
)
from src.ltp.governance import (
    TransitionVoteManager,
    create_transition_vote,
)
from src.ltp.primitives import MLDSA, canonical_hash

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def op_a() -> KeyPair:
    return KeyPair.generate("p6-op-a")


@pytest.fixture(scope="session")
def op_b() -> KeyPair:
    return KeyPair.generate("p6-op-b")


@pytest.fixture(scope="session")
def op_c() -> KeyPair:
    return KeyPair.generate("p6-op-c")


# ---------------------------------------------------------------------------
# Full Integration: All Federation Components
# ---------------------------------------------------------------------------


class TestPhase6FullIntegration:
    def test_all_phase6_components_in_single_scenario(self, op_a, op_b, op_c):
        """
        Step 1: GOVERNANCE — vote for BOOTSTRAP→GROWTH
        Step 2: NIR — create and publish
        Step 3: FEDERATION SETUP — register, verify STH
        Step 4: FEDERATE — bilateral agreement
        Step 5: CROSS-NETWORK — commit on A, fetch from B
        Step 6: RATE LIMIT — enforce quota
        Step 7: VERIFY — shards match, trust correct
        """

        # ---- Step 1: Governance Voting ----
        vote_mgr = TransitionVoteManager(required_ratio=2 / 3)
        vote_mgr.register_operator("op-a", canonical_hash(op_a.vk))
        vote_mgr.register_operator("op-b", canonical_hash(op_b.vk))
        vote_mgr.register_operator("op-c", canonical_hash(op_c.vk))

        vote_mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))
        vote_mgr.cast_vote("bootstrap->growth", create_transition_vote(op_b, "bootstrap", "growth"))
        assert vote_mgr.has_supermajority("bootstrap->growth")

        gt = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=1000.0,
            gini_coefficient=0.3,
            governance_participation=0.2,
            foundation_veto_active=True,
        )
        result = vote_mgr.execute_if_ready("bootstrap->growth", gt, metrics)
        assert result is True

        # ---- Step 2: NIR Discovery ----
        nir_a = NetworkIdentityRecord.create(op_a, b"\xaa" * 32, 0, "Network A", "https://a.net")
        nir_b = NetworkIdentityRecord.create(op_b, b"\xbb" * 32, 0, "Network B", "https://b.net")
        assert nir_a.verify() and nir_b.verify()

        discovery = StaticDiscoveryService()
        discovery.publish(nir_a)
        discovery.publish(nir_b)
        assert len(discovery.discover()) == 2
        assert discovery.resolve(nir_a.network_id) is not None

        # ---- Step 3: Federation Setup (B's perspective) ----
        reg_b = FederationRegistry(FederationConfig(enabled=True))
        reg_b.set_local_network_id(nir_b.network_id)
        reg_b.register_from_nir(nir_a)
        import struct

        sth = {"sequence": 1, "root_hash": "root", "timestamp": 1.0, "record_count": 5}
        payload = struct.pack(">Qd", 1, 1.0) + b"root"
        sth["signable_payload"] = payload
        sth["signature"] = MLDSA.sign(op_a.sk, payload)
        reg_b.verify_sth(nir_a.network_id, sth, current_epoch=1)
        assert reg_b.get_network(nir_a.network_id).trust_level == TrustLevel.VERIFIED

        # ---- Step 4: Bilateral Federation Agreement ----
        half = FederationAgreement.initiate(op_b, nir_b, nir_a)
        full = FederationAgreement.countersign(half, op_a)
        assert full.verify_both()

        reg_b.federate_with_agreement(full)
        assert reg_b.get_network(nir_a.network_id).trust_level == TrustLevel.FEDERATED

        # ---- Step 5: Cross-Network Shard Fetch ----
        net_a = CommitmentNetwork()
        for i in range(6):
            net_a.add_node(f"a-{i}", ["US-East", "US-West", "EU-West"][i % 3])

        proto_a = LTPProtocol(net_a)
        content = b"Phase 6 gate closure integration payload " * 5
        entity = Entity(content=content, shape="application/octet-stream")
        entity_id, _, _ = proto_a.commit(entity, op_a, n=6, k=3)

        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a, network_id=nir_a.network_id)

        rate_limiter = FederationRateLimiter(max_requests_per_window=10, window_seconds=60.0)

        fetcher = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: full},
            rate_limiter=rate_limiter,
        )

        shards = fetcher.fetch_entity_shards(entity_id, [0, 1, 2])
        assert shards is not None
        assert len(shards) >= 1

        # ---- Step 6: Rate Limit Enforcement ----
        assert rate_limiter.remaining(nir_a.network_id) == 9  # Used 1 of 10

        # ---- Step 7: Verify ----
        for idx, data in shards.items():
            assert isinstance(data, bytes)
            assert len(data) > 0
            assert content not in data  # Encrypted, not plaintext


# ---------------------------------------------------------------------------
# Individual Gate Checks
# ---------------------------------------------------------------------------


class TestPhase6GateChecklist:
    def test_governance_transition_voted(self, op_a, op_b, op_c):
        """Operators can vote to trigger phase transition."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))
        mgr.cast_vote("b->g", create_transition_vote(op_a, "bootstrap", "growth"))
        mgr.cast_vote("b->g", create_transition_vote(op_b, "bootstrap", "growth"))
        assert mgr.has_supermajority("b->g")

    def test_nir_signed_and_discoverable(self, op_a):
        nir = NetworkIdentityRecord.create(op_a, b"\x11" * 32, 0, "Test", "https://test")
        assert nir.verify()
        svc = StaticDiscoveryService()
        svc.publish(nir)
        assert svc.resolve(nir.network_id) is not None

    def test_bilateral_agreement_verified(self, op_a, op_b):
        nir_a = NetworkIdentityRecord.create(op_a, b"\x22" * 32, 0, "A", "https://a")
        nir_b = NetworkIdentityRecord.create(op_b, b"\x33" * 32, 0, "B", "https://b")
        half = FederationAgreement.initiate(op_a, nir_a, nir_b)
        full = FederationAgreement.countersign(half, op_b)
        assert full.verify_both()

    def test_rate_limiter_enforces_quota(self):
        rl = FederationRateLimiter(max_requests_per_window=2, window_seconds=60.0)
        assert rl.allow("net") is True
        assert rl.allow("net") is True
        assert rl.allow("net") is False


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_existing_federation_registry_works(self):
        """FederationRegistry without new features still works."""
        reg = FederationRegistry()
        reg.set_local_network_id("local")
        reg.register_local_entity("ent-1")
        result = reg.resolve_entity("ent-1")
        assert result.found is True

    def test_existing_governance_transition_works(self):
        """GovernanceTransition without voting still works."""
        gt = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=1000.0,
            gini_coefficient=0.3,
            governance_participation=0.2,
            foundation_veto_active=True,
        )
        can, _ = gt.can_transition("bootstrap", "growth", metrics)
        assert can is True
