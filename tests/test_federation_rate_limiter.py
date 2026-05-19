"""
Federation rate limiter tests.

Tests per-network quota enforcement, window expiry,
and CrossNetworkFetcher integration.
"""

from __future__ import annotations

import struct

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.entity import Entity
from src.ltp.federation import (
    CrossNetworkFetcher,
    FederationAgreement,
    FederationConfig,
    FederationRateLimiter,
    FederationRegistry,
    InMemoryFederationTransport,
    NetworkIdentityRecord,
)
from src.ltp.primitives import MLDSA


def _make_signed_sth(sk, seq=1, root="x", ts=1.0, count=1):
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
def kp_a() -> KeyPair:
    return KeyPair.generate("rl-net-a")


@pytest.fixture(scope="session")
def kp_b() -> KeyPair:
    return KeyPair.generate("rl-net-b")


# ---------------------------------------------------------------------------
# FederationRateLimiter
# ---------------------------------------------------------------------------


class TestFederationRateLimiter:
    def test_allow_within_quota(self):
        rl = FederationRateLimiter(max_requests_per_window=5, window_seconds=60.0)
        for _ in range(5):
            assert rl.allow("net-1") is True

    def test_reject_over_quota(self):
        rl = FederationRateLimiter(max_requests_per_window=3, window_seconds=60.0)
        for _ in range(3):
            rl.allow("net-1")
        assert rl.allow("net-1") is False

    def test_per_network_independence(self):
        rl = FederationRateLimiter(max_requests_per_window=2, window_seconds=60.0)
        assert rl.allow("net-1") is True
        assert rl.allow("net-1") is True
        assert rl.allow("net-1") is False  # net-1 exhausted

        # net-2 is independent
        assert rl.allow("net-2") is True
        assert rl.allow("net-2") is True

    def test_remaining_count(self):
        rl = FederationRateLimiter(max_requests_per_window=5, window_seconds=60.0)
        assert rl.remaining("net-1") == 5
        rl.allow("net-1")
        assert rl.remaining("net-1") == 4
        rl.allow("net-1")
        assert rl.remaining("net-1") == 3

    def test_reset_restores_quota(self):
        rl = FederationRateLimiter(max_requests_per_window=2, window_seconds=60.0)
        rl.allow("net-1")
        rl.allow("net-1")
        assert rl.allow("net-1") is False

        rl.reset("net-1")
        assert rl.allow("net-1") is True
        assert rl.remaining("net-1") == 1


# ---------------------------------------------------------------------------
# Window Expiry
# ---------------------------------------------------------------------------


class TestRateLimiterWindowExpiry:
    def test_window_expiry_resets_quota(self):
        """Quota resets after window elapses."""
        current_time = 1000.0
        clock = lambda: current_time

        rl = FederationRateLimiter(
            max_requests_per_window=2,
            window_seconds=10.0,
            clock=clock,
        )

        assert rl.allow("net-1") is True
        assert rl.allow("net-1") is True
        assert rl.allow("net-1") is False  # Exhausted

        # Advance past window
        current_time = 1011.0
        assert rl.allow("net-1") is True  # New window
        assert rl.remaining("net-1") == 1

    def test_remaining_resets_after_window(self):
        current_time = 100.0
        clock = lambda: current_time

        rl = FederationRateLimiter(
            max_requests_per_window=5,
            window_seconds=10.0,
            clock=clock,
        )
        rl.allow("net-1")
        rl.allow("net-1")
        assert rl.remaining("net-1") == 3

        current_time = 111.0
        assert rl.remaining("net-1") == 5  # Full reset


# ---------------------------------------------------------------------------
# CrossNetworkFetcher with Rate Limiter
# ---------------------------------------------------------------------------


class TestFetcherWithRateLimiter:
    def _setup_federated_fetcher(self, kp_a, kp_b, rate_limiter=None):
        """Set up a complete federated fetch scenario."""
        net_a = CommitmentNetwork()
        for i in range(6):
            net_a.add_node(f"rla-{i}", ["US-East", "US-West", "EU-West"][i % 3])

        proto_a = LTPProtocol(net_a)
        entity = Entity(content=b"rate limit test data " * 8, shape="text/plain")
        entity_id, _, _ = proto_a.commit(entity, kp_a, n=6, k=3)

        nir_a = NetworkIdentityRecord.create(kp_a, b"\xaa" * 32, 0, "A", "https://a.net")
        nir_b = NetworkIdentityRecord.create(kp_b, b"\xbb" * 32, 0, "B", "https://b.net")

        reg_b = FederationRegistry(FederationConfig(enabled=True))
        reg_b.set_local_network_id(nir_b.network_id)
        reg_b.register_from_nir(nir_a)
        reg_b.verify_sth(nir_a.network_id, _make_signed_sth(kp_a.sk), current_epoch=1)

        half = FederationAgreement.initiate(kp_b, nir_b, nir_a)
        agreement = FederationAgreement.countersign(half, kp_a)
        reg_b.federate_with_agreement(agreement)

        transport = InMemoryFederationTransport()
        transport.register_network("https://a.net", net_a)

        fetcher = CrossNetworkFetcher(
            reg_b,
            transport,
            nir_b,
            {nir_a.network_id: agreement},
            rate_limiter=rate_limiter,
        )
        return fetcher, entity_id, nir_a.network_id

    def test_rate_limited_fetch_rejected(self, kp_a, kp_b):
        """Fetch rejected when rate limit exhausted."""
        rl = FederationRateLimiter(max_requests_per_window=1, window_seconds=60.0)
        fetcher, entity_id, _ = self._setup_federated_fetcher(kp_a, kp_b, rate_limiter=rl)

        # First fetch succeeds
        result1 = fetcher.fetch_entity_shards(entity_id, [0, 1])
        assert result1 is not None

        # Second fetch — rate limited
        result2 = fetcher.fetch_entity_shards(entity_id, [0, 1])
        assert result2 is None

    def test_unlimited_without_rate_limiter(self, kp_a, kp_b):
        """Without rate_limiter, fetches are unlimited (backward compat)."""
        fetcher, entity_id, _ = self._setup_federated_fetcher(kp_a, kp_b)

        # Multiple fetches all succeed
        for _ in range(5):
            result = fetcher.fetch_entity_shards(entity_id, [0])
            assert result is not None


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_zero_window_rejected(self):
        """window_seconds=0 is rejected (would make limiter always reset)."""
        with pytest.raises(ValueError, match="window_seconds must be > 0"):
            FederationRateLimiter(window_seconds=0.0)

    def test_negative_window_rejected(self):
        with pytest.raises(ValueError, match="window_seconds must be > 0"):
            FederationRateLimiter(window_seconds=-1.0)

    def test_negative_max_requests_rejected(self):
        with pytest.raises(ValueError, match="max_requests_per_window must be >= 0"):
            FederationRateLimiter(max_requests_per_window=-1)

    def test_remaining_unseen_network_returns_max(self):
        """Never-seen network has full quota available."""
        rl = FederationRateLimiter(max_requests_per_window=50, window_seconds=60.0)
        assert rl.remaining("never-queried") == 50
