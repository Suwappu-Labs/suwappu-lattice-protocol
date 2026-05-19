"""
Tests for commitment network backends: Local, Base L1, and Ethereum.

Tests are parameterized across all three backends to ensure the abstract
interface contract is satisfied uniformly.  Backend-specific tests follow.
"""

import pytest

from src.ltp.backends import (
    BackendCapabilities,
    BackendConfig,
    BaseL1Backend,
    CommitmentBackend,
    EthereumBackend,
    LocalBackend,
    create_backend,
)
from src.ltp.backends.base import FinalityModel
from src.ltp.primitives import canonical_hash

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def local_backend():
    return create_backend(BackendConfig(backend_type="local"))


@pytest.fixture
def base_l1_backend():
    return create_backend(
        BackendConfig(
            backend_type="base-l1",
            base_l1_parallel_threads=16,
            base_l1_block_time_ms=500,
            operator_address="validator-test",
        )
    )


@pytest.fixture
def ethereum_backend():
    return create_backend(
        BackendConfig(
            backend_type="ethereum",
            eth_finality_mode="latest",
            eth_confirmations=1,
        )
    )


@pytest.fixture
def ethereum_l2_backend():
    return create_backend(
        BackendConfig(
            backend_type="ethereum",
            eth_use_l2=True,
            eth_l2_name="base",
            eth_finality_mode="latest",
            eth_confirmations=0,
        )
    )


ALL_BACKENDS = ["local_backend", "base_l1_backend", "ethereum_backend"]


def _sample_record(entity_id: str = None) -> tuple[str, bytes, bytes, bytes]:
    """Generate sample commitment data."""
    eid = entity_id or canonical_hash(b"test-entity-" + bytes(range(32)))
    record_bytes = b'{"entity_id":"' + eid.encode() + b'","shape":"text/plain"}'
    signature = b"\x00" * 64
    sender_vk = b"\x01" * 32
    return eid, record_bytes, signature, sender_vk


# ---------------------------------------------------------------------------
# Factory tests
# ---------------------------------------------------------------------------


class TestFactory:
    def test_create_local(self):
        backend = create_backend(BackendConfig(backend_type="local"))
        assert isinstance(backend, LocalBackend)

    def test_create_base_l1(self):
        backend = create_backend(BackendConfig(backend_type="base-l1"))
        assert isinstance(backend, BaseL1Backend)

    def test_create_ethereum(self):
        backend = create_backend(BackendConfig(backend_type="ethereum"))
        assert isinstance(backend, EthereumBackend)

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            create_backend(BackendConfig(backend_type="nonexistent"))


# ---------------------------------------------------------------------------
# Interface contract tests (parameterized across all backends)
# ---------------------------------------------------------------------------


class TestBackendContract:
    """Every backend must satisfy these interface requirements."""

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_capabilities_returns_descriptor(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        caps = backend.capabilities()
        assert isinstance(caps, BackendCapabilities)
        assert isinstance(caps.finality, FinalityModel)
        assert caps.max_tps > 0

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_append_and_fetch(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        eid, rec, sig, vk = _sample_record()
        ref = backend.append_commitment(eid, rec, sig, vk)
        assert ref.startswith("sha3-256:")
        fetched = backend.fetch_commitment(eid)
        assert fetched is not None
        assert fetched["entity_id"] == eid

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_duplicate_append_raises(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        eid, rec, sig, vk = _sample_record()
        backend.append_commitment(eid, rec, sig, vk)
        with pytest.raises(ValueError, match="already committed"):
            backend.append_commitment(eid, rec, sig, vk)

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_fetch_nonexistent_returns_none(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        assert backend.fetch_commitment("nonexistent") is None

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_register_and_list_nodes(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        assert backend.register_node("node-1", "US-East", stake_wei=1000)
        assert backend.register_node("node-2", "EU-West", stake_wei=2000)
        active = backend.get_active_nodes()
        assert len(active) == 2
        node_ids = {n["node_id"] for n in active}
        assert "node-1" in node_ids
        assert "node-2" in node_ids

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_evict_removes_from_active(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        backend.register_node("node-evict", "US-East", stake_wei=5000)
        assert len(backend.get_active_nodes()) >= 1
        backend.evict_node("node-evict", "audit-failure")
        evicted_ids = {n["node_id"] for n in backend.get_active_nodes()}
        assert "node-evict" not in evicted_ids

    @pytest.mark.parametrize("backend_name", ALL_BACKENDS)
    def test_get_pricing_returns_dict(self, backend_name, request):
        backend = request.getfixturevalue(backend_name)
        pricing = backend.get_pricing()
        assert "cost_per_shard_per_epoch" in pricing
        assert "epoch_seconds" in pricing
        assert "currency" in pricing


# ---------------------------------------------------------------------------
# Local backend specific tests
# ---------------------------------------------------------------------------


class TestLocalBackend:
    def test_instant_finality(self, local_backend):
        eid, rec, sig, vk = _sample_record()
        local_backend.append_commitment(eid, rec, sig, vk)
        assert local_backend.is_finalized(eid) is True

    def test_no_slashing(self, local_backend):
        local_backend.register_node("n1", "US-East")
        assert local_backend.slash_node("n1", b"evidence") == 0

    def test_capabilities_instant(self, local_backend):
        caps = local_backend.capabilities()
        assert caps.finality == FinalityModel.INSTANT
        assert caps.estimated_finality_seconds == 0.0
        assert caps.gas_cost_per_commit is None


# ---------------------------------------------------------------------------
# Base L1 specific tests
# ---------------------------------------------------------------------------


class TestBaseL1Backend:
    def test_single_slot_finality(self, base_l1_backend):
        caps = base_l1_backend.capabilities()
        assert caps.finality == FinalityModel.SINGLE_SLOT
        assert caps.estimated_finality_seconds == 0.5

    def test_high_tps(self, base_l1_backend):
        caps = base_l1_backend.capabilities()
        assert caps.max_tps >= 10_000

    def test_native_storage_proofs(self, base_l1_backend):
        caps = base_l1_backend.capabilities()
        assert caps.has_native_storage_proofs is True

    def test_block_production(self, base_l1_backend):
        eid, rec, sig, vk = _sample_record()
        base_l1_backend.append_commitment(eid, rec, sig, vk)
        assert base_l1_backend.chain_height >= 1

    def test_commitment_finalized_after_block(self, base_l1_backend):
        eid, rec, sig, vk = _sample_record()
        base_l1_backend.append_commitment(eid, rec, sig, vk)
        assert base_l1_backend.is_finalized(eid) is True

    def test_verkle_proof_generation(self, base_l1_backend):
        eid, rec, sig, vk = _sample_record()
        base_l1_backend.append_commitment(eid, rec, sig, vk)
        proof = base_l1_backend.get_inclusion_proof(eid)
        assert proof is not None
        assert "verkle_proof" in proof
        vp = proof["verkle_proof"]
        assert "commitment_indices" in vp
        assert len(vp["commitment_indices"]) == 4

    def test_verkle_proof_verification(self, base_l1_backend):
        eid, rec, sig, vk = _sample_record()
        base_l1_backend.append_commitment(eid, rec, sig, vk)
        proof = base_l1_backend.get_inclusion_proof(eid)
        assert base_l1_backend.verify_inclusion(eid, proof) is True

    def test_node_staking_and_slashing(self, base_l1_backend):
        base_l1_backend.register_node("staked-node", "US-East", stake_wei=10_000)
        slashed = base_l1_backend.slash_node("staked-node", b"audit-evidence")
        assert slashed == 1_000  # 10% of 10,000

    def test_slash_pool_accumulates(self, base_l1_backend):
        base_l1_backend.register_node("slash-target", "EU-West", stake_wei=20_000)
        base_l1_backend.slash_node("slash-target", b"evidence")
        assert base_l1_backend.slash_pool == 2_000

    def test_eviction_triggers_slash(self, base_l1_backend):
        base_l1_backend.register_node("evict-target", "AP-East", stake_wei=50_000)
        initial_staked = base_l1_backend.total_staked
        base_l1_backend.evict_node("evict-target", "misbehavior")
        assert base_l1_backend.total_staked < initial_staked

    def test_min_stake_enforcement(self):
        backend = create_backend(
            BackendConfig(
                backend_type="base-l1",
                min_stake_wei=5000,
            )
        )
        assert backend.register_node("under-stake", "US-East", stake_wei=1000) is False
        assert backend.register_node("ok-stake", "US-East", stake_wei=5000) is True

    def test_multiple_commitments_in_blocks(self, base_l1_backend):
        for i in range(5):
            eid = canonical_hash(f"entity-{i}".encode())
            rec = f'{{"id":"{eid}","idx":{i}}}'.encode()
            base_l1_backend.append_commitment(eid, rec, b"\x00" * 64, b"\x01" * 32)
        assert base_l1_backend.total_commitments == 5
        assert base_l1_backend.chain_height >= 5

    def test_pricing_uses_native_token(self, base_l1_backend):
        pricing = base_l1_backend.get_pricing()
        assert pricing["currency"] == "LTP"
        assert pricing["block_time_ms"] == 500


# ---------------------------------------------------------------------------
# Ethereum backend specific tests
# ---------------------------------------------------------------------------


class TestEthereumBackend:
    def test_probabilistic_finality(self, ethereum_backend):
        caps = ethereum_backend.capabilities()
        assert caps.finality == FinalityModel.PROBABILISTIC

    def test_l1_block_time(self, ethereum_backend):
        pricing = ethereum_backend.get_pricing()
        assert pricing["block_time_seconds"] == 12
        assert pricing["is_l2"] is False

    def test_l2_configuration(self, ethereum_l2_backend):
        caps = ethereum_l2_backend.capabilities()
        assert caps.max_tps > 30  # L2 has higher TPS
        pricing = ethereum_l2_backend.get_pricing()
        assert pricing["is_l2"] is True
        assert pricing["l2_name"] == "base"
        assert pricing["block_time_seconds"] == 2

    def test_l2_cheaper_pricing(self, ethereum_l2_backend):
        pricing = ethereum_l2_backend.get_pricing()
        assert pricing["cost_per_shard_per_epoch"] < 100  # cheaper than L1

    def test_gas_accounting(self, ethereum_backend):
        eid, rec, sig, vk = _sample_record()
        ethereum_backend.append_commitment(eid, rec, sig, vk)
        assert ethereum_backend.total_gas_used > 0

    def test_transaction_receipts(self, ethereum_backend):
        eid, rec, sig, vk = _sample_record()
        ethereum_backend.append_commitment(eid, rec, sig, vk)
        assert ethereum_backend.transaction_count >= 1

    def test_mpt_proof_generation(self, ethereum_backend):
        eid, rec, sig, vk = _sample_record()
        ethereum_backend.append_commitment(eid, rec, sig, vk)
        proof = ethereum_backend.get_inclusion_proof(eid)
        assert proof is not None
        assert "mpt_proof" in proof
        mp = proof["mpt_proof"]
        assert "proof_nodes" in mp
        assert len(mp["proof_nodes"]) == 7  # typical MPT depth

    def test_mpt_proof_verification(self, ethereum_backend):
        eid, rec, sig, vk = _sample_record()
        ethereum_backend.append_commitment(eid, rec, sig, vk)
        proof = ethereum_backend.get_inclusion_proof(eid)
        assert ethereum_backend.verify_inclusion(eid, proof) is True

    def test_node_staking_and_slashing(self, ethereum_backend):
        ethereum_backend.register_node("eth-node", "US-East", stake_wei=100_000)
        slashed = ethereum_backend.slash_node("eth-node", b"evidence")
        assert slashed == 10_000  # 10% of 100,000

    def test_finality_mode_latest(self):
        backend = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="latest",
                eth_confirmations=0,
            )
        )
        eid, rec, sig, vk = _sample_record()
        backend.append_commitment(eid, rec, sig, vk)
        assert backend.is_finalized(eid) is True

    def test_eth_uses_eth_currency(self, ethereum_backend):
        pricing = ethereum_backend.get_pricing()
        assert pricing["currency"] == "ETH"

    def test_multiple_commitments_produce_blocks(self, ethereum_backend):
        for i in range(3):
            eid = canonical_hash(f"eth-entity-{i}".encode())
            rec = f'{{"id":"{eid}"}}'.encode()
            ethereum_backend.append_commitment(eid, rec, b"\x00" * 64, b"\x01" * 32)
        assert ethereum_backend.chain_height >= 3


# ---------------------------------------------------------------------------
# Comparison tests — verify relative properties across backends
# ---------------------------------------------------------------------------


class TestBackendComparison:
    def test_base_l1_faster_finality_than_ethereum_safe(self, base_l1_backend):
        """Compare Base L1 finality against Ethereum in 'safe' mode (realistic)."""
        eth_safe = create_backend(
            BackendConfig(
                backend_type="ethereum",
                eth_finality_mode="safe",
            )
        )
        base_l1_caps = base_l1_backend.capabilities()
        eth_caps = eth_safe.capabilities()
        assert base_l1_caps.estimated_finality_seconds < eth_caps.estimated_finality_seconds

    def test_base_l1_higher_tps_than_ethereum(self, base_l1_backend, ethereum_backend):
        base_l1_caps = base_l1_backend.capabilities()
        eth_caps = ethereum_backend.capabilities()
        assert base_l1_caps.max_tps > eth_caps.max_tps

    def test_both_support_slashing(self, base_l1_backend, ethereum_backend):
        base_l1_caps = base_l1_backend.capabilities()
        eth_caps = ethereum_backend.capabilities()
        assert base_l1_caps.has_slashing is True
        assert eth_caps.has_slashing is True

    def test_base_l1_has_native_proofs_ethereum_does_not(self, base_l1_backend, ethereum_backend):
        assert base_l1_backend.capabilities().has_native_storage_proofs is True
        assert ethereum_backend.capabilities().has_native_storage_proofs is False

    def test_all_backends_commit_and_fetch_identically(
        self, local_backend, base_l1_backend, ethereum_backend
    ):
        """The same entity committed to all three backends should be fetchable."""
        for i, backend in enumerate([local_backend, base_l1_backend, ethereum_backend]):
            eid = canonical_hash(f"cross-backend-{i}".encode())
            rec = f'{{"entity_id":"{eid}"}}'.encode()
            ref = backend.append_commitment(eid, rec, b"\x00" * 64, b"\x01" * 32)
            assert ref.startswith("sha3-256:")
            fetched = backend.fetch_commitment(eid)
            assert fetched is not None
            assert fetched["entity_id"] == eid
