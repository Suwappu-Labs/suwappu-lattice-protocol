"""
Shared pytest fixtures for the LTP test suite.

Fixtures are organized by scope:
  - session: keypairs (expensive key generation, reused across all tests)
  - function: network and protocol (fresh instance per test to avoid state bleed)
"""

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol, reset_poc_state


# ---------------------------------------------------------------------------
# LTP-A-032 Phase 4c — module-scoped opt-out from implicit-HSM
# ---------------------------------------------------------------------------
#
# Production runs with `LTP_KEYPAIR_IMPLICIT_HSM` default-on, so
# `KeyPair.generate(hsm=None)` returns sentinel-backed keypairs. The
# modules listed below still read raw `kp.sk` / `kp.dk` bytes or pass
# them into helpers that have not yet been migrated to `KeyPair.sign`
# / `KeyPair.decaps`. Until Phase 4e migrates them, each test in those
# modules gets `LTP_KEYPAIR_IMPLICIT_HSM=0` automatically.
#
# **Tests in any other module run under the production default** —
# i.e. new tests written against this suite exercise the implicit-HSM
# code path by default. Tests that need plaintext explicitly add the
# `_legacy_plaintext_keypair` fixture or monkeypatch the env var.
#
# Shrink this list as Phase 4e migrates each module.
LEGACY_PLAINTEXT_TEST_MODULES = frozenset({
    # Phase 4e will migrate these one at a time onto KeyPair.sign/decaps.
    "test_acvp_mldsa",
    "test_acvp_mlkem",
    "test_anchor_scheduler",
    "test_anchor_verifier",
    "test_backend_boundaries",
    "test_bls_attestation",
    "test_bls_e2e",
    "test_bls_keys",
    "test_commitment",
    "test_compliance",
    "test_cross_network_e2e",
    "test_cross_network_fetcher",
    "test_domain_separation",
    "test_encoding",
    "test_federation",
    "test_federation_agreement",
    "test_federation_gate_closure",
    "test_federation_rate_limiter",
    "test_gossip_core",
    "test_gossip_grpc",
    "test_gossip_integration",
    "test_key_lifecycle",
    "test_key_rotation",
    "test_merkle_log",
    "test_optimistic_bridge",
    "test_primitives",
    "test_production_gate",
    "test_security_audit",
    "test_shard_distribution",
    "test_stark_bridge",
    "test_timing_analysis",
    "test_zk_bridge",
    "test_zk_e2e",
})


@pytest.fixture
def _legacy_plaintext_keypair(monkeypatch):
    """Opt out of implicit-HSM mode so kp.sk / kp.dk hold plaintext.

    Auto-applied to modules in `LEGACY_PLAINTEXT_TEST_MODULES`.
    Available as an explicit fixture for any other test that needs to
    inspect plaintext key material (e.g. AEAD wrong-key probes).
    """
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "0")


def pytest_collection_modifyitems(config, items):
    """Apply `_legacy_plaintext_keypair` to legacy modules."""
    for item in items:
        mod_name = item.module.__name__.rsplit(".", 1)[-1]
        if mod_name in LEGACY_PLAINTEXT_TEST_MODULES:
            item.fixturenames.append("_legacy_plaintext_keypair")


# ---------------------------------------------------------------------------
# Keypairs (session scope — generation is expensive)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def alice() -> KeyPair:
    """Alice — the sender keypair."""
    return KeyPair.generate("alice")


@pytest.fixture(scope="session")
def bob() -> KeyPair:
    """Bob — the authorized receiver keypair."""
    return KeyPair.generate("bob")


@pytest.fixture(scope="session")
def eve() -> KeyPair:
    """Eve — the unauthorized attacker keypair."""
    return KeyPair.generate("eve-attacker")


# ---------------------------------------------------------------------------
# Network and protocol (function scope — fresh per test)
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_poc_state() -> None:
    """Reset PoC simulation state. Use for tests that need clean crypto tables.

    Not autouse because session-scoped keypair fixtures populate the PoC
    lookup tables at session start — clearing them would invalidate all
    previously generated keys. Request this fixture explicitly when a test
    needs guaranteed-clean state.
    """
    reset_poc_state()


@pytest.fixture
def network() -> CommitmentNetwork:
    """Six-node commitment network spanning three regions."""
    net = CommitmentNetwork()
    for node_id, region in [
        ("node-us-east-1", "US-East"),
        ("node-us-west-1", "US-West"),
        ("node-eu-west-1", "EU-West"),
        ("node-eu-east-1", "EU-East"),
        ("node-ap-east-1", "AP-East"),
        ("node-ap-south-1", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return net


@pytest.fixture
def protocol(network: CommitmentNetwork) -> LTPProtocol:
    """Fresh LTPProtocol instance backed by the function-scoped network."""
    return LTPProtocol(network)
