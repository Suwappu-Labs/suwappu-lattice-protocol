"""
Shared pytest fixtures for the LTP test suite.

Fixtures are organized by scope:
  - session: keypairs (expensive key generation, reused across all tests)
  - function: network and protocol (fresh instance per test to avoid state bleed)
"""

import os

import pytest

# LTP-A-032 Phase 4c: the implicit-HSM flag is default-on in production.
# Many legacy tests still read kp.dk/kp.sk directly or pass kp.sk into
# helpers that expect raw bytes. Opt those tests out at the suite level
# until a dedicated migration pass (Phase 4e) rewrites each call site.
# Tests/files that explicitly want the production default (implicit-HSM
# on) monkeypatch this env var to a truthy value or unset it.
os.environ.setdefault("LTP_KEYPAIR_IMPLICIT_HSM", "0")

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol, reset_poc_state


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
