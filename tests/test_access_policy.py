"""Access-policy enforcement (whitepaper §2.2.1, §2.3.1 step 2).

Unit tests for the policy algebra in ltp.access_policy — kept aligned with
the machine-checked model in formal/lean/Ltp/Policy.lean — plus end-to-end
enforcement through LTPProtocol.materialize: one-time exhaustion, time
windows, fail-closed rejection of unknown types, rollback of the
materialization slot on failed attempts, and race-safety under concurrency.
"""

from __future__ import annotations

import threading

import pytest

from src.ltp.access_policy import KNOWN_POLICY_TYPES, PolicyViolation, check_policy
from src.ltp.commitment import CommitmentNetwork
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair
from src.ltp.protocol import LTPProtocol

NOW = 1_740_422_400.0  # fixed policy clock for determinism


# ---------------------------------------------------------------------------
# Unit: check_policy — the permits() algebra
# ---------------------------------------------------------------------------


class TestCheckPolicy:
    def test_unrestricted_permits_any_count(self):
        for count in (0, 1, 10, 10_000):
            check_policy({"type": "unrestricted"}, count, NOW)

    def test_one_time_defaults_to_limit_one(self):
        check_policy({"type": "one-time"}, 0, NOW)
        with pytest.raises(PolicyViolation, match="exhausted"):
            check_policy({"type": "one-time"}, 1, NOW)

    def test_explicit_max_materializations(self):
        policy = {"type": "one-time", "max_materializations": 3}
        for count in (0, 1, 2):
            check_policy(policy, count, NOW)
        with pytest.raises(PolicyViolation, match="exhausted"):
            check_policy(policy, 3, NOW)

    def test_count_bound_is_strict_lean_countok(self):
        """Lean countOk: count < m permits, count >= m denies — boundary exact."""
        policy = {"type": "time-limited", "max_materializations": 1}
        check_policy(policy, 0, NOW)
        with pytest.raises(PolicyViolation):
            check_policy(policy, 1, NOW)

    def test_time_window(self):
        policy = {"type": "time-limited", "not_before": NOW - 10, "not_after": NOW + 10}
        check_policy(policy, 0, NOW)
        check_policy(policy, 0, NOW - 10)  # inclusive lower bound (Lean lowerOk)
        check_policy(policy, 0, NOW + 10)  # inclusive upper bound (Lean upperOk)
        with pytest.raises(PolicyViolation, match="not yet open"):
            check_policy(policy, 0, NOW - 11)
        with pytest.raises(PolicyViolation, match="expired"):
            check_policy(policy, 0, NOW + 11)

    def test_window_enforced_for_every_type(self):
        """Presence of a constraint always constrains, whatever the type."""
        for ptype in KNOWN_POLICY_TYPES:
            with pytest.raises(PolicyViolation):
                check_policy({"type": ptype, "not_after": NOW - 1}, 0, NOW)

    def test_unknown_type_fails_closed(self):
        for bad in ("availability-test", "", None, 7):
            with pytest.raises(PolicyViolation, match="fail-closed"):
                check_policy({"type": bad}, 0, NOW)

    def test_non_dict_policy_rejected(self):
        for bad in (None, "unrestricted", ["unrestricted"], b"{}"):
            with pytest.raises(PolicyViolation):
                check_policy(bad, 0, NOW)

    def test_malformed_fields_rejected(self):
        with pytest.raises(PolicyViolation, match="not_after"):
            check_policy({"type": "time-limited", "not_after": "2026-03-24"}, 0, NOW)
        with pytest.raises(PolicyViolation, match="not_before"):
            check_policy({"type": "time-limited", "not_before": True}, 0, NOW)
        for bad_limit in (-1, 1.5, "2", True):
            with pytest.raises(PolicyViolation, match="max_materializations"):
                check_policy({"type": "one-time", "max_materializations": bad_limit}, 0, NOW)

    def test_zero_limit_is_expressible_revocation(self):
        with pytest.raises(PolicyViolation, match="exhausted"):
            check_policy({"type": "time-limited", "max_materializations": 0}, 0, NOW)

    def test_permits_antitone_in_count(self):
        """Lean permits_antitone_count: permitting at c2 permits at any c1 <= c2."""
        policy = {"type": "delegatable", "max_materializations": 5}
        check_policy(policy, 4, NOW)
        for lower in range(4):
            check_policy(policy, lower, NOW)


# ---------------------------------------------------------------------------
# End-to-end: enforcement inside materialize
# ---------------------------------------------------------------------------


@pytest.fixture
def rig():
    network = CommitmentNetwork()
    for i in range(8):
        network.add_node(f"node-{i}", ["us", "eu", "ap", "sa"][i % 4])
    protocol = LTPProtocol(network)
    alice = KeyPair.generate("alice")
    bob = KeyPair.generate("bob")
    content = b"policy enforcement end-to-end payload"
    entity = Entity(content=content, shape="text/plain")
    entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
    return protocol, entity_id, record, cek, bob, content


class TestMaterializeEnforcement:
    def test_one_time_key_exhausts(self, rig):
        protocol, entity_id, record, cek, bob, content = rig
        sealed = protocol.lattice(entity_id, record, cek, bob, access_policy={"type": "one-time"})
        assert protocol.materialize(sealed, bob, record) == content
        assert protocol.materialize(sealed, bob, record) is None

    def test_max_materializations_honored(self, rig):
        protocol, entity_id, record, cek, bob, content = rig
        sealed = protocol.lattice(
            entity_id,
            record,
            cek,
            bob,
            access_policy={"type": "time-limited", "max_materializations": 3},
        )
        for _ in range(3):
            assert protocol.materialize(sealed, bob, record) == content
        assert protocol.materialize(sealed, bob, record) is None

    def test_fresh_seal_is_a_fresh_capability(self, rig):
        """Counts attach to the sealed key, not the entity: a new seal of the
        same entity starts a new count."""
        protocol, entity_id, record, cek, bob, content = rig
        first = protocol.lattice(entity_id, record, cek, bob, access_policy={"type": "one-time"})
        second = protocol.lattice(entity_id, record, cek, bob, access_policy={"type": "one-time"})
        assert protocol.materialize(first, bob, record) == content
        assert protocol.materialize(first, bob, record) is None
        assert protocol.materialize(second, bob, record) == content

    def test_window_denied_before_and_after(self, rig):
        protocol, entity_id, record, cek, bob, content = rig
        policy = {"type": "time-limited", "not_before": NOW, "not_after": NOW + 100}
        sealed = protocol.lattice(entity_id, record, cek, bob, access_policy=policy)
        assert protocol.materialize(sealed, bob, record, now=NOW - 1) is None
        assert protocol.materialize(sealed, bob, record, now=NOW + 101) is None
        assert protocol.materialize(sealed, bob, record, now=NOW + 50) == content

    def test_unknown_type_rejected_at_seal(self, rig):
        """A conforming sender fails fast: lattice() refuses to seal a key
        that no conforming receiver would honor."""
        protocol, entity_id, record, cek, bob, _ = rig
        with pytest.raises(PolicyViolation, match="fail-closed"):
            protocol.lattice(
                entity_id, record, cek, bob, access_policy={"type": "availability-test"}
            )

    def test_unknown_type_denied_end_to_end(self, rig):
        """A NON-conforming sender that seals a junk policy directly (bypassing
        lattice()'s validation) is still denied by the receiver."""
        from src.ltp.lattice import LatticeKey
        from src.ltp.primitives import canonical_hash

        protocol, entity_id, record, cek, bob, _ = rig
        rogue = LatticeKey(
            entity_id=entity_id,
            cek=cek,
            commitment_ref=canonical_hash(record.to_bytes()),
            access_policy={"type": "availability-test"},
        )
        sealed = rogue.seal(bob.ek)
        assert protocol.materialize(sealed, bob, record) is None

    def test_default_policy_is_unrestricted(self, rig):
        protocol, entity_id, record, cek, bob, content = rig
        sealed = protocol.lattice(entity_id, record, cek, bob)
        for _ in range(4):
            assert protocol.materialize(sealed, bob, record) == content

    def test_failed_attempt_does_not_consume(self, rig):
        """A materialization that fails after the policy gate (here: shard
        shortage) releases its reserved slot — counts track completions."""
        protocol, entity_id, record, cek, bob, content = rig
        sealed = protocol.lattice(entity_id, record, cek, bob, access_policy={"type": "one-time"})

        # Destroy all shards so the attempt fails downstream of the gate.
        stashed = []
        for node in list(protocol.network.nodes):
            for idx in range(8):
                data = node.fetch_shard(entity_id, idx)
                if data is not None:
                    stashed.append((node, idx, data))
                    node.remove_shard(entity_id, idx)
        assert protocol.materialize(sealed, bob, record) is None

        # Restore shards: the one-time slot must still be available.
        for node, idx, data in stashed:
            node.store_shard(entity_id, idx, data)
        assert protocol.materialize(sealed, bob, record) == content
        assert protocol.materialize(sealed, bob, record) is None

    def test_denial_precedes_any_fetch(self, rig):
        """§2.3.1: policy failure aborts before shard fetch — an expired key
        is denied even when no shards exist at all (no fetch was attempted)."""
        protocol, entity_id, record, cek, bob, _ = rig
        sealed = protocol.lattice(
            entity_id,
            record,
            cek,
            bob,
            access_policy={"type": "time-limited", "not_after": NOW - 1},
        )
        fetch_calls = []
        original = protocol.network.fetch_encrypted_shards

        def spy(*args, **kwargs):
            fetch_calls.append(args)
            return original(*args, **kwargs)

        protocol.network.fetch_encrypted_shards = spy
        try:
            assert protocol.materialize(sealed, bob, record, now=NOW) is None
        finally:
            protocol.network.fetch_encrypted_shards = original
        assert fetch_calls == []

    def test_one_time_race_admits_exactly_one(self, rig):
        """Concurrent attempts under a one-time key: the slot reservation is
        atomic, so exactly one materialization completes."""
        protocol, entity_id, record, cek, bob, content = rig
        sealed = protocol.lattice(entity_id, record, cek, bob, access_policy={"type": "one-time"})

        results = []
        barrier = threading.Barrier(4)

        def attempt():
            barrier.wait()
            results.append(protocol.materialize(sealed, bob, record))

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(content) == 1
        assert results.count(None) == 3
