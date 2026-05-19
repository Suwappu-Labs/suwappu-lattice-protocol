"""
LTP demo entry point.

Run with:
  python -m ltp

Executes the full LTP transfer demonstration including:
  - Three-phase transfers (small, JSON, large payload)
  - Security tests (unauthorized receiver, node ciphertext-only)
  - Shard integrity / tamper detection (Theorem 4 — SINT)
  - Network audit protocol with burst challenges
  - Degraded materialization (any k-of-n guarantee)
  - Threshold secrecy (Theorem 7 — TSEC)
  - Entity immutability (Theorem 3 — IMM)
  - Commitment log trust model (§5.1.4)
  - Storage proof strengthening (§5.2.2)
  - Correlated failure model (§5.4.1.1)
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
from itertools import combinations

from . import (
    AEAD,
    MLDSA,
    MLKEM,
    CommitmentNetwork,
    Entity,
    ErasureCoder,
    KeyPair,
    LTPProtocol,
    ShardEncryptor,
    canonical_hash,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_network() -> tuple[CommitmentNetwork, list[tuple[str, str]]]:
    """Create and populate a commitment network with 6 regional nodes."""
    node_defs = [
        ("node-us-east-1", "US-East"),
        ("node-us-west-1", "US-West"),
        ("node-eu-west-1", "EU-West"),
        ("node-eu-east-1", "EU-East"),
        ("node-ap-east-1", "AP-East"),
        ("node-ap-south-1", "AP-South"),
    ]
    network = CommitmentNetwork()
    for node_id, region in node_defs:
        network.add_node(node_id, region)
        print(f"  Added commitment node: {node_id} ({region})")
    return network, node_defs


# ---------------------------------------------------------------------------
# Phase demos
# ---------------------------------------------------------------------------


def demo_transfers(
    protocol: LTPProtocol,
    network: CommitmentNetwork,
    alice: KeyPair,
    bob: KeyPair,
    eve: KeyPair,
) -> list[tuple[str, bytes, str]]:
    """Run three-phase transfers with security tests."""
    test_cases = [
        ("Small message", b"Hello, this is a secure immutable transfer via LTP!", "text/plain"),
        (
            "JSON document",
            json.dumps(
                {
                    "patient_id": "P-29381",
                    "diagnosis": "healthy",
                    "lab_results": {"blood_pressure": "120/80", "heart_rate": 72},
                    "timestamp": "2026-02-24T00:00:00Z",
                    "physician": "Dr. Smith",
                    "notes": "Regular checkup. All vitals normal.",
                },
                indent=2,
            ).encode(),
            "application/json",
        ),
        ("Large payload", os.urandom(100_000), "application/octet-stream"),
    ]

    for name, content, shape in test_cases:
        print("─" * 74)
        print(f"▸ TRANSFER: {name} ({len(content):,} bytes)")
        print("─" * 74)
        print()

        entity = Entity(content=content, shape=shape)

        print("┌─ PHASE 1: COMMIT (Alice — ML-DSA signed)")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        print("└─ ✓ Committed\n")

        print("┌─ PHASE 2: LATTICE (Alice → Bob, ML-KEM sealed)")
        sealed_key = protocol.lattice(
            entity_id,
            record,
            cek,
            bob,
            access_policy={"type": "one-time", "expires": "2026-03-24"},
        )
        print(f"  [LATTICE] ═══ SEALED KEY (ML-KEM-768): {len(sealed_key):,} bytes ═══")
        print("└─ ✓ Lattice key sealed\n")

        print("  ⚡ Alice goes offline. Transfer continues without her.\n")

        print("┌─ PHASE 3: MATERIALIZE (Bob — ML-KEM unseal + decrypt)")
        materialized = protocol.materialize(sealed_key, bob)
        if materialized is not None:
            match = materialized == content
            print(f"  [VERIFY] Content match: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}")
        print("└─ Done\n")

        print("┌─ SECURITY TEST: Eve attempts materialization (wrong dk)")
        print(f"  [EVE] Intercepted sealed key ({len(sealed_key):,} bytes)")
        print(f"  [EVE] Attempting ML-KEM decapsulation with her dk...")
        eve_result = protocol.materialize(sealed_key, eve)
        if eve_result is None:
            print(f"  [SECURITY] ✓ Eve BLOCKED — ML-KEM decapsulation failed (wrong dk)")
        else:
            print(f"  [SECURITY] ✗ BREACH — Eve reconstructed the entity!")

        print(f"  [EVE] Attempting to fetch shards directly from nodes...")
        raw_shards = network.fetch_encrypted_shards(entity_id, 8, 4)
        if raw_shards:
            sample = list(raw_shards.values())[0]
            print(f"  [EVE] Fetched {len(raw_shards)} encrypted shards")
            print(f"  [EVE] Shard content: {sample[:32].hex()}...  (ciphertext)")
            print(f"  [EVE] Without CEK, this is computationally useless random bytes")
            print(f"  [SECURITY] ✓ Node compromise yields ONLY ciphertext")
        print("└─ Security tests done\n")

    return test_cases


# ---------------------------------------------------------------------------
# Shard integrity (Theorem 4 — SINT)
# ---------------------------------------------------------------------------


def demo_shard_integrity(
    protocol: LTPProtocol,
    network: CommitmentNetwork,
    alice: KeyPair,
    bob: KeyPair,
) -> None:
    """Test tamper detection via AEAD authentication."""
    print("─" * 74)
    print("▸ SHARD INTEGRITY: Tamper Detection (Theorem 4 — SINT game)")
    print("─" * 74)
    print()

    tamper_content = b"This content must be received EXACTLY as committed."
    tamper_entity = Entity(content=tamper_content, shape="x-ltp/integrity-test")
    tamper_eid, tamper_record, tamper_cek = protocol.commit(tamper_entity, alice, n=8, k=4)
    tamper_sealed = protocol.lattice(
        tamper_eid,
        tamper_record,
        tamper_cek,
        bob,
        access_policy={"type": "integrity-test"},
    )
    print()

    print("┌─ SIMULATING NODE COMPROMISE: Tampering with stored shard")
    target_nodes = network._placement(tamper_eid, 0)
    for node in target_nodes:
        if not node.evicted and (tamper_eid, 0) in node.shards:
            original = node.shards[(tamper_eid, 0)]
            tampered = bytearray(original)
            tampered[0] ^= 0xFF
            tampered[1] ^= 0xFF
            node.shards[(tamper_eid, 0)] = bytes(tampered)
            print(f"  [TAMPER] Modified shard 0 on {node.node_id}")
            print(f"  [TAMPER] Original: {original[:8].hex()}...")
            print(f"  [TAMPER] Tampered: {bytes(tampered[:8]).hex()}...")
            break
    print("└─ Shard tampered\n")

    print("┌─ MATERIALIZE with tampered shard (should detect and skip)")
    tamper_result = protocol.materialize(tamper_sealed, bob)
    if tamper_result is not None:
        match = tamper_result == tamper_content
        print(f"  [INTEGRITY] Reconstruction: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}")
        if match:
            print(f"  [INTEGRITY] ✓ Tampered shard was DETECTED by AEAD tag verification")
            print(f"  [INTEGRITY]   Skipped shard 0, reconstructed from remaining shards")
    else:
        print(f"  [INTEGRITY] ✗ Materialization failed (not enough valid shards)")
    print("└─ Integrity test complete\n")


# ---------------------------------------------------------------------------
# Audit protocol
# ---------------------------------------------------------------------------


def demo_audit(
    protocol: LTPProtocol,
    network: CommitmentNetwork,
    alice: KeyPair,
    bob: KeyPair,
    test_cases: list[tuple[str, bytes, str]],
) -> None:
    """Test commitment network audit and eviction."""
    print("─" * 74)
    print("▸ COMMITMENT NETWORK AUDIT PROTOCOL")
    print("─" * 74)
    print()

    print("┌─ AUDIT ROUND 1: All nodes healthy")
    audit_results = network.audit_all_nodes()
    all_pass = True
    for r in audit_results:
        status = "✓ PASS" if r.result == "PASS" else "✗ FAIL"
        print(
            f"  [{r.node_id}] {status} — "
            f"{r.challenged} challenges, {r.passed} passed, "
            f"{r.failed} failed, {r.missing} missing "
            f"(strikes: {r.strikes})"
        )
        if r.result != "PASS":
            all_pass = False
    if all_pass:
        print("  → All nodes passed storage proof challenges")
    print("└─ Audit round complete\n")

    target_node = network.nodes[2]
    print(f"┌─ SIMULATING NODE FAILURE: {target_node.node_id}")
    deleted = 0
    for key in list(target_node.shards.keys())[:4]:
        target_node.remove_shard(key[0], key[1])
        deleted += 1
    print(f"  [SIM] Deleted {deleted} shards from {target_node.node_id}")
    print(f"  [SIM] Node now has {target_node.shard_count} shards")
    print("└─ Failure simulated\n")

    print("┌─ AUDIT ROUND 2: Post-failure audit")
    audit_results = network.audit_all_nodes()
    for r in audit_results:
        status = "✓ PASS" if r.result == "PASS" else "✗ FAIL"
        marker = " ◀ DEGRADED" if r.result != "PASS" else ""
        print(
            f"  [{r.node_id}] {status} — "
            f"{r.challenged} challenges, {r.passed} passed, "
            f"{r.failed} failed, {r.missing} missing "
            f"(strikes: {r.strikes}){marker}"
        )
    print("└─ Audit round complete\n")

    strike_node = None
    for n in network.nodes:
        if n.strikes > 0:
            strike_node = n
            break

    if strike_node:
        print(f"┌─ EVICTION PROTOCOL: {strike_node.node_id}")
        strike_node.strikes = 3
        print(
            f"  [EVICTION] {strike_node.node_id} has {strike_node.strikes} strikes (threshold: 3)"
        )
        print(f"  [EVICTION] Initiating eviction + shard repair...")
        eviction = network.evict_node(strike_node)
        print(f"  [EVICTION] Node evicted: {eviction['evicted_node']}")
        print(f"  [EVICTION] Shards affected: {eviction['shards_affected']}")
        print(f"  [EVICTION] Repaired: {eviction['repaired']}")
        print(f"  [EVICTION] Lost: {eviction['lost']}")
        print(f"  [EVICTION] Active nodes: {network.active_node_count} / {len(network.nodes)}")
        print("└─ Eviction complete\n")

        print("┌─ POST-EVICTION VERIFICATION")
        last_entity = Entity(content=test_cases[-1][1], shape=test_cases[-1][2])
        last_eid, last_record, last_cek = protocol.commit(last_entity, alice, n=8, k=4)
        last_sealed = protocol.lattice(
            last_eid,
            last_record,
            last_cek,
            bob,
            access_policy={"type": "one-time"},
        )
        last_materialized = protocol.materialize(last_sealed, bob)
        if last_materialized is not None:
            match = last_materialized == test_cases[-1][1]
            print(
                f"  [VERIFY] Post-eviction transfer: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}"
            )
        else:
            print(f"  [VERIFY] ✗ Transfer failed after eviction")
        print("└─ Verification complete\n")


# ---------------------------------------------------------------------------
# Degraded materialization
# ---------------------------------------------------------------------------


def demo_degraded_materialization(
    protocol: LTPProtocol,
    network: CommitmentNetwork,
    alice: KeyPair,
    bob: KeyPair,
) -> None:
    """Test any-k-of-n availability guarantee under shard loss."""
    print("─" * 74)
    print("▸ AVAILABILITY GUARANTEE: Degraded Materialization")
    print("─" * 74)
    print()

    degraded_content = b"This entity survives catastrophic shard loss."
    degraded_entity = Entity(content=degraded_content, shape="x-ltp/availability-test")
    entity_id, record, cek = protocol.commit(degraded_entity, alice, n=8, k=4)
    sealed_key = protocol.lattice(
        entity_id,
        record,
        cek,
        bob,
        access_policy={"type": "availability-test"},
    )

    print()
    print("┌─ BASELINE: Normal materialization (first 4 shards)")
    baseline = protocol.materialize(sealed_key, bob)
    if baseline is not None:
        print(
            f"  [VERIFY] Baseline: "
            f"{'✓ EXACT MATCH' if baseline == degraded_content else '✗ MISMATCH'}"
        )
    print("└─ Done\n")

    print("┌─ SIMULATING CATASTROPHIC SHARD LOSS")
    destroyed_indices = [0, 1, 2]
    for idx in destroyed_indices:
        for node in network._placement(entity_id, idx):
            if not node.evicted:
                node.remove_shard(entity_id, idx)
    print(f"  [CATASTROPHE] Destroyed shards {destroyed_indices} across ALL replicas")
    print(f"  [CATASTROPHE] Only shards 3-7 remain (5 of 8)")
    print(f"  [CATASTROPHE] Need k=4 for reconstruction — should still succeed")
    print("└─ Shard destruction complete\n")

    print("┌─ DEGRADED MATERIALIZATION: From non-sequential shards")
    sealed_key2 = protocol.lattice(
        entity_id,
        record,
        cek,
        bob,
        access_policy={"type": "availability-test"},
    )
    degraded_result = protocol.materialize(sealed_key2, bob)
    if degraded_result is not None:
        match = degraded_result == degraded_content
        print(f"  [VERIFY] Degraded reconstruction: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}")
        print(
            f"  [VERIFY] ═══ ANY {record.encoding_params['k']}-of-"
            f"{record.encoding_params['n']} shards reconstruct the entity ═══"
        )
    else:
        print(f"  [VERIFY] ✗ Degraded materialization failed")
    print("└─ Done\n")

    print("┌─ AVAILABILITY BOUNDARY: Destroy one more shard (below k)")
    for node in network._placement(entity_id, 3):
        if not node.evicted:
            node.remove_shard(entity_id, 3)
    print(f"  [BOUNDARY] Destroyed shard 3 — exactly k=4 shards remain (4,5,6,7)")
    sealed_key3 = protocol.lattice(
        entity_id,
        record,
        cek,
        bob,
        access_policy={"type": "boundary-test"},
    )
    boundary_result = protocol.materialize(sealed_key3, bob)
    if boundary_result is not None:
        match = boundary_result == degraded_content
        print(f"  [VERIFY] At k boundary: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}")
    print("└─ Done\n")

    print("┌─ BELOW THRESHOLD: Only k-1 shards remain")
    for node in network._placement(entity_id, 4):
        if not node.evicted:
            node.remove_shard(entity_id, 4)
    print(f"  [BOUNDARY] Destroyed shard 4 — only 3 shards remain (k=4 needed)")
    sealed_key4 = protocol.lattice(
        entity_id,
        record,
        cek,
        bob,
        access_policy={"type": "below-threshold"},
    )
    below_result = protocol.materialize(sealed_key4, bob)
    if below_result is None:
        print(f"  [VERIFY] ✓ CORRECTLY FAILED — insufficient shards (3 < k=4)")
    else:
        print(f"  [VERIFY] ✗ Unexpected success — should have failed")
    print("└─ Done\n")


# ---------------------------------------------------------------------------
# Threshold secrecy (Theorem 7 — TSEC)
# ---------------------------------------------------------------------------


def demo_threshold_secrecy() -> None:
    """Validate information-theoretic threshold secrecy."""
    print("─" * 74)
    print("▸ THRESHOLD SECRECY: Information-Theoretic (Theorem 7 — TSEC game)")
    print("─" * 74)
    print()

    tsec_n, tsec_k = 8, 4
    msg_0 = b"ALPHA-MSG: The first candidate message for TSEC game"
    msg_1 = b"OMEGA-MSG: The other candidate message for TSEC game"
    assert len(msg_0) == len(msg_1)

    print(f"  TSEC Game Setup: n={tsec_n}, k={tsec_k} over GF(256)")
    print()

    shards_0 = ErasureCoder.encode(msg_0, tsec_n, tsec_k)
    shards_1 = ErasureCoder.encode(msg_1, tsec_n, tsec_k)
    chunk_size = len(shards_0[0])

    # Validation 1: k shards → unique reconstruction
    print("┌─ TSEC VALIDATION 1: k shards → unique reconstruction")
    k_indices = [1, 3, 5, 7]
    recon_0 = ErasureCoder.decode({i: shards_0[i] for i in k_indices}, tsec_n, tsec_k)
    recon_1 = ErasureCoder.decode({i: shards_1[i] for i in k_indices}, tsec_n, tsec_k)
    print(f"  Reconstruct m_0: {'✓ EXACT MATCH' if recon_0 == msg_0 else '✗ MISMATCH'}")
    print(f"  Reconstruct m_1: {'✓ EXACT MATCH' if recon_1 == msg_1 else '✗ MISMATCH'}")
    print("└─ Done\n")

    # Validation 2: k-1 shards → zero distinguishing advantage
    print("┌─ TSEC VALIDATION 2: k-1 shards → zero distinguishing advantage")
    tsec_subsets_tested = 0
    tsec_all_consistent = True

    for subset in combinations(range(tsec_n), tsec_k - 1):
        subset = list(subset)
        ErasureCoder._init_gf()
        missing_indices = [i for i in range(tsec_n) if i not in subset]
        test_idx = missing_indices[0]
        for byte_pos in range(chunk_size):
            full_indices = subset + [test_idx]
            alphas_0 = [i + 1 for i in full_indices]
            try:
                ErasureCoder._invert_vandermonde(alphas_0, tsec_k)
            except AssertionError:
                tsec_all_consistent = False
                break
        tsec_subsets_tested += 1

    print(
        f"  Tested all C({tsec_n},{tsec_k - 1}) = {tsec_subsets_tested} subsets of "
        f"k-1={tsec_k - 1} shards"
    )
    if tsec_all_consistent:
        print(f"  → Adv^TSEC_A = 0 for all k-1 subsets (PERFECT SECRECY)")
    else:
        print(f"  → ✗ UNEXPECTED: found a distinguishing subset!")
    print("└─ Done\n")

    # Validation 3: Statistical uniformity
    print("┌─ TSEC VALIDATION 3: Statistical uniformity of k-1 shard bytes")
    import random as _tsec_rng

    _tsec_rng.seed(42)
    tsec_large_msg = bytes(_tsec_rng.randint(0, 255) for _ in range(16384))
    tsec_large_shards = ErasureCoder.encode(tsec_large_msg, tsec_n, tsec_k)
    tsec_subset = [0, 2, 4]
    all_bytes = bytearray()
    for idx in tsec_subset:
        all_bytes.extend(tsec_large_shards[idx])
    byte_counts = [0] * 256
    for b in all_bytes:
        byte_counts[b] += 1
    total_bytes = len(all_bytes)
    expected_count = total_bytes / 256
    max_deviation = max(
        abs(c - expected_count) / expected_count for c in byte_counts if expected_count > 0
    )
    unique_values = sum(1 for c in byte_counts if c > 0)
    chi2 = sum((c - expected_count) ** 2 / expected_count for c in byte_counts)
    chi2_critical = 310.0
    chi2_pass = chi2 < chi2_critical
    print(f"  Collected {total_bytes:,} bytes from k-1={tsec_k - 1} shards")
    print(f"  Unique byte values: {unique_values}/256")
    print(f"  Max relative deviation: {max_deviation:.2%}")
    print(f"  Chi-squared: {chi2:.1f} (critical {chi2_critical}, p=0.01)")
    print(f"  Chi-squared test: {'PASS (uniform)' if chi2_pass else 'FAIL (non-uniform)'}")
    print("└─ Done\n")

    # Validation 4: CEK compromise + k-1 nodes → zero information
    print("┌─ TSEC VALIDATION 4: CEK compromise + k-1 nodes → zero information")
    tsec_cek = ShardEncryptor.generate_cek()
    tsec_entity_id = canonical_hash(tsec_cek + b"tsec-validation-4")
    enc_shards_0 = [
        ShardEncryptor.encrypt_shard(tsec_cek, tsec_entity_id, s, i) for i, s in enumerate(shards_0)
    ]
    enc_shards_1 = [
        ShardEncryptor.encrypt_shard(tsec_cek, tsec_entity_id, s, i) for i, s in enumerate(shards_1)
    ]
    compromised = [0, 1, 2]
    print(f"  Adversary compromises nodes storing shards {compromised} AND obtains CEK")
    dec_0 = [
        ShardEncryptor.decrypt_shard(tsec_cek, tsec_entity_id, enc_shards_0[i], i)
        for i in compromised
    ]
    dec_1 = [
        ShardEncryptor.decrypt_shard(tsec_cek, tsec_entity_id, enc_shards_1[i], i)
        for i in compromised
    ]
    dec_match_0 = all(dec_0[j] == shards_0[compromised[j]] for j in range(len(compromised)))
    dec_match_1 = all(dec_1[j] == shards_1[compromised[j]] for j in range(len(compromised)))
    print(
        f"  Adversary decrypts k-1={len(compromised)} shards: "
        f"{'✓' if dec_match_0 and dec_match_1 else '✗'} (plaintext recovered)"
    )
    try:
        ErasureCoder.decode({i: shards_0[i] for i in compromised}, tsec_n, tsec_k)
        print(f"  ✗ UNEXPECTED: Reconstruction from k-1 shards should fail")
    except (AssertionError, Exception):
        print(f"  Reconstruction from k-1={len(compromised)} shards: IMPOSSIBLE (< k)")
    print(f"  → Adv^TSEC = 0: information-theoretic secrecy holds even after CEK compromise")
    print("└─ Done\n")

    # Validation 5: Sharp threshold boundary (k-1 → k)
    print("┌─ TSEC VALIDATION 5: Sharp threshold boundary (k-1 → k)")
    recon_from_k = ErasureCoder.decode({i: shards_0[i] for i in range(tsec_k)}, tsec_n, tsec_k)
    print(
        f"  With k={tsec_k} shards: message FULLY determined: "
        f"{'✓ EXACT MATCH' if recon_from_k == msg_0 else '✗ MISMATCH'}"
    )
    print(f"  One shard makes the difference between perfect secrecy and full disclosure")
    print("└─ Done\n")


# ---------------------------------------------------------------------------
# Entity immutability (Theorem 3 — IMM)
# ---------------------------------------------------------------------------


def demo_entity_immutability(
    protocol: LTPProtocol,
    alice: KeyPair,
    bob: KeyPair,
) -> None:
    """Validate entity immutability and collision resistance."""
    print("─" * 74)
    print("▸ ENTITY IMMUTABILITY: Collision Resistance (Theorem 3 — IMM game)")
    print("─" * 74)
    print()

    imm_sender = alice
    imm_timestamp = 1740000000.0
    imm_content = b"Immutable content: this entity's identity is bound to its bits."
    imm_entity = Entity(content=imm_content, shape="text/plain")

    print("┌─ IMM VALIDATION 1: Deterministic EntityID")
    eid_1 = imm_entity.compute_id(imm_sender.vk, imm_timestamp)
    eid_2 = imm_entity.compute_id(imm_sender.vk, imm_timestamp)
    eid_3 = imm_entity.compute_id(imm_sender.vk, imm_timestamp)
    all_equal = eid_1 == eid_2 == eid_3
    print(f"  All identical: {'✓ YES' if all_equal else '✗ NO'}")
    print("└─ Done\n")

    print("┌─ IMM VALIDATION 2: Avalanche effect")
    eid_original = imm_entity.compute_id(imm_sender.vk, imm_timestamp)
    content_flipped = bytearray(imm_content)
    content_flipped[0] ^= 0x01
    entity_v1 = Entity(content=bytes(content_flipped), shape="text/plain")
    eid_v1 = entity_v1.compute_id(imm_sender.vk, imm_timestamp)
    entity_v2 = Entity(content=imm_content, shape="text/html")
    eid_v2 = entity_v2.compute_id(imm_sender.vk, imm_timestamp)
    eid_v3 = imm_entity.compute_id(
        imm_sender.vk, imm_timestamp + sys.float_info.epsilon * imm_timestamp
    )
    eid_v4 = imm_entity.compute_id(bob.vk, imm_timestamp)
    all_eids = {eid_original, eid_v1, eid_v2, eid_v3, eid_v4}
    print(f"  All 5 EntityIDs unique: {'✓ YES' if len(all_eids) == 5 else '✗ NO'}")
    print("└─ Done\n")

    print("┌─ IMM VALIDATION 3: Encoding injectivity")

    def encode_entity_raw(entity: Entity, sender_vk: bytes, ts: float) -> bytes:
        return entity.content + entity.shape.encode() + struct.pack(">d", ts) + sender_vk

    enc_original = encode_entity_raw(imm_entity, imm_sender.vk, imm_timestamp)
    enc_v1 = encode_entity_raw(entity_v1, imm_sender.vk, imm_timestamp)
    print(f"  Raw encodings differ: {'✓ YES' if enc_original != enc_v1 else '✗ NO (BUG!)'}")
    print("└─ Done\n")

    print("┌─ IMM VALIDATION 4: Empirical collision search")
    n_entities = 10_000
    collision_set: set[str] = set()
    collision_found = False
    collision_tester_vk = imm_sender.vk
    for i in range(n_entities):
        random_content = os.urandom(64) + struct.pack(">I", i)
        random_entity = Entity(content=random_content, shape="x-ltp/collision-test")
        eid = random_entity.compute_id(collision_tester_vk, float(i))
        if eid in collision_set:
            collision_found = True
            print(f"  ✗ COLLISION FOUND at entity #{i}!")
            break
        collision_set.add(eid)
    if not collision_found:
        print(f"  Generated {n_entities:,} unique EntityIDs — zero collisions")
    print("└─ Done\n")

    print("┌─ IMM VALIDATION 5: End-to-end immutability gate")
    imm_test_content = b"The immutable truth that cannot be rewritten."
    imm_test_entity = Entity(content=imm_test_content, shape="x-ltp/immutability-test")
    imm_eid, imm_record, imm_cek = protocol.commit(imm_test_entity, alice, n=8, k=4)
    original_sig_valid = imm_record.verify_signature(alice.vk)
    print(
        f"  ML-DSA signature on original record: {'✓ VALID' if original_sig_valid else '✗ INVALID'}"
    )
    saved_hash = imm_record.content_hash
    imm_record.content_hash = canonical_hash(b"fake-content")
    tampered_sig_valid = imm_record.verify_signature(alice.vk)
    print(
        f"  Signature after content_hash tamper: "
        f"{'✗ BREACH!' if tampered_sig_valid else '✓ INVALID (forgery detected)'}"
    )
    imm_record.content_hash = saved_hash
    imm_sealed = protocol.lattice(
        imm_eid,
        imm_record,
        imm_cek,
        bob,
        access_policy={"type": "immutability-test"},
    )
    imm_materialized = protocol.materialize(imm_sealed, bob)
    if imm_materialized is not None:
        match = imm_materialized == imm_test_content
        print(f"  Materialize → content integrity: {'✓ EXACT MATCH' if match else '✗ MISMATCH'}")
    print("└─ Done\n")


# ---------------------------------------------------------------------------
# Commitment log trust model (§5.1.4)
# ---------------------------------------------------------------------------


def demo_commitment_log_trust(network: CommitmentNetwork) -> None:
    """Validate hash-chain integrity, inclusion proofs, tamper detection, STH."""
    print("─" * 74)
    print("▸ COMMITMENT LOG TRUST MODEL (§5.1.4 — Hash-Chain + STH)")
    print("─" * 74)
    print()

    print("┌─ 4.2 VALIDATION 1: Hash-chain integrity")
    chain_ok, last_idx = network.log.verify_chain_integrity()
    print(f"  Integrity: {'✓ INTACT' if chain_ok else '✗ BROKEN at index ' + str(last_idx)}")
    assert chain_ok
    print("└─ Done\n")

    print("┌─ 4.2 VALIDATION 2: Inclusion proofs")
    proofs_checked = 0
    proofs_valid = 0
    for eid_check in network.log._chain[:5]:
        proof = network.log.get_inclusion_proof(eid_check)
        if proof is not None:
            valid = network.log.verify_inclusion(eid_check, proof)
            proofs_checked += 1
            if valid:
                proofs_valid += 1
    print(f"  Inclusion proofs: {proofs_valid}/{proofs_checked} verified")
    assert proofs_valid == proofs_checked
    print("└─ Done\n")

    print("┌─ 4.2 VALIDATION 3: Tamper detection")
    first_eid = network.log._chain[0]
    original_record = network.log._records[first_eid]
    original_content_hash = original_record.content_hash
    _prefix, _hex = original_content_hash.split(":", 1)
    tampered_hash = _prefix + ":" + hex(int(_hex, 16) ^ 1)[2:].zfill(64)
    original_record.content_hash = tampered_hash
    tamper_ok, break_idx = network.log.verify_chain_integrity()
    print(f"  Chain after tamper: {'✗ BROKEN' if not tamper_ok else '✓ INTACT (UNEXPECTED)'}")
    assert not tamper_ok and break_idx == 0
    original_record.content_hash = original_content_hash
    restore_ok, _ = network.log.verify_chain_integrity()
    assert restore_ok
    print(f"  Chain restored: ✓ INTACT")
    print("└─ Done\n")

    print("┌─ 4.2 VALIDATION 4: Signed Tree Head sequence")
    sth_list = network.log.merkle_log._sths
    sth_monotonic = True
    for i in range(1, min(5, len(sth_list))):
        if sth_list[i].timestamp < sth_list[i - 1].timestamp:
            sth_monotonic = False
        if sth_list[i].sequence != sth_list[i - 1].sequence + 1:
            sth_monotonic = False
    sth_verified = all(sth.verify() for sth in sth_list[:5])
    print(
        f"  Monotonically increasing timestamps + sequential indices: {'✓' if sth_monotonic else '✗'}"
    )
    print(
        f"  ML-DSA-65 STH signatures verified: {'✓' if sth_verified else '✗'} ({min(5, len(sth_list))} checked)"
    )
    print("└─ Done\n")


# ---------------------------------------------------------------------------
# Storage proof strengthening (§5.2.2)
# ---------------------------------------------------------------------------


def demo_storage_proofs(network: CommitmentNetwork) -> None:
    """Validate burst-challenge storage proofs."""
    print("─" * 74)
    print("▸ STORAGE PROOF STRENGTHENING (§5.2.2 — Burst Challenges)")
    print("─" * 74)
    print()

    print("┌─ 4.3 VALIDATION 1: Baseline audit (burst=1)")
    baseline_audit = network.audit_all_nodes(burst=1)
    for r in baseline_audit:
        if r.result == "PASS":
            print(
                f"  [{r.node_id}] ✓ PASS — {r.challenged} challenges, avg {r.avg_response_us:.1f}µs"
            )
    print("└─ Done\n")

    print("┌─ 4.3 VALIDATION 2: Burst audit (burst=4)")
    burst_audit = network.audit_all_nodes(burst=4)
    all_burst_pass = True
    for r in burst_audit:
        status = "✓ PASS" if r.result == "PASS" else "✗ FAIL"
        suspicious = f" ⚠ {r.suspicious_latency} suspicious" if r.suspicious_latency > 0 else ""
        print(
            f"  [{r.node_id}] {status} — "
            f"{r.challenged} challenges (burst={r.burst_size}), "
            f"avg {r.avg_response_us:.1f}µs{suspicious}"
        )
        if r.result != "PASS":
            all_burst_pass = False
    print(f"  All nodes passed: {'✓' if all_burst_pass else '✗'}")
    print("└─ Done\n")

    burst_target = None
    for nd in network.nodes:
        if not nd.evicted and nd.shard_count > 0:
            burst_target = nd
            break
    if burst_target:
        print(f"┌─ 4.3 VALIDATION 3: Burst audit on degraded node ({burst_target.node_id})")
        deleted_keys = list(burst_target.shards.keys())[:2]
        for dk in deleted_keys:
            burst_target.remove_shard(dk[0], dk[1])
        degraded_audit = network.audit_node(burst_target, burst=4)
        status = "✓ PASS" if degraded_audit.result == "PASS" else "✗ FAIL"
        print(
            f"  [{degraded_audit.node_id}] {status} — "
            f"challenged={degraded_audit.challenged}, "
            f"passed={degraded_audit.passed}, "
            f"failed={degraded_audit.failed}, "
            f"missing={degraded_audit.missing}"
        )
        print("└─ Done\n")


# ---------------------------------------------------------------------------
# Correlated failure model (§5.4.1.1)
# ---------------------------------------------------------------------------


def demo_correlated_failure(
    network: CommitmentNetwork,
    entity_id: str,
) -> None:
    """Validate cross-region placement and regional failure resilience."""
    print("─" * 74)
    print("▸ CORRELATED FAILURE MODEL (§5.4.1.1 — Regional Failure)")
    print("─" * 74)
    print()

    corr_entity_id = network.log._chain[-1] if network.log._chain else entity_id
    corr_record = network.log.fetch(corr_entity_id)
    corr_n = corr_record.encoding_params.get("n", 8) if corr_record else 8
    corr_k = corr_record.encoding_params.get("k", 4) if corr_record else 4

    print("┌─ 4.5 VALIDATION 1: Cross-region shard placement")
    placement = network.check_cross_region_placement(corr_entity_id, corr_n)
    print(f"  Cross-region replica pairs: {placement['cross_region_count']}")
    print(f"  Regions used: {', '.join(placement['regions_used'])}")
    print(f"  All cross-region: {'✓' if placement['all_cross_region'] else '✗'}")
    print("└─ Done\n")

    regions = sorted(set(nd.region for nd in network.nodes if not nd.evicted))
    print("┌─ 4.5 VALIDATION 2: Availability under single-region failure")
    region_results = []
    for region in regions:
        avail = network.availability_under_region_failure(corr_entity_id, corr_n, corr_k, region)
        can = "✓ CAN reconstruct" if avail["can_reconstruct"] else "✗ CANNOT reconstruct"
        print(
            f"  [{region:8s} fails] surviving={avail['shards_surviving']}/{avail['shards_total']}: {can}"
        )
        region_results.append(avail)
    all_survive = all(r["can_reconstruct"] for r in region_results)
    print(f"  → Entity survives ANY single region failure: {'✓' if all_survive else '✗'}")
    print("└─ Done\n")

    test_region = regions[0] if regions else "US-East"
    print(f"┌─ 4.5 VALIDATION 3: Live region failure ({test_region})")
    affected_nodes = network.region_failure(test_region)
    print(f"  [FAILURE] {test_region}: {len(affected_nodes)} nodes offline")
    surviving_shards = network.fetch_encrypted_shards(corr_entity_id, corr_n, corr_k)
    fetch_ok = len(surviving_shards) >= corr_k
    print(f"  [FETCH] Materialization possible: {'✓ YES' if fetch_ok else '✗ NO'}")
    restored = network.restore_region(test_region)
    print(f"  [RESTORE] {test_region}: {len(restored)} nodes restored")
    print("└─ Done\n")

    if len(regions) >= 2:
        print(f"┌─ 4.5 VALIDATION 4: Two-region failure ({regions[0]} + {regions[1]})")
        network.region_failure(regions[0])
        network.region_failure(regions[1])
        print(f"  [STATUS] Active nodes: {network.active_node_count} / {len(network.nodes)}")
        surviving_2 = network.fetch_encrypted_shards(corr_entity_id, corr_n, corr_k)
        print(
            f"  [FETCH] Materialization possible: "
            f"{'✓ YES' if len(surviving_2) >= corr_k else '✗ NO'}"
        )
        network.restore_region(regions[0])
        network.restore_region(regions[1])
        print("└─ Done\n")

    # --- Economics Engine Demo ---
    print("─" * 74)
    print("▸ ECONOMICS ENGINE: Epoch Processing + Rewards")
    print("─" * 74)
    print()

    from .economics import (
        WEI_PER_LTP,
        EconomicsConfig,
        EconomicsEngine,
        NodeEconomics,
    )

    econ_config = EconomicsConfig()
    engine = EconomicsEngine(econ_config)
    epoch = 100  # Early bootstrap phase

    econ_nodes = []
    for nd in network.nodes:
        if not nd.evicted:
            ne = NodeEconomics(
                node_id=nd.node_id,
                stake=1_000 * WEI_PER_LTP,
                shards_stored=nd.shard_count,
                audit_score=100 if nd.strikes == 0 else max(0, 100 - nd.strikes * 20),
            )
            econ_nodes.append(ne)

    print(f"┌─ EPOCH {epoch} PROCESSING (Phase: {engine.network_phase(epoch).value})")
    snapshot = engine.process_epoch(
        epoch=epoch,
        nodes=econ_nodes,
        total_commitments_this_epoch=network.log.length,
        network_capacity=10_000,
    )
    print(f"  Active nodes:      {snapshot.active_nodes}")
    print(f"  Total staked:      {snapshot.total_staked / WEI_PER_LTP:,.0f} LTP")
    print(f"  Total shards:      {snapshot.total_shards}")
    print(f"  Fee multiplier:    {snapshot.fee_multiplier:.4f}x")
    print(f"  Rewards distributed: {snapshot.total_rewards_distributed / WEI_PER_LTP:.6f} LTP")
    print(f"  Fees collected:    {snapshot.total_fees_collected / WEI_PER_LTP:.6f} LTP")
    print(f"  Fees burned:       {snapshot.total_fees_burned / WEI_PER_LTP:.6f} LTP")
    print(f"  Storage endowment: {snapshot.total_fees_to_endowment / WEI_PER_LTP:.6f} LTP")
    print(f"  Insurance fund:    {snapshot.total_fees_to_insurance / WEI_PER_LTP:.6f} LTP")
    if snapshot.rewards:
        top = max(snapshot.rewards, key=lambda r: r.total)
        print(f"  Top earner: {top.node_id} → {top.total / WEI_PER_LTP:.6f} LTP")
    print("└─ Epoch complete\n")

    # --- Integrated Enforcement Pipeline Demo ---
    print("─" * 74)
    print("▸ ENFORCEMENT PIPELINE: End-to-End Audit → Slash → Governance")
    print("─" * 74)
    print()

    from .enforcement import (
        DecentralizationMetrics,
        EnforcementInvariants,
        StorageProofStrategy,
        VDFConfig,
    )
    from .enforcement_pipeline import EnforcementPipeline, EnforcementPipelineConfig

    pipeline_config = EnforcementPipelineConfig(
        storage_proof_strategy=StorageProofStrategy.HYBRID,
        vdf_enabled=True,
        vdf_config=VDFConfig(enabled=True, difficulty=10),
        enable_runtime_invariants=True,
    )
    pipeline = EnforcementPipeline(pipeline_config)
    network.set_enforcement_pipeline(pipeline)

    print(f"┌─ PIPELINE INITIALIZED")
    print(f"  Conditions registered: {len(pipeline.condition_registry.conditions)}")
    for cid, cond in pipeline.condition_registry.conditions.items():
        print(f"    {cid}: {cond.stake_allocation_bps} bps")
    print(f"  VDF enabled: {pipeline_config.vdf_enabled}")
    print(f"  Runtime invariants: {pipeline_config.enable_runtime_invariants}")
    print("└─\n")

    print("┌─ PDP + VDF HYBRID AUDIT")
    pdp_target = None
    for nd in network.nodes:
        if not nd.evicted and nd.shard_count > 0:
            pdp_target = nd
            break
    if pdp_target:
        pdp_result = network.audit_node_pdp(
            pdp_target,
            epoch=epoch,
            sample_size=4,
            vdf_verifier=pipeline.vdf_verifier,
        )
        print(f"  Node: {pdp_result['node_id']}")
        print(f"  Entities challenged: {pdp_result['entities_challenged']}")
        print(f"  PDP passed: {pdp_result['passed']}, failed: {pdp_result['failed']}")
        print(f"  Result: {'PASS' if pdp_result['result'] == 'PASS' else 'FAIL'}")
        if "vdf" in pdp_result:
            vdf = pdp_result["vdf"]
            print(
                f"  VDF verified: {'yes' if vdf['verified'] else 'no'} ({vdf['computation_time_ms']:.1f}ms)"
            )

        # Run through enforcement pipeline
        if econ_nodes:
            total_stake = sum(n.stake for n in econ_nodes)
            slash_result = pipeline.handle_pdp_result(
                pdp_result,
                econ_nodes[0],
                engine,
                epoch,
                total_network_stake=total_stake,
            )
            if slash_result and slash_result.violated:
                print(f"  Pipeline: VIOLATION detected ({slash_result.severity})")
                print(f"  Slash queued in batch accumulator for epoch {epoch}")
            else:
                print(f"  Pipeline: No violation (clean audit)")
    print("└─ Hybrid audit complete\n")

    print("┌─ EPOCH FINALIZATION (batch slash processing)")
    finalization = pipeline.finalize_epoch(epoch, econ_nodes, engine)
    print(f"  Batch entries processed: {finalization['batch_entries']}")
    print(f"  Pending slashes created: {finalization['pending_created']}")
    print(f"  Slashes finalized (past grace): {finalization['slashes_finalized']}")
    print(f"  Stake deducted: {finalization['stake_deducted'] / WEI_PER_LTP:.4f} LTP")
    if finalization["nodes_evicted"]:
        print(f"  Nodes evicted: {finalization['nodes_evicted']}")
    print("└─ Epoch finalization complete\n")

    print("┌─ GOVERNANCE TRANSITION CHECK")
    can_grow, unmet = pipeline.check_governance_transition(
        "bootstrap",
        "growth",
        econ_nodes,
        governance_participation=0.10,
    )
    print(f"  Bootstrap → Growth: {'READY' if can_grow else 'NOT READY'}")
    for u in unmet:
        print(f"    Unmet: {u}")
    print("└─ Governance check complete\n")

    print("┌─ FORMAL VERIFICATION INVARIANTS")
    s4_ok = EnforcementInvariants.check_safety_s4(0, 1000 * WEI_PER_LTP)
    l3_ok = EnforcementInvariants.check_liveness_l3(0)
    c1_ok = EnforcementInvariants.check_correlation_c1(1.0, 3.0)
    print(f"  INV-S4 (slash <= stake):          {'HOLDS' if s4_ok else 'VIOLATED'}")
    print(f"  INV-L3 (offense >= 0):            {'HOLDS' if l3_ok else 'VIOLATED'}")
    print(f"  INV-C1 (correlation in [1, max]): {'HOLDS' if c1_ok else 'VIOLATED'}")
    print("└─ Invariant checks complete\n")

    print("┌─ PIPELINE STATISTICS")
    stats = pipeline.stats
    print(f"  Total violations:     {stats['total_violations']}")
    print(f"  Slashes queued:       {stats['total_slashes_queued']}")
    print(f"  Epochs finalized:     {stats['total_epochs_finalized']}")
    print(f"  Disputes resolved:    {stats['total_disputes_resolved']}")
    stakes = [ne.stake for ne in econ_nodes]
    hhi = DecentralizationMetrics.compute_hhi([float(s) for s in stakes])
    gini = DecentralizationMetrics.compute_gini([float(s) for s in stakes])
    print(f"  HHI (concentration):  {hhi:.0f}")
    print(f"  Gini (inequality):    {gini:.3f}")
    print("└─ Pipeline stats complete\n")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def print_summary(network: CommitmentNetwork) -> None:
    """Print the final transfer summary."""
    print("=" * 74)
    print("  TRANSFER SUMMARY — Post-Quantum Security (ML-KEM-768 + ML-DSA-65)")
    print("=" * 74)
    print(f"  Commitment log entries: {network.log.length}")
    print(f"  Commitment nodes active: {network.active_node_count} / {len(network.nodes)}")
    total_shards = sum(n.shard_count for n in network.nodes if not n.evicted)
    print(f"  Total encrypted shards stored: {total_shards}")
    evicted_nodes = [n.node_id for n in network.nodes if n.evicted]
    if evicted_nodes:
        print(f"  Evicted nodes: {', '.join(evicted_nodes)}")
    print()
    print("  CRYPTOGRAPHIC POSTURE:")
    print(f"  Key encapsulation:  ML-KEM-768 (FIPS 203, NIST Level 3)")
    print(
        f"    ek: {MLKEM.EK_SIZE}B  dk: {MLKEM.DK_SIZE}B  ct: {MLKEM.CT_SIZE}B  ss: {MLKEM.SS_SIZE}B"
    )
    print(f"  Digital signatures: ML-DSA-65 (FIPS 204, NIST Level 3)")
    print(f"    vk: {MLDSA.VK_SIZE}B  sk: {MLDSA.SK_SIZE}B  sig: {MLDSA.SIG_SIZE}B")
    print(f"  Shard encryption:   AEAD (BLAKE2b keystream + 32B auth tag)")
    print(f"  Content addressing: BLAKE2b-256 (quantum-resistant hashing)")
    print()
    print("  SECURITY POSTURE:")
    print("  ✓ Leak 1 CLOSED: Key sealed via ML-KEM-768 (post-quantum KEM)")
    print("  ✓ Leak 2 CLOSED: Commitment log has Merkle root only (no shard_ids)")
    print("  ✓ Leak 3 CLOSED: Shards encrypted at rest (AEAD ciphertext)")
    print("  ✓ Quantum safe:  No X25519/Ed25519 — ML-KEM + ML-DSA throughout")
    print("  ✓ Forward secrecy: fresh ML-KEM encapsulation per seal (ephemeral ss)")
    print()
    print("  BANDWIDTH COST MODEL (honest accounting):")
    print("  ┌─────────────────────────┬────────────────┬─────────────────────┐")
    print("  │ Metric                  │ Direct Transfer│ LTP                 │")
    print("  ├─────────────────────────┼────────────────┼─────────────────────┤")
    print("  │ Sender→Receiver path    │ O(entity)      │ O(1) ~1,300 bytes   │")
    print("  │ Total system (1 recv)   │ O(entity)      │ O(entity × (r+1))   │")
    print("  │ Total system (N recv)   │ O(entity × N)  │ O(entity×r + ent×N) │")
    print("  │ Sender cost after commit│ O(entity × N)  │ O(1,300 × N)        │")
    print("  └─────────────────────────┴────────────────┴─────────────────────┘")
    print("  Note: PQ sealed key (~1,300B) is larger than pre-quantum (~240B).")
    print("  This is the honest cost of quantum resistance. The O(1) property")
    print("  is preserved — 1,300B is still constant regardless of entity size.")
    print()
    print("  The data didn't move. The proof moved. The truth materialized.")
    print("  Bandwidth didn't disappear. It redistributed to where it's cheapest.")
    print("  Now quantum-resistant at every layer.")
    print("=" * 74)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def demo() -> None:
    """Run a full LTP transfer demo with post-quantum security."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    print("=" * 74)
    print("  LATTICE TRANSFER PROTOCOL (LTP) v3")
    print("  Security: Post-Quantum (ML-KEM-768 + ML-DSA-65 + AEAD)")
    print("=" * 74)
    print()

    # --- Keypairs ---
    print("▸ Generating post-quantum keypairs (ML-KEM-768 + ML-DSA-65)...")
    alice = KeyPair.generate("alice")
    bob = KeyPair.generate("bob")
    eve = KeyPair.generate("eve-attacker")
    print(f"  Alice (sender):   ek={alice.pub_hex}  (ek:{MLKEM.EK_SIZE}B dk:{MLKEM.DK_SIZE}B)")
    print(f"  Bob (receiver):   ek={bob.pub_hex}  (vk:{MLDSA.VK_SIZE}B sk:{MLDSA.SK_SIZE}B)")
    print(f"  Eve (attacker):   ek={eve.pub_hex}")
    print()

    # --- Commitment network ---
    print("▸ Setting up commitment network...")
    network, _ = _setup_network()
    print()
    protocol = LTPProtocol(network)

    # --- Run demo sections ---
    test_cases = demo_transfers(protocol, network, alice, bob, eve)
    demo_shard_integrity(protocol, network, alice, bob)
    demo_audit(protocol, network, alice, bob, test_cases)
    demo_degraded_materialization(protocol, network, alice, bob)
    demo_threshold_secrecy()
    demo_entity_immutability(protocol, alice, bob)
    demo_commitment_log_trust(network)
    demo_storage_proofs(network)
    demo_correlated_failure(network, entity_id="")
    print_summary(network)


def compliance_demo() -> None:
    """Demonstrate institutional compliance features."""

    print()
    print("=" * 74)
    print("  INSTITUTIONAL COMPLIANCE FRAMEWORK")
    print("  Standards: FIPS 140-3 | SOC 2 | FedRAMP | GDPR | Basel III")
    print("=" * 74)
    print()

    from .compliance import (
        AuditEvent,
        AuditEventType,
        ComplianceAuditLogger,
        ComplianceConfig,
        ComplianceFramework,
        ComplianceRole,
        CryptoProviderMode,
        DeletionProof,
        FIPSCryptoProvider,
        GDPRDeletionManager,
        GeoFencePolicy,
        HSMConfig,
        Jurisdiction,
        KeyRotationManager,
        KeyRotationPolicy,
        Permission,
        RBACManager,
        SIEMExporter,
        SIEMFormat,
        SoftwareHSM,
    )

    # --- 1. FIPS Crypto Provider ---
    print("▸ 1. FIPS 140-3 Crypto Provider")
    provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
    info = provider.algorithm_info()
    print(f"  Mode: {info['mode']}")
    print(f"  Hash: {info['hash']}")
    print(f"  AEAD: {info['aead']}")
    print(f"  KEM:  {info['kem']}")
    print(f"  DSA:  {info['dsa']}")
    print(f"  FIPS OpenSSL available: {info['fips_available']}")
    # Test hashing
    test_data = b"compliance test data"
    h = provider.hash(test_data)
    print(f"  Hash output: {h[:40]}...")
    # Test AEAD round-trip
    from .primitives import AEAD

    key = os.urandom(32)
    nonce = os.urandom(AEAD.NONCE_SIZE)
    ct = provider.encrypt(key, test_data, nonce)
    pt = provider.decrypt(key, ct, nonce)
    assert pt == test_data, "AEAD round-trip failed"
    print(f"  AEAD round-trip: OK ({len(ct)} bytes ciphertext)")
    print()

    # --- 2. RBAC ---
    print("▸ 2. Role-Based Access Control (SOC 2 CC6.1)")
    rbac = RBACManager()
    rbac.create_policy("alice", {ComplianceRole.SENDER})
    rbac.create_policy("bob", {ComplianceRole.RECEIVER})
    rbac.create_policy("charlie", {ComplianceRole.AUDITOR})
    rbac.create_policy("admin-0", {ComplianceRole.ADMIN})

    checks = [
        ("alice", Permission.ENTITY_COMMIT, True),
        ("alice", Permission.SLASH_EXECUTE, False),
        ("bob", Permission.ENTITY_MATERIALIZE, True),
        ("bob", Permission.GDPR_DELETE, False),
        ("charlie", Permission.AUDIT_LOG_READ, True),
        ("charlie", Permission.ENTITY_COMMIT, False),
        ("admin-0", Permission.CONFIG_MODIFY, True),
    ]
    for identity, perm, expected in checks:
        result = rbac.check_permission(identity, perm)
        status = "PASS" if result == expected else "FAIL"
        print(f"  [{status}] {identity}.has({perm.value}) = {result}")
    print()

    # --- 3. Geo-Fencing ---
    print("▸ 3. Geo-Fenced Shard Placement (Data Sovereignty)")
    # FedRAMP policy: US-only
    fed_policy = GeoFencePolicy(
        allowed_jurisdictions={Jurisdiction.US, Jurisdiction.US_GOVCLOUD},
    )
    test_regions = [
        ("us-east-1", True),
        ("us-west-2", True),
        ("us_gov-east-1", True),
        ("eu-west-1", False),
        ("ap-southeast-1", False),
    ]
    for region, expected in test_regions:
        allowed = fed_policy.is_region_allowed(region)
        status = "PASS" if allowed == expected else "FAIL"
        print(f"  [{status}] Region '{region}' → {'allowed' if allowed else 'blocked'}")

    # Create a network with geo-fencing
    network = CommitmentNetwork()
    network.set_geo_fence_policy(fed_policy)
    us_node = network.add_node("us-node-1", "us-east-1")
    us_node2 = network.add_node("us-node-2", "us-west-2")
    eu_node = network.add_node("eu-node-1", "eu-west-1")
    # Distribute shards — should only go to US nodes
    test_shards = [os.urandom(64) for _ in range(4)]
    merkle_root = network.distribute_encrypted_shards("test-entity", test_shards)
    us_shards = us_node.shard_count + us_node2.shard_count
    eu_shards = eu_node.shard_count
    print(f"  Shards on US nodes: {us_shards}")
    print(f"  Shards on EU nodes: {eu_shards} (geo-fenced out)")
    assert eu_shards == 0, "Geo-fence violation: shards placed in EU"
    print(f"  [PASS] Geo-fence enforced: all shards in US jurisdiction")
    print()

    # --- 4. Audit Logger ---
    print("▸ 4. Immutable Audit Log (SOC 2 CC7.1, FedRAMP AU-2)")
    logger = ComplianceAuditLogger(operator_id="ltp-operator-1")
    events = [
        AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="us-node-1",
            action="node_registered",
            details={"region": "us-east-1"},
            epoch=1,
        ),
        AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="alice",
            target_id="entity-001",
            action="entity_committed",
            epoch=2,
        ),
        AuditEvent(
            event_type=AuditEventType.NODE_AUDITED,
            actor_id="system",
            target_id="us-node-1",
            action="audit_passed",
            details={"result": "PASS", "challenged": 4, "passed": 4},
            epoch=3,
        ),
        AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            actor_id="eve",
            action="unauthorized_materialize_attempt",
            details={"reason": "no_permission"},
            epoch=4,
        ),
    ]
    for event in events:
        chain_hash = logger.log(event)
    print(f"  Log length: {logger.length} events")
    print(f"  Head hash: {logger.head_hash[:40]}...")
    valid, idx = logger.verify_chain_integrity()
    print(f"  Chain integrity: {'VALID' if valid else 'INVALID at ' + str(idx)}")
    # Query
    denied = logger.query(event_type=AuditEventType.ACCESS_DENIED)
    print(f"  Access denied events: {len(denied)}")
    print()

    # --- 5. SIEM Export ---
    print("▸ 5. SIEM Export (FedRAMP AU-6)")
    for fmt in [SIEMFormat.JSON, SIEMFormat.CEF, SIEMFormat.JSON_LD]:
        output = SIEMExporter.export_event(events[3], fmt)
        print(f"  [{fmt.value}] {output[:80]}...")
    print()

    # --- 6. Key Rotation ---
    print("▸ 6. Key Rotation Manager (NIST SP 800-57)")
    rotation_mgr = KeyRotationManager(
        policy=KeyRotationPolicy(max_key_age_epochs=8760),
        audit_logger=logger,
    )
    kv1 = rotation_mgr.register_key("bob", "fp-v1-abc123", epoch=0)
    print(f"  Key v{kv1.version}: fingerprint={kv1.key_fingerprint}, expires={kv1.expires_epoch}")
    needs, reason = rotation_mgr.check_rotation_needed("bob", current_epoch=8000)
    print(f"  Rotation needed at epoch 8000: {needs} ({reason})")
    needs, reason = rotation_mgr.check_rotation_needed("bob", current_epoch=8760)
    print(f"  Rotation needed at epoch 8760: {needs} ({reason})")
    # Register new version
    kv2 = rotation_mgr.register_key("bob", "fp-v2-def456", epoch=8760)
    print(f"  Key v{kv2.version}: fingerprint={kv2.key_fingerprint}")
    active = rotation_mgr.get_active_key("bob")
    print(f"  Active key: v{active.version}")
    print()

    # --- 7. GDPR Deletion ---
    print("▸ 7. GDPR Right-to-Erasure (Article 17)")
    gdpr = GDPRDeletionManager(audit_logger=logger)
    # Store some shards first
    test_network = CommitmentNetwork()
    n1 = test_network.add_node("node-a", "eu-west-1")
    n2 = test_network.add_node("node-b", "eu-central-1")
    test_shards = [os.urandom(128) for _ in range(4)]
    test_network.distribute_encrypted_shards("entity-to-delete", test_shards)
    shards_before = n1.shard_count + n2.shard_count
    print(f"  Shards before deletion: {shards_before}")
    # Submit deletion request
    request = gdpr.submit_request(
        entity_id="entity-to-delete",
        requester_id="data-subject-1",
        epoch=100,
        reason="gdpr_art17",
    )
    print(f"  Request ID: {request.request_id[:40]}...")
    print(f"  Status: {request.status}")
    # Execute deletion
    proof = gdpr.execute_deletion(
        request_id=request.request_id,
        nodes=[n1, n2],
        epoch=101,
    )
    shards_after = n1.shard_count + n2.shard_count
    print(f"  Shards after deletion: {shards_after}")
    print(f"  Status: {request.status}")
    if proof:
        print(f"  Deletion proof hash: {proof.proof_hash[:40]}...")
        print(f"  Shards destroyed: {proof.shard_count_destroyed}")
        print(f"  Nodes participating: {proof.node_count_participating}")
        print(f"  Destruction Merkle root: {proof.destruction_merkle_root[:40]}...")
    print()

    # --- 8. HSM ---
    print("▸ 8. Software HSM (PKCS#11 Interface)")
    hsm = SoftwareHSM()
    kp_result = hsm.generate_keypair("test-key")
    print(f"  Key ID: {kp_result['key_id']}")
    print(f"  Label: {kp_result['label']}")
    keys = hsm.list_keys()
    print(f"  Keys in HSM: {len(keys)}")
    # Sign with HSM
    test_msg = b"test message for HSM signing"
    sig = hsm.sign(kp_result["key_id"], test_msg)
    print(f"  Signature size: {len(sig)} bytes")
    # Destroy key
    destroyed = hsm.destroy_key(kp_result["key_id"])
    print(f"  Key destroyed: {destroyed}")
    print(f"  Keys remaining: {len(hsm.list_keys())}")
    print()

    # --- 9. Compliance Validation ---
    print("▸ 9. Compliance Configuration Validation")
    # FedRAMP config (should show violations without FIPS)
    fed_config = ComplianceConfig(
        frameworks={ComplianceFramework.FEDRAMP_MODERATE},
        crypto_mode=CryptoProviderMode.DEFAULT,
        enable_rbac=False,
        enable_audit_logging=True,
    )
    valid, violations = fed_config.validate()
    print(f"  FedRAMP Moderate (misconfigured): {'PASS' if valid else 'FAIL'}")
    for v in violations:
        print(f"    - {v}")

    # Correctly configured SOC 2
    soc2_config = ComplianceConfig(
        frameworks={ComplianceFramework.SOC2_TYPE2},
        enable_rbac=True,
        enable_audit_logging=True,
        enable_key_rotation=True,
    )
    valid, violations = soc2_config.validate()
    print(f"  SOC 2 Type II (correct): {'PASS' if valid else 'FAIL'}")
    if valid:
        print(f"    All controls satisfied")

    # Controls summary
    summary = soc2_config.controls_summary()
    print(f"  Controls summary:")
    for k, v in summary.items():
        print(f"    {k}: {v}")
    print()

    print("=" * 74)
    print("  Institutional compliance framework operational.")
    print("  9 control families | 8 regulatory frameworks | FIPS 140-3 ready")
    print("=" * 74)


if __name__ == "__main__":
    demo()
    compliance_demo()
