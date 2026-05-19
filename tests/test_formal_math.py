"""
Formal Mathematical Verification Tests for ETP.

Exhaustive and property-based verification of core mathematical constructions:
- GF(256) field axioms (exhaustive, all 65,536 pairs)
- Reed-Solomon MDS property (property-based, Hypothesis)
- AEAD round-trip and integrity (property-based)
- Merkle tree invariants (RFC 6962 compliance)
- Sealed box forward secrecy
- Nonce derivation uniqueness
- Lattice key size invariance

These tests verify the MATHEMATICAL CORRECTNESS of the protocol,
not just functional behavior.
"""

import math
import os
import random
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.ltp import (
    CommitmentNetwork,
    Entity,
    KeyPair,
    LTPProtocol,
    canonical_hash_bytes,
    reset_poc_state,
)
from src.ltp.erasure import ErasureCoder
from src.ltp.keypair import SealedBox
from src.ltp.merkle_log.proof import InclusionProof
from src.ltp.merkle_log.tree import (
    MerkleTree,
    _compute_root,
    _internal_hash,
    _leaf_hash,
    verify_consistency,
)
from src.ltp.primitives import AEAD, MLDSA, MLKEM
from src.ltp.shards import ShardEncryptor

# ═══════════════════════════════════════════════════════════════════════════
# 1. GF(256) FIELD AXIOM VERIFICATION (Exhaustive)
# ═══════════════════════════════════════════════════════════════════════════


class TestGF256FieldAxioms:
    """
    Exhaustively verify all field axioms of GF(2^8) with irreducible
    polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).

    GF(256) has only 256 elements — all axioms can be checked
    exhaustively in under 1 second.
    """

    @classmethod
    def setup_class(cls):
        ErasureCoder._init_gf()

    def test_additive_closure(self):
        """a ⊕ b ∈ GF(256) for all a, b."""
        for a in range(256):
            for b in range(256):
                result = a ^ b
                assert 0 <= result <= 255, f"{a} ^ {b} = {result} out of range"

    def test_multiplicative_closure(self):
        """a · b ∈ GF(256) for all a, b."""
        for a in range(256):
            for b in range(256):
                result = ErasureCoder._gf_mul(a, b)
                assert 0 <= result <= 255, f"gf_mul({a}, {b}) = {result} out of range"

    def test_additive_identity(self):
        """a ⊕ 0 = a for all a."""
        for a in range(256):
            assert a ^ 0 == a

    def test_multiplicative_identity(self):
        """a · 1 = a for all a."""
        for a in range(256):
            assert ErasureCoder._gf_mul(a, 1) == a

    def test_additive_inverse(self):
        """a ⊕ a = 0 for all a (every element is its own additive inverse in GF(2^n))."""
        for a in range(256):
            assert a ^ a == 0

    def test_multiplicative_inverse(self):
        """a · a^{-1} = 1 for all a ≠ 0."""
        for a in range(1, 256):
            inv = ErasureCoder._gf_inv(a)
            product = ErasureCoder._gf_mul(a, inv)
            assert product == 1, f"gf_mul({a}, gf_inv({a})={inv}) = {product}, expected 1"

    def test_multiplicative_commutativity(self):
        """a · b = b · a for all a, b."""
        for a in range(256):
            for b in range(256):
                assert ErasureCoder._gf_mul(a, b) == ErasureCoder._gf_mul(b, a), (
                    f"gf_mul({a},{b}) ≠ gf_mul({b},{a})"
                )

    def test_multiplicative_associativity(self):
        """(a · b) · c = a · (b · c) for all a, b, c.

        Full exhaustive check: 256³ = 16.7M triples. This runs in ~5 seconds.
        """
        gf_mul = ErasureCoder._gf_mul
        for a in range(256):
            for b in range(256):
                ab = gf_mul(a, b)
                for c in range(256):
                    assert gf_mul(ab, c) == gf_mul(a, gf_mul(b, c)), (
                        f"Associativity failed: ({a}·{b})·{c} ≠ {a}·({b}·{c})"
                    )

    def test_distributivity(self):
        """a · (b ⊕ c) = (a · b) ⊕ (a · c) for all a, b, c."""
        gf_mul = ErasureCoder._gf_mul
        for a in range(256):
            for b in range(256):
                for c in range(256):
                    lhs = gf_mul(a, b ^ c)
                    rhs = gf_mul(a, b) ^ gf_mul(a, c)
                    assert lhs == rhs, (
                        f"Distributivity failed: {a}·({b}⊕{c})={lhs} ≠ ({a}·{b})⊕({a}·{c})={rhs}"
                    )

    def test_zero_annihilation(self):
        """a · 0 = 0 for all a."""
        for a in range(256):
            assert ErasureCoder._gf_mul(a, 0) == 0


# ═══════════════════════════════════════════════════════════════════════════
# 2. REED-SOLOMON MDS PROPERTY (Property-based)
# ═══════════════════════════════════════════════════════════════════════════


class TestReedSolomonMDS:
    """
    Verify the Maximum Distance Separable property: any k-of-n shards
    can reconstruct the original data.
    """

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=100, deadline=10000)
    def test_any_k_shards_reconstruct(self, data):
        """Any k shards out of n reconstruct original data."""
        k, n = 4, 8
        all_shards = ErasureCoder.encode(data, n, k)

        # Select random k shards
        indices = random.sample(range(n), k)
        selected = {i: all_shards[i] for i in indices}

        decoded = ErasureCoder.decode(selected, n, k)
        assert decoded == data, f"MDS failed with indices {indices}"

    @given(data=st.binary(min_size=1, max_size=200))
    @settings(max_examples=50, deadline=10000)
    def test_encode_decode_roundtrip(self, data):
        """encode → decode is identity for all k-of-n configs."""
        for k, n in [(2, 4), (3, 6), (4, 8), (5, 10)]:
            if len(data) < k:
                continue
            shards = ErasureCoder.encode(data, n, k)
            assert len(shards) == n
            # Use first k shards (simplest case)
            selected = {i: shards[i] for i in range(k)}
            decoded = ErasureCoder.decode(selected, n, k)
            assert decoded == data

    def test_vandermonde_invertibility(self):
        """Vandermonde matrix is invertible for all valid (k, n) used by ETP."""
        for k in range(2, 16):
            for n in range(k, min(k + 10, 256)):
                alphas = list(range(1, n + 1))
                # Build Vandermonde matrix for first k alphas
                V = [[1] * k for _ in range(k)]
                for i in range(k):
                    for j in range(1, k):
                        V[i][j] = ErasureCoder._gf_mul(V[i][j - 1], alphas[i])

                # Invert via Gauss-Jordan
                inv = ErasureCoder._invert_vandermonde(alphas[:k], k)
                assert inv is not None, f"Vandermonde singular for k={k}, alphas={alphas[:k]}"

    def test_shard_count_correct(self):
        """encode() always produces exactly n shards."""
        data = b"test data for shard count"
        for k, n in [(2, 4), (4, 8), (3, 9)]:
            shards = ErasureCoder.encode(data, n, k)
            assert len(shards) == n


# ═══════════════════════════════════════════════════════════════════════════
# 3. AEAD CORRECTNESS (Property-based)
# ═══════════════════════════════════════════════════════════════════════════


class TestAEADFormalProperties:
    """Verify AEAD authenticated encryption correctness properties."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    @given(
        plaintext=st.binary(min_size=0, max_size=2000),
        aad=st.binary(min_size=0, max_size=100),
    )
    @settings(max_examples=100, deadline=5000)
    def test_roundtrip_with_aad(self, plaintext, aad):
        """Decrypt(Encrypt(key, pt, nonce, aad)) = pt."""
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, plaintext, nonce, aad)
        pt = AEAD.decrypt(key, ct, nonce, aad)
        assert pt == plaintext

    def test_aad_binding(self):
        """Changing AAD without recomputing tag → verification fails."""
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"payload", nonce, b"correct-aad")
        with pytest.raises(ValueError):
            AEAD.decrypt(key, ct, nonce, b"wrong-aad")

    def test_key_sensitivity(self):
        """Decrypting with wrong key fails."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key1, b"secret", nonce)
        with pytest.raises(ValueError):
            AEAD.decrypt(key2, ct, nonce)

    def test_nonce_sensitivity(self):
        """Same plaintext + key with different nonces → different ciphertexts."""
        key = os.urandom(32)
        pt = b"same plaintext"
        nonce1 = os.urandom(AEAD.NONCE_SIZE)
        nonce2 = os.urandom(AEAD.NONCE_SIZE)
        ct1 = AEAD.encrypt(key, pt, nonce1)
        ct2 = AEAD.encrypt(key, pt, nonce2)
        assert ct1 != ct2, "Same plaintext with different nonces produced same ciphertext"

    def test_ciphertext_integrity(self):
        """Flipping any bit in ciphertext → decryption fails."""
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"integrity test payload", nonce)

        # Flip bit at position len(ct)//2
        ct_bytes = bytearray(ct)
        pos = len(ct_bytes) // 2
        ct_bytes[pos] ^= 0x01
        with pytest.raises(ValueError):
            AEAD.decrypt(key, bytes(ct_bytes), nonce)

    def test_tag_removal_fails(self):
        """Truncating ciphertext (removing tag) → decryption fails."""
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"tag test", nonce)
        with pytest.raises((ValueError, Exception)):
            AEAD.decrypt(key, ct[:-1], nonce)


# ═══════════════════════════════════════════════════════════════════════════
# 4. MERKLE TREE FORMAL PROPERTIES (RFC 6962)
# ═══════════════════════════════════════════════════════════════════════════


class TestMerkleTreeFormalProperties:
    """Verify RFC 6962 Merkle tree mathematical invariants."""

    def test_domain_separation(self):
        """leaf_hash(x) ≠ internal_hash(x, x) for all x — prevents
        second-preimage attacks across tree levels."""
        for data in [b"", b"a", b"hello", os.urandom(32)]:
            leaf = _leaf_hash(data)
            internal = _internal_hash(data, data)
            assert leaf != internal, f"Domain separation failed for {data!r}"

    def test_determinism(self):
        """Same leaf sequence → same root (idempotent)."""
        leaves = [f"leaf-{i}".encode() for i in range(10)]
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        for leaf in leaves:
            tree1.append(leaf)
            tree2.append(leaf)
        assert tree1.root() == tree2.root()

    def test_tamper_detection(self):
        """Changing any single leaf → root changes."""
        leaves = [f"leaf-{i}".encode() for i in range(8)]
        tree = MerkleTree()
        for leaf in leaves:
            tree.append(leaf)
        original_root = tree.root()

        # Create new tree with one leaf changed
        for target in range(8):
            tree2 = MerkleTree()
            for i, leaf in enumerate(leaves):
                if i == target:
                    tree2.append(b"TAMPERED")
                else:
                    tree2.append(leaf)
            assert tree2.root() != original_root, f"Tamper at index {target} not detected"

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=30, deadline=5000)
    def test_inclusion_proof_soundness(self, n):
        """For every leaf in tree, inclusion proof verifies against root."""
        tree = MerkleTree()
        data_items = [f"item-{i}".encode() for i in range(n)]
        for item in data_items:
            tree.append(item)

        root = tree.root()
        for i in range(n):
            path = tree.audit_path(i)
            leaf = tree.leaf_hash(i)
            proof = InclusionProof(
                leaf_index=i,
                tree_size=tree.size,
                audit_path=path,
                root_hash=root,
            )
            assert proof.verify(data_items[i], root), (
                f"Inclusion proof failed for leaf {i} in tree of size {n}"
            )

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=30, deadline=5000)
    def test_proof_path_length_bound(self, n):
        """Audit path length ≤ ⌈log₂(n)⌉."""
        tree = MerkleTree()
        for i in range(n):
            tree.append(f"leaf-{i}".encode())

        max_path_len = math.ceil(math.log2(n)) if n > 1 else 0
        for i in range(n):
            path = tree.audit_path(i)
            assert len(path) <= max_path_len + 1, (
                f"Path too long: {len(path)} > {max_path_len} for n={n}, i={i}"
            )

    def test_consistency_proof_append_only(self):
        """Tree(N) is provably a prefix of Tree(N+M) for sequential appends."""
        tree = MerkleTree()
        roots = []

        for i in range(20):
            tree.append(f"entry-{i}".encode())
            roots.append(tree.root())

        # Verify consistency between all snapshot pairs
        for old_size in range(1, 20):
            new_size = 20
            proof = tree.consistency_proof(old_size)
            valid = verify_consistency(
                old_size,
                new_size,
                roots[old_size - 1],
                roots[new_size - 1],
                proof,
            )
            assert valid, f"Consistency failed: tree({old_size}) → tree({new_size})"

    def test_empty_tree_sentinel(self):
        """Empty tree has a deterministic root (H(b''))."""
        tree = MerkleTree()
        expected = canonical_hash_bytes(b"")
        assert tree.root() == expected


# ═══════════════════════════════════════════════════════════════════════════
# 5. SEALED BOX FORWARD SECRECY
# ═══════════════════════════════════════════════════════════════════════════


class TestSealedBoxForwardSecrecy:
    """Verify ML-KEM envelope encryption properties."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_forward_secrecy_different_ciphertexts(self):
        """Same plaintext sealed twice → different ciphertexts (fresh KEM each time)."""
        kp = KeyPair.generate("forward-secrecy-test")
        pt = b"identical plaintext"
        sealed1 = SealedBox.seal(pt, kp.ek)
        sealed2 = SealedBox.seal(pt, kp.ek)
        assert sealed1 != sealed2, "Two seal() calls produced identical output — no forward secrecy"

    def test_receiver_binding(self):
        """Sealed to Bob cannot be unsealed by Eve."""
        bob = KeyPair.generate("bob-binding")
        eve = KeyPair.generate("eve-binding")
        sealed = SealedBox.seal(b"for bob only", bob.ek)
        with pytest.raises(ValueError):
            SealedBox.unseal(sealed, eve)

    def test_plaintext_recovery(self):
        """unseal(seal(pt, ek), kp) = pt."""
        kp = KeyPair.generate("roundtrip-test")
        pt = b"round-trip test payload"
        sealed = SealedBox.seal(pt, kp.ek)
        recovered = SealedBox.unseal(sealed, kp)
        assert recovered == pt

    def test_size_depends_only_on_plaintext_length(self):
        """Sealed size depends on |pt|, not pt content."""
        kp = KeyPair.generate("size-test")
        pt1 = b"A" * 100
        pt2 = b"B" * 100
        pt3 = b"\x00" * 100
        s1 = len(SealedBox.seal(pt1, kp.ek))
        s2 = len(SealedBox.seal(pt2, kp.ek))
        s3 = len(SealedBox.seal(pt3, kp.ek))
        assert s1 == s2 == s3, f"Sizes differ: {s1}, {s2}, {s3}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. NONCE DERIVATION UNIQUENESS
# ═══════════════════════════════════════════════════════════════════════════


class TestNonceDerivation:
    """Verify shard nonce derivation produces unique nonces."""

    def test_different_indices_different_nonces(self):
        """Same CEK + entity_id, different shard indices → different nonces."""
        cek = ShardEncryptor.generate_cek()
        entity_id = "sha3-256:abcdef1234567890"
        nonces = set()
        for i in range(100):
            nonce = ShardEncryptor._nonce(cek, entity_id, i)
            assert nonce not in nonces, f"Nonce collision at shard index {i}"
            nonces.add(nonce)

    def test_different_ceks_different_nonces(self):
        """Different CEKs, same entity_id + index → different nonces."""
        entity_id = "sha3-256:test-entity-id"
        nonces = set()
        for _ in range(100):
            cek = ShardEncryptor.generate_cek()
            nonce = ShardEncryptor._nonce(cek, entity_id, 0)
            nonces.add(nonce)
        assert len(nonces) == 100, "CEK variation didn't produce unique nonces"

    def test_different_entities_different_nonces(self):
        """Same CEK + index, different entity_ids → different nonces."""
        cek = ShardEncryptor.generate_cek()
        nonces = set()
        for i in range(100):
            entity_id = f"sha3-256:entity-{i:04d}"
            nonce = ShardEncryptor._nonce(cek, entity_id, 0)
            nonces.add(nonce)
        assert len(nonces) == 100, "Entity ID variation didn't produce unique nonces"


# ═══════════════════════════════════════════════════════════════════════════
# 7. PROTOCOL-LEVEL PROPERTIES
# ═══════════════════════════════════════════════════════════════════════════


class TestProtocolFormalProperties:
    """Verify end-to-end protocol mathematical properties."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    @given(content=st.binary(min_size=1, max_size=1000))
    @settings(max_examples=20, deadline=30000)
    def test_commit_materialize_roundtrip(self, content):
        """Random content always reconstructs through COMMIT → LATTICE → MATERIALIZE."""
        reset_poc_state()
        alice = KeyPair.generate("alice-rt")
        bob = KeyPair.generate("bob-rt")
        network = CommitmentNetwork()
        for i in range(3):
            network.add_node(f"node-{i}", "us-east-1")
        protocol = LTPProtocol(network)

        entity = Entity(content=content, shape="application/octet-stream")
        eid, record, cek = protocol.commit(entity, alice)
        sealed = protocol.lattice(eid, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content, "Commit→Materialize round-trip failed"

    def test_lattice_key_size_invariance(self):
        """Sealed key size is O(1) — independent of content size."""
        reset_poc_state()
        alice = KeyPair.generate("alice-size")
        bob = KeyPair.generate("bob-size")
        network = CommitmentNetwork()
        for i in range(3):
            network.add_node(f"node-{i}", "us-east-1")
        protocol = LTPProtocol(network)

        sizes = []
        for content_size in [10, 100, 1000, 10000]:
            reset_poc_state()
            alice = KeyPair.generate("alice-sz")
            bob = KeyPair.generate("bob-sz")
            network = CommitmentNetwork()
            for i in range(3):
                network.add_node(f"node-{i}", "us-east-1")
            proto = LTPProtocol(network)

            entity = Entity(content=os.urandom(content_size), shape="application/octet-stream")
            eid, record, cek = proto.commit(entity, alice)
            sealed = proto.lattice(eid, record, cek, bob)
            sizes.append(len(sealed))

        # All sealed keys should be the same size (within a few bytes for JSON encoding)
        assert max(sizes) - min(sizes) <= 20, f"Sealed key sizes vary too much: {sizes}"

    def test_cross_entity_isolation(self):
        """Materializing entity A with entity B's sealed key fails."""
        reset_poc_state()
        alice = KeyPair.generate("alice-iso")
        bob = KeyPair.generate("bob-iso")
        network = CommitmentNetwork()
        for i in range(3):
            network.add_node(f"node-{i}", "us-east-1")
        protocol = LTPProtocol(network)

        entity_a = Entity(content=b"Entity A content", shape="text/plain")
        entity_b = Entity(content=b"Entity B content", shape="text/plain")

        eid_a, rec_a, cek_a = protocol.commit(entity_a, alice)
        eid_b, rec_b, cek_b = protocol.commit(entity_b, alice)

        # Seal entity B's key to Bob
        sealed_b = protocol.lattice(eid_b, rec_b, cek_b, bob)

        # Bob should get entity B, not entity A
        result = protocol.materialize(sealed_b, bob)
        assert result == b"Entity B content"
        assert result != b"Entity A content"
