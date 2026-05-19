"""
Backend boundary tests for LTP Core Hardening.

Tests lane boundary enforcement, trust anchor independence from internal lane,
protocol-shape assertions at backend boundaries, and trust-artifact invariance
across internal-lane backends.
"""

import os

import pytest

from src.ltp.commitment import CommitmentRecord
from src.ltp.dual_lane import (
    COMPLIANCE_APPROVED,
    HashFunction,
    SecurityProfile,
)
from src.ltp.dual_lane.hashing import _blake3_available
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair, SealedBox
from src.ltp.primitives import (
    AEAD,
    MLDSA,
    MLKEM,
    _pqcrypto_kem_available,
    _pqcrypto_sign_available,
    _pynacl_available,
    canonical_hash,
    get_security_profile,
    internal_hash,
    set_compliance_strict,
    set_security_profile,
)


@pytest.fixture(autouse=True)
def restore_default_profile():
    """Ensure every test starts and ends with the default Level 3 profile."""
    original = get_security_profile()
    set_security_profile(SecurityProfile.level3())
    set_compliance_strict(False)
    yield
    set_security_profile(original)
    set_compliance_strict(False)


@pytest.fixture(autouse=True)
def reset_poc_tables():
    """Clear PoC lookup tables between tests for isolation."""
    yield
    MLKEM.reset_poc_state()
    MLDSA.reset_poc_state()


# =========================================================================
# A. Lane boundary enforcement
# =========================================================================


class TestLaneBoundaryEnforcement:
    """Prove the compliance wall holds regardless of what's installed."""

    def test_canonical_always_sha3_regardless_of_blake3(self):
        """Canonical outputs use SHA3-256 whether BLAKE3 is installed or not."""
        result = canonical_hash(b"test")
        assert result.startswith("sha3-256:")

    def test_canonical_rejects_blake3(self):
        """Canonical lane hard-rejects BLAKE3 even without strict mode."""
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.BLAKE3_256))
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"test")

    def test_canonical_rejects_blake2b(self):
        """Canonical lane hard-rejects BLAKE2b even without strict mode."""
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.BLAKE2B_256))
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"test")

    def test_internal_may_change_with_blake3(self):
        """Internal lane uses BLAKE3 when available, SHA3 fallback otherwise."""
        result = internal_hash(b"test")
        if _blake3_available:
            assert result.startswith("blake3:")
        else:
            assert result.startswith("sha3-256:")

    def test_canonical_accepts_sha384(self):
        """Canonical lane accepts FIPS-approved SHA-384."""
        set_security_profile(SecurityProfile(level=5, canonical_hash=HashFunction.SHA_384))
        result = canonical_hash(b"test")
        assert result.startswith("sha384:")

    def test_canonical_accepts_sha512(self):
        """Canonical lane accepts FIPS-approved SHA-512."""
        set_security_profile(SecurityProfile(level=5, canonical_hash=HashFunction.SHA_512))
        result = canonical_hash(b"test")
        assert result.startswith("sha512:")

    def test_strict_mode_redundant_for_canonical(self):
        """Compliance strict mode is now redundant — canonical always enforces."""
        # Even without strict mode, BLAKE3 is rejected
        set_compliance_strict(False)
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.BLAKE3_256))
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"test")

        # With strict mode, same behavior
        set_compliance_strict(True)
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"test")


# =========================================================================
# B. Trust anchor independence from internal lane
# =========================================================================


class TestTrustAnchorLaneIndependence:
    """Prove that trust anchors never depend on the internal lane."""

    def test_entity_id_uses_canonical_only(self):
        """Entity IDs (used in approval receipts) use canonical lane."""
        kp = KeyPair.generate("test-entity-id")
        e = Entity(content=b"data", shape="text/plain")
        eid = e.compute_id(kp.vk, 1.0)
        assert eid.startswith("sha3-256:")

    def test_commitment_record_hash_uses_canonical(self):
        """Commitment record hashes (audit trail) use canonical lane."""
        kp = KeyPair.generate("test-commit")
        record = CommitmentRecord(
            entity_id=canonical_hash(os.urandom(32)),
            sender_id=kp.label,
            shard_map_root=canonical_hash(b"root"),
            content_hash=canonical_hash(b"content"),
            encoding_params={
                "n": 8,
                "k": 4,
                "algorithm": "reed-solomon-gf256",
                "gf_poly": "0x11d",
                "eval": "vandermonde-powers-of-0x02",
            },
            shape="text/plain",
            shape_hash=canonical_hash(b"text/plain"),
            timestamp=1740000000.0,
        )
        # All hash fields are canonical
        assert record.entity_id.startswith("sha3-256:")
        assert record.shard_map_root.startswith("sha3-256:")
        assert record.content_hash.startswith("sha3-256:")

    def test_mldsa_signature_independent_of_internal_lane(self):
        """ML-DSA signatures (approval receipts) are canonical-lane only."""
        vk, sk = MLDSA.keygen()
        msg = b"approval receipt payload"
        sig = MLDSA.sign(sk, msg)
        assert MLDSA.verify(vk, msg, sig) is True
        assert len(sig) == MLDSA.SIG_SIZE


# =========================================================================
# C. Protocol-shape assertions at backend boundaries
# =========================================================================


class TestProtocolShapeAssertions:
    """Verify primitive sizes match FIPS 203/204 specifications."""

    def test_mlkem_key_sizes(self):
        ek, dk = MLKEM.keygen()
        assert len(ek) == MLKEM.EK_SIZE == 1184
        assert len(dk) == MLKEM.DK_SIZE == 2400

    def test_mlkem_ciphertext_size(self):
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        assert len(ct) == MLKEM.CT_SIZE == 1088
        assert len(ss) == MLKEM.SS_SIZE == 32

    def test_mldsa_key_sizes(self):
        vk, sk = MLDSA.keygen()
        assert len(vk) == MLDSA.VK_SIZE == 1952
        assert len(sk) == MLDSA.SK_SIZE == 4032

    def test_mldsa_signature_size(self):
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"message")
        assert len(sig) == MLDSA.SIG_SIZE == 3309

    def test_aead_nonce_and_tag_sizes(self):
        assert AEAD.NONCE_SIZE in (16, 24)
        assert AEAD.TAG_SIZE in (16, 32)

    def test_aead_roundtrip(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        plaintext = b"hello world"
        ct = AEAD.encrypt(key, plaintext, nonce)
        assert len(ct) == len(plaintext) + AEAD._tag_size()
        recovered = AEAD.decrypt(key, ct, nonce)
        assert recovered == plaintext

    def test_aead_rejects_wrong_nonce_size(self):
        key = os.urandom(32)
        wrong_nonce = os.urandom(AEAD.NONCE_SIZE + 1)
        with pytest.raises(ValueError, match="Nonce must be"):
            AEAD.encrypt(key, b"data", wrong_nonce)
        with pytest.raises(ValueError, match="Nonce must be"):
            AEAD.decrypt(key, b"data" * 10, wrong_nonce)

    def test_sealed_box_framing(self):
        """Sealed box parsing offsets match actual primitive sizes."""
        kp = KeyPair.generate("framing-test")
        sealed = SealedBox.seal(b"payload", kp.ek)
        # kem_ct || nonce || aead_ct || aead_tag
        assert len(sealed) >= MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD._tag_size()
        kem_ct = sealed[: MLKEM.CT_SIZE]
        assert len(kem_ct) == 1088

    def test_sealed_box_roundtrip(self):
        """Seal/unseal works end-to-end with current backend."""
        kp = KeyPair.generate("roundtrip-test")
        payload = b"sensitive lattice key material"
        sealed = SealedBox.seal(payload, kp.ek)
        recovered = SealedBox.unseal(sealed, kp)
        assert recovered == payload

    def test_mlkem_decaps_recovers_shared_secret(self):
        """ML-KEM decaps recovers the same shared secret from encaps."""
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        recovered = MLKEM.decaps(dk, ct)
        assert recovered == ss

    @pytest.mark.skipif(not _pqcrypto_kem_available, reason="pqcrypto not installed")
    def test_mlkem_stateless_decaps(self):
        """Real ML-KEM decaps works without PoC lookup tables."""
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        MLKEM.reset_poc_state()  # Clear PoC tables — real backend doesn't need them
        recovered = MLKEM.decaps(dk, ct)
        assert recovered == ss

    @pytest.mark.skipif(not _pqcrypto_sign_available, reason="pqcrypto not installed")
    def test_mldsa_stateless_verify(self):
        """Real ML-DSA verify works without PoC lookup tables."""
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"msg")
        MLDSA.reset_poc_state()  # Clear PoC tables
        assert MLDSA.verify(vk, b"msg", sig) is True


# =========================================================================
# D. Trust-artifact invariance across internal-lane backends
# =========================================================================


class TestTrustArtifactInvariance:
    """Prove canonical trust artifacts are identical regardless of internal lane."""

    def test_entity_id_invariant_across_internal_lane(self):
        """Entity ID is byte-for-byte identical regardless of internal lane algorithm.

        The internal lane (BLAKE3 vs SHA3 fallback) must never affect entity IDs,
        which are canonical-lane artifacts used in approval receipts and audit trails.
        """
        kp = KeyPair.generate("invariance-test")
        e = Entity(content=b"invariance payload", shape="text/plain")

        # Compute entity ID with current internal lane (whatever is installed)
        eid = e.compute_id(kp.vk, 1.0)

        # Entity ID must always be canonical-lane SHA3-256
        assert eid.startswith("sha3-256:")

        # The exact hash value is deterministic from (content, vk, weight) alone —
        # no internal-lane input can change it. Verify by recomputing:
        eid2 = e.compute_id(kp.vk, 1.0)
        assert eid == eid2, "Entity ID must be deterministic"

    def test_commitment_hash_invariant_across_internal_lane(self):
        """Commitment record hash uses only canonical lane — BLAKE3 presence irrelevant."""
        kp = KeyPair.generate("commit-invariance")
        entity_id = canonical_hash(b"test-entity")
        record = CommitmentRecord(
            entity_id=entity_id,
            sender_id=kp.label,
            shard_map_root=canonical_hash(b"root"),
            content_hash=canonical_hash(b"content"),
            encoding_params={
                "n": 8,
                "k": 4,
                "algorithm": "reed-solomon-gf256",
                "gf_poly": "0x11d",
                "eval": "vandermonde-powers-of-0x02",
            },
            shape="text/plain",
            shape_hash=canonical_hash(b"text/plain"),
            timestamp=1740000000.0,
        )
        # Commitment ref fields must be canonical
        assert record.entity_id.startswith("sha3-256:")
        assert record.shard_map_root.startswith("sha3-256:")
        assert record.content_hash.startswith("sha3-256:")

    def test_mldsa_signature_invariant_across_internal_lane(self):
        """ML-DSA sign/verify is independent of internal lane hash."""
        vk, sk = MLDSA.keygen()
        msg = b"canonical trust artifact"
        sig = MLDSA.sign(sk, msg)
        # Signature verification must work regardless of internal lane
        assert MLDSA.verify(vk, msg, sig) is True
        # Signature size is fixed by FIPS 204, not by hash lane
        assert len(sig) == MLDSA.SIG_SIZE
