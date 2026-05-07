"""Tests for BLS key management — three modes (Spec C1 §3)."""

import pytest

from src.ltp.bls import BLS


class TestBLSKeyPairStandalone:
    """Mode 2: Standalone BLSKeyPair (Spec C1 §3.2)."""

    def test_generate_returns_bls_keypair(self):
        from src.ltp.bls_keys import BLSKeyPair
        kp = BLSKeyPair.generate("test-standalone")
        assert kp.label == "test-standalone"
        assert len(kp.pk) == BLS.PK_SIZE
        assert len(kp.sk) == BLS.SK_SIZE

    def test_sign_verify_roundtrip(self):
        from src.ltp.bls_keys import BLSKeyPair
        kp = BLSKeyPair.generate("test-sign")
        msg = b"standalone sign test"
        sig = BLS.sign(kp.sk, msg)
        assert BLS.verify(kp.pk, msg, sig) is True

    def test_bls_fingerprint_is_32_bytes(self):
        from src.ltp.bls_keys import BLSKeyPair, bls_fingerprint
        kp = BLSKeyPair.generate("test-fp")
        fp = bls_fingerprint(kp.pk)
        assert isinstance(fp, bytes)
        assert len(fp) == 32

    def test_bls_fingerprint_deterministic(self):
        from src.ltp.bls_keys import BLSKeyPair, bls_fingerprint
        kp = BLSKeyPair.generate("test-fp-det")
        fp1 = bls_fingerprint(kp.pk)
        fp2 = bls_fingerprint(kp.pk)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self):
        from src.ltp.bls_keys import BLSKeyPair, bls_fingerprint
        kp1 = BLSKeyPair.generate("kp1")
        kp2 = BLSKeyPair.generate("kp2")
        assert bls_fingerprint(kp1.pk) != bls_fingerprint(kp2.pk)

    def test_own_key_state_lifecycle(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyState
        kp = BLSKeyPair.generate("lifecycle-test")
        assert kp.state == KeyState.ACTIVE


class TestBLSKeyPairDerived:
    """Mode 3: Derived from ML-DSA signing key (Spec C1 §3.3)."""

    def test_derive_from_mldsa_sk(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair
        mldsa_kp = KeyPair.generate("derive-test")
        bls_kp = BLSKeyPair.derive_from(mldsa_kp.sk)
        assert len(bls_kp.pk) == BLS.PK_SIZE
        assert len(bls_kp.sk) == BLS.SK_SIZE

    def test_derive_is_deterministic(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair
        mldsa_kp = KeyPair.generate("det-test")
        bls1 = BLSKeyPair.derive_from(mldsa_kp.sk)
        bls2 = BLSKeyPair.derive_from(mldsa_kp.sk)
        assert bls1.pk == bls2.pk
        assert bls1.sk == bls2.sk

    def test_different_context_different_keys(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair
        mldsa_kp = KeyPair.generate("ctx-test")
        bls_a = BLSKeyPair.derive_from(mldsa_kp.sk, context=b"GSX-BLS-DERIVE:v1:chain-1")
        bls_b = BLSKeyPair.derive_from(mldsa_kp.sk, context=b"GSX-BLS-DERIVE:v1:chain-2")
        assert bls_a.pk != bls_b.pk
        assert bls_a.sk != bls_b.sk

    def test_derived_key_signs_and_verifies(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair
        mldsa_kp = KeyPair.generate("sign-test")
        bls_kp = BLSKeyPair.derive_from(mldsa_kp.sk)
        msg = b"derived key attestation"
        sig = BLS.sign(bls_kp.sk, msg)
        assert BLS.verify(bls_kp.pk, msg, sig) is True


class TestBLSIdentity:
    """Unified BLSIdentity interface (Spec C1 §3.4)."""

    def test_standalone_to_identity(self):
        from src.ltp.bls_keys import BLSKeyPair
        kp = BLSKeyPair.generate("id-standalone")
        identity = kp.to_identity()
        assert identity.pk == kp.pk
        assert identity.sk_accessor() == kp.sk
        assert identity.mode == "standalone"
        assert identity.label == "id-standalone"
        assert len(identity.fingerprint) == 32

    def test_derived_to_identity(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair
        mldsa_kp = KeyPair.generate("id-derived")
        bls_kp = BLSKeyPair.derive_from(mldsa_kp.sk, label="id-derived")
        identity = bls_kp.to_identity()
        assert identity.mode == "derived"

    def test_identity_frozen(self):
        from src.ltp.bls_keys import BLSKeyPair
        kp = BLSKeyPair.generate("frozen-test")
        identity = kp.to_identity()
        with pytest.raises(AttributeError):
            identity.pk = b"\x00" * 48
