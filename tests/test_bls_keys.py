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
        bls_a = BLSKeyPair.derive_from(mldsa_kp.sk, context=b"SUWAPPU-BLS-DERIVE:v1:chain-1")
        bls_b = BLSKeyPair.derive_from(mldsa_kp.sk, context=b"SUWAPPU-BLS-DERIVE:v1:chain-2")
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


class TestKeyPairComposite:
    """Mode 1: Composite BLS fields on KeyPair (Spec C1 §3.1)."""

    def test_generate_without_bls(self):
        """Default KeyPair.generate() still works without BLS."""
        from src.ltp.keypair import KeyPair

        kp = KeyPair.generate("no-bls")
        assert kp.bls_pk is None
        assert kp.bls_sk is None

    def test_generate_with_bls(self):
        from src.ltp.keypair import KeyPair

        kp = KeyPair.generate("with-bls", with_bls=True)
        assert kp.bls_pk is not None
        assert len(kp.bls_pk) == 48
        assert kp.bls_sk is not None
        assert len(kp.bls_sk) == 32

    def test_composite_bls_signs_and_verifies(self):
        from src.ltp.keypair import KeyPair

        kp = KeyPair.generate("comp-sign", with_bls=True)
        msg = b"composite BLS test"
        sig = BLS.sign(kp.bls_sk, msg)
        assert BLS.verify(kp.bls_pk, msg, sig) is True

    def test_composite_fingerprint_includes_bls(self):
        """Composite fingerprint = SHA3(mldsa_vk || bls_pk), differs from ML-DSA only."""
        from src.ltp.bls_keys import composite_fingerprint
        from src.ltp.domain import signer_fingerprint
        from src.ltp.keypair import KeyPair

        kp_no_bls = KeyPair.generate("fp-no-bls")
        kp_with_bls = KeyPair.generate("fp-with-bls", with_bls=True)

        fp_standard = signer_fingerprint(kp_no_bls.vk)
        fp_composite = composite_fingerprint(kp_with_bls.vk, kp_with_bls.bls_pk)

        assert fp_standard != fp_composite
        assert len(fp_composite) == 32

    def test_to_bls_identity(self):
        from src.ltp.keypair import KeyPair

        kp = KeyPair.generate("id-comp", with_bls=True)
        identity = kp.to_bls_identity()
        assert identity.pk == kp.bls_pk
        assert identity.sk_accessor() == kp.bls_sk
        assert identity.mode == "composite"
        assert identity.label == "id-comp"

    def test_to_bls_identity_raises_without_bls(self):
        from src.ltp.keypair import KeyPair

        kp = KeyPair.generate("no-bls-id")
        with pytest.raises(ValueError, match="no BLS"):
            kp.to_bls_identity()


class TestAllModesUnified:
    """All three key modes produce identities that can sign and verify."""

    def test_all_modes_produce_signing_identity(self):
        from src.ltp.bls_keys import BLSKeyPair
        from src.ltp.keypair import KeyPair

        # Standalone
        standalone = BLSKeyPair.generate("mode-s").to_identity()

        # Derived
        mldsa_kp = KeyPair.generate("mode-d")
        derived = BLSKeyPair.derive_from(mldsa_kp.sk, label="mode-d").to_identity()

        # Composite (from KeyPair with BLS)
        comp_kp = KeyPair.generate("mode-c", with_bls=True)
        composite = comp_kp.to_bls_identity()

        for identity in [standalone, derived, composite]:
            msg = b"unified signing test"
            sig = BLS.sign(identity.sk_accessor(), msg)
            assert BLS.verify(identity.pk, msg, sig) is True
