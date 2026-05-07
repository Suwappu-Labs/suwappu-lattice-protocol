"""Tests for BLS12-381 crypto backend (Spec C1 §2)."""

from hypothesis import given, settings
from hypothesis import strategies as st


class TestBLSBackendDetection:
    """Verify backend availability flags and assertions."""

    def test_py_ecc_bls_available(self):
        from src.ltp.bls import _py_ecc_bls_available
        assert _py_ecc_bls_available is True

    def test_blst_availability_flag_exists(self):
        from src.ltp.bls import _blst_available
        assert isinstance(_blst_available, bool)

    def test_assert_bls_crypto_passes(self):
        """At least one BLS backend must be available."""
        from src.ltp.bls import assert_bls_crypto
        assert_bls_crypto()  # Should not raise


class TestBLSSizes:
    """Verify BLS12-381 constant sizes."""

    def test_pk_size(self):
        from src.ltp.bls import BLS
        assert BLS.PK_SIZE == 48

    def test_sk_size(self):
        from src.ltp.bls import BLS
        assert BLS.SK_SIZE == 32

    def test_sig_size(self):
        from src.ltp.bls import BLS
        assert BLS.SIG_SIZE == 96


class TestBLSKeygen:
    """Test BLS12-381 key generation."""

    def test_keygen_returns_tuple(self):
        from src.ltp.bls import BLS
        result = BLS.keygen()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_keygen_pk_is_48_bytes(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        assert len(pk) == 48

    def test_keygen_sk_is_32_bytes(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        assert len(sk) == 32

    def test_keygen_produces_unique_keys(self):
        from src.ltp.bls import BLS
        pk1, sk1 = BLS.keygen()
        pk2, sk2 = BLS.keygen()
        assert pk1 != pk2
        assert sk1 != sk2


class TestBLSSignVerify:
    """Test BLS12-381 sign and verify."""

    def test_sign_returns_96_bytes(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        sig = BLS.sign(sk, b"hello")
        assert len(sig) == 96

    def test_sign_verify_roundtrip(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        msg = b"ETP attestation test"
        sig = BLS.sign(sk, msg)
        assert BLS.verify(pk, msg, sig) is True

    def test_wrong_key_rejects(self):
        from src.ltp.bls import BLS
        pk1, sk1 = BLS.keygen()
        pk2, sk2 = BLS.keygen()
        sig = BLS.sign(sk1, b"msg")
        assert BLS.verify(pk2, b"msg", sig) is False

    def test_tampered_message_rejects(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        sig = BLS.sign(sk, b"original")
        assert BLS.verify(pk, b"tampered", sig) is False

    def test_wrong_signature_rejects(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        sig = BLS.sign(sk, b"msg")
        bad_sig = bytes(96)  # all zeros
        assert BLS.verify(pk, b"msg", bad_sig) is False

    @given(msg=st.binary(min_size=1, max_size=1024))
    @settings(max_examples=20, deadline=None)
    def test_sign_verify_hypothesis(self, msg):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        sig = BLS.sign(sk, msg)
        assert BLS.verify(pk, msg, sig) is True


class TestBLSAggregate:
    """Test BLS12-381 aggregate signatures."""

    def test_aggregate_single_sig(self):
        from src.ltp.bls import BLS
        pk, sk = BLS.keygen()
        msg = b"single"
        sig = BLS.sign(sk, msg)
        agg = BLS.aggregate_signatures([sig])
        assert len(agg) == 96
        assert BLS.aggregate_verify_same_message([pk], msg, agg) is True

    def test_aggregate_multiple_sigs_same_message(self):
        from src.ltp.bls import BLS
        keys = [BLS.keygen() for _ in range(5)]
        msg = b"committee attestation"
        sigs = [BLS.sign(sk, msg) for pk, sk in keys]
        agg = BLS.aggregate_signatures(sigs)
        assert len(agg) == 96
        pks = [pk for pk, sk in keys]
        assert BLS.aggregate_verify_same_message(pks, msg, agg) is True

    def test_aggregate_wrong_pk_rejects(self):
        from src.ltp.bls import BLS
        keys = [BLS.keygen() for _ in range(3)]
        msg = b"test"
        sigs = [BLS.sign(sk, msg) for pk, sk in keys]
        agg = BLS.aggregate_signatures(sigs)
        bad_pks = [keys[0][0], keys[1][0], BLS.keygen()[0]]
        assert BLS.aggregate_verify_same_message(bad_pks, msg, agg) is False

    def test_aggregate_verify_different_messages(self):
        from src.ltp.bls import BLS
        keys = [BLS.keygen() for _ in range(3)]
        msgs = [b"msg-0", b"msg-1", b"msg-2"]
        sigs = [BLS.sign(keys[i][1], msgs[i]) for i in range(3)]
        agg = BLS.aggregate_signatures(sigs)
        pks = [pk for pk, sk in keys]
        assert BLS.aggregate_verify(pks, msgs, agg) is True

    def test_aggregate_verify_different_messages_wrong_order_rejects(self):
        from src.ltp.bls import BLS
        keys = [BLS.keygen() for _ in range(3)]
        msgs = [b"msg-0", b"msg-1", b"msg-2"]
        sigs = [BLS.sign(keys[i][1], msgs[i]) for i in range(3)]
        agg = BLS.aggregate_signatures(sigs)
        pks = [pk for pk, sk in keys]
        assert BLS.aggregate_verify(pks, [msgs[2], msgs[1], msgs[0]], agg) is False

    @given(n=st.integers(min_value=1, max_value=10))
    @settings(max_examples=10, deadline=None)
    def test_aggregate_hypothesis_same_message(self, n):
        from src.ltp.bls import BLS
        keys = [BLS.keygen() for _ in range(n)]
        msg = b"hypothesis committee"
        sigs = [BLS.sign(sk, msg) for pk, sk in keys]
        agg = BLS.aggregate_signatures(sigs)
        pks = [pk for pk, sk in keys]
        assert BLS.aggregate_verify_same_message(pks, msg, agg) is True
