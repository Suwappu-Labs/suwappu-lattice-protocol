"""Tests for domain-separated BLS signing (Spec C1 §4)."""

import pytest

from src.ltp.bls import BLS


class TestBLSDomainTags:
    """Verify BLS domain tags exist and follow conventions."""

    def test_bls_sign_tag_exists(self):
        from src.ltp.domain import DOMAIN_BLS_SIGN

        assert DOMAIN_BLS_SIGN == b"GSX-LTP:bls-sign:v1\x00"

    def test_bls_attest_tag_exists(self):
        from src.ltp.domain import DOMAIN_BLS_ATTEST

        assert DOMAIN_BLS_ATTEST == b"GSX-LTP:bls-attest:v1\x00"

    def test_tags_in_registry(self):
        from src.ltp.domain import _ALL_TAGS

        assert "DOMAIN_BLS_SIGN" in _ALL_TAGS
        assert "DOMAIN_BLS_ATTEST" in _ALL_TAGS

    def test_tag_count_updated(self):
        from src.ltp.domain import _ALL_TAGS

        assert len(_ALL_TAGS) == 31  # 29 existing + 2 new BLS tags


class TestBLSDomainSign:
    """Test domain-separated BLS signing functions."""

    def test_bls_domain_sign_verify_roundtrip(self):
        from src.ltp.domain import DOMAIN_BLS_SIGN, bls_domain_sign, bls_domain_verify

        pk, sk = BLS.keygen()
        data = b"BLS domain signing test"
        sig = bls_domain_sign(DOMAIN_BLS_SIGN, sk, data)
        assert len(sig) == 96
        assert bls_domain_verify(DOMAIN_BLS_SIGN, pk, data, sig) is True

    def test_wrong_domain_rejects(self):
        from src.ltp.domain import (
            DOMAIN_BLS_ATTEST,
            DOMAIN_BLS_SIGN,
            bls_domain_sign,
            bls_domain_verify,
        )

        pk, sk = BLS.keygen()
        data = b"cross-domain test"
        sig = bls_domain_sign(DOMAIN_BLS_SIGN, sk, data)
        assert bls_domain_verify(DOMAIN_BLS_ATTEST, pk, data, sig) is False

    def test_wrong_key_rejects(self):
        from src.ltp.domain import DOMAIN_BLS_SIGN, bls_domain_sign, bls_domain_verify

        pk1, sk1 = BLS.keygen()
        pk2, sk2 = BLS.keygen()
        sig = bls_domain_sign(DOMAIN_BLS_SIGN, sk1, b"msg")
        assert bls_domain_verify(DOMAIN_BLS_SIGN, pk2, b"msg", sig) is False

    def test_tampered_data_rejects(self):
        from src.ltp.domain import DOMAIN_BLS_SIGN, bls_domain_sign, bls_domain_verify

        pk, sk = BLS.keygen()
        sig = bls_domain_sign(DOMAIN_BLS_SIGN, sk, b"original")
        assert bls_domain_verify(DOMAIN_BLS_SIGN, pk, b"tampered", sig) is False


class TestBLSAggregateVerify:
    """Test domain-separated BLS aggregate verification."""

    def test_aggregate_same_message(self):
        from src.ltp.domain import (
            DOMAIN_BLS_ATTEST,
            bls_aggregate_sigs,
            bls_aggregate_verify,
            bls_domain_sign,
        )

        keys = [BLS.keygen() for _ in range(5)]
        data = b"committee attestation data"
        sigs = [bls_domain_sign(DOMAIN_BLS_ATTEST, sk, data) for pk, sk in keys]
        agg = bls_aggregate_sigs(sigs)
        assert len(agg) == 96
        pks = [pk for pk, sk in keys]
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, pks, data, agg) is True

    def test_aggregate_wrong_domain_rejects(self):
        from src.ltp.domain import (
            DOMAIN_BLS_ATTEST,
            DOMAIN_BLS_SIGN,
            bls_aggregate_sigs,
            bls_aggregate_verify,
            bls_domain_sign,
        )

        keys = [BLS.keygen() for _ in range(3)]
        data = b"domain mismatch test"
        sigs = [bls_domain_sign(DOMAIN_BLS_SIGN, sk, data) for pk, sk in keys]
        agg = bls_aggregate_sigs(sigs)
        pks = [pk for pk, sk in keys]
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, pks, data, agg) is False

    def test_aggregate_wrong_pk_rejects(self):
        from src.ltp.domain import (
            DOMAIN_BLS_ATTEST,
            bls_aggregate_sigs,
            bls_aggregate_verify,
            bls_domain_sign,
        )

        keys = [BLS.keygen() for _ in range(3)]
        data = b"wrong pk test"
        sigs = [bls_domain_sign(DOMAIN_BLS_ATTEST, sk, data) for pk, sk in keys]
        agg = bls_aggregate_sigs(sigs)
        bad_pks = [keys[0][0], keys[1][0], BLS.keygen()[0]]
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, bad_pks, data, agg) is False
