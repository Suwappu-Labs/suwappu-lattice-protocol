"""Constant-size commitment envelope tests (paper §10.2)."""

from __future__ import annotations

import pytest

from ltp.corridor import (
    BLS_G2_COMPRESSED_BYTES,
    Cid,
    EnvelopeSizeError,
    ML_KEM_768_CT_BYTES,
    ML_KEM_1024_CT_BYTES,
    OnChainCommitment,
    SHA3_256_BYTES,
)


def _make(kem_size: int = ML_KEM_768_CT_BYTES) -> OnChainCommitment:
    return OnChainCommitment(
        sealed_session_key=bytes(kem_size),
        aggregate_signature=bytes(BLS_G2_COMPRESSED_BYTES),
        payload_root=bytes(SHA3_256_BYTES),
    )


def test_construction_ml_kem_768() -> None:
    env = _make(ML_KEM_768_CT_BYTES)
    assert env.total_bytes == 1_088 + 96 + 32


def test_construction_ml_kem_1024() -> None:
    env = _make(ML_KEM_1024_CT_BYTES)
    assert env.total_bytes == 1_568 + 96 + 32


def test_rejects_wrong_sig_size() -> None:
    with pytest.raises(EnvelopeSizeError):
        OnChainCommitment(
            sealed_session_key=bytes(ML_KEM_768_CT_BYTES),
            aggregate_signature=bytes(95),
            payload_root=bytes(SHA3_256_BYTES),
        )


def test_rejects_wrong_payload_root_size() -> None:
    with pytest.raises(EnvelopeSizeError):
        OnChainCommitment(
            sealed_session_key=bytes(ML_KEM_768_CT_BYTES),
            aggregate_signature=bytes(BLS_G2_COMPRESSED_BYTES),
            payload_root=bytes(33),
        )


def test_rejects_wrong_kem_size() -> None:
    with pytest.raises(EnvelopeSizeError):
        OnChainCommitment(
            sealed_session_key=bytes(1_200),
            aggregate_signature=bytes(BLS_G2_COMPRESSED_BYTES),
            payload_root=bytes(SHA3_256_BYTES),
        )


def test_serialize_deserialize_round_trip_768() -> None:
    env = _make(ML_KEM_768_CT_BYTES)
    blob = env.serialize()
    assert len(blob) == ML_KEM_768_CT_BYTES + 96 + 32
    parsed = OnChainCommitment.deserialize(blob)
    assert parsed == env


def test_serialize_deserialize_round_trip_1024() -> None:
    env = _make(ML_KEM_1024_CT_BYTES)
    parsed = OnChainCommitment.deserialize(env.serialize())
    assert parsed == env


def test_payload_cid_uses_corridor_tag() -> None:
    payload = b"institutional commitment"
    env = OnChainCommitment(
        sealed_session_key=bytes(ML_KEM_768_CT_BYTES),
        aggregate_signature=bytes(BLS_G2_COMPRESSED_BYTES),
        payload_root=Cid.of(payload).value,
    )
    assert env.payload_cid() == Cid.of(payload)


def test_commitment_digest_is_stable() -> None:
    a = _make()
    b = _make()
    assert a.commitment_digest() == b.commitment_digest()


def test_strict_total_rejects_approximation() -> None:
    # Neither ML-KEM-768 nor ML-KEM-1024 hits exactly 1,600 — the constant
    # is paper-level, not byte-level. Strict mode surfaces the gap rather
    # than papering over it.
    env = _make(ML_KEM_768_CT_BYTES)
    with pytest.raises(EnvelopeSizeError):
        env.assert_strict_total()
