"""7-of-9 corridor attestation pipeline tests.

These require a working BLS backend (`blst` or py_ecc's `G2Basic`); they're
skipped if neither is importable.
"""

from __future__ import annotations

import pytest

from ltp.corridor import (
    AggregateVerificationFailed,
    AttestationPayload,
    BadCorridorSize,
    BelowQuorum,
    Corridor,
    CorridorBlsBackendMissing,
    SuperNode,
    UnknownWitness,
    WitnessSignature,
    attest,
    corridor_sign,
    keygen,
    verify_attestation,
)


def _backend_available() -> bool:
    try:
        keygen()
        return True
    except CorridorBlsBackendMissing:
        return False


pytestmark = pytest.mark.skipif(
    not _backend_available(),
    reason="no BLS backend (blst or py_ecc.G2Basic) available",
)


def _build_corridor() -> tuple[Corridor, list[bytes]]:
    members = []
    sks = []
    for i in range(9):
        pk, sk = keygen()
        members.append(SuperNode(authority=i, corridor=0, bls_public_key=pk))
        sks.append(sk)
    return Corridor(id=0, members=tuple(members)), sks


def _payload() -> AttestationPayload:
    return AttestationPayload(
        source_chain=1,
        target_chain=100,
        source_height=42,
        state_root=bytes([0xAB] * 32),
        timestamp_round=7,
    )


def test_seven_signatures_attest_and_verify() -> None:
    corridor, sks = _build_corridor()
    payload = _payload()
    digest = payload.canonical_digest()
    sigs = [
        WitnessSignature(witness=i, signature=corridor_sign(sks[i], digest))
        for i in range(7)
    ]
    att = attest(corridor, payload, sigs)
    verify_attestation(corridor, att)
    assert len(att.signers) == 7


def test_six_signatures_below_quorum() -> None:
    corridor, sks = _build_corridor()
    payload = _payload()
    digest = payload.canonical_digest()
    sigs = [
        WitnessSignature(witness=i, signature=corridor_sign(sks[i], digest))
        for i in range(6)
    ]
    with pytest.raises(BelowQuorum) as e:
        attest(corridor, payload, sigs)
    assert e.value.have == 6 and e.value.need == 7


def test_bad_corridor_size_rejected() -> None:
    corridor, _sks = _build_corridor()
    truncated = Corridor(id=corridor.id, members=corridor.members[:8])
    with pytest.raises(BadCorridorSize):
        attest(truncated, _payload(), [])


def test_unknown_witness_rejected() -> None:
    corridor, _sks = _build_corridor()
    payload = _payload()
    digest = payload.canonical_digest()
    _, foreign_sk = keygen()
    sigs = [WitnessSignature(witness=99, signature=corridor_sign(foreign_sk, digest))]
    with pytest.raises(UnknownWitness):
        attest(corridor, payload, sigs)


def test_tampered_state_root_breaks_verification() -> None:
    corridor, sks = _build_corridor()
    payload = _payload()
    digest = payload.canonical_digest()
    sigs = [
        WitnessSignature(witness=i, signature=corridor_sign(sks[i], digest))
        for i in range(7)
    ]
    att = attest(corridor, payload, sigs)

    tampered_payload = AttestationPayload(
        source_chain=payload.source_chain,
        target_chain=payload.target_chain,
        source_height=payload.source_height,
        state_root=bytes([payload.state_root[0] ^ 1]) + payload.state_root[1:],
        timestamp_round=payload.timestamp_round,
    )
    tampered = att.__class__(
        payload=tampered_payload,
        aggregate_signature=att.aggregate_signature,
        signers=att.signers,
    )
    with pytest.raises(AggregateVerificationFailed):
        verify_attestation(corridor, tampered)


def test_duplicate_signer_collapsed() -> None:
    corridor, sks = _build_corridor()
    payload = _payload()
    digest = payload.canonical_digest()
    sigs = [
        WitnessSignature(witness=i, signature=corridor_sign(sks[i], digest))
        for i in range(7)
    ]
    # Same signer twice — must be collapsed, not double-counted as 8.
    sigs.append(sigs[0])
    att = attest(corridor, payload, sigs)
    assert len(att.signers) == 7
