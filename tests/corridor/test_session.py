"""Signing sessions — `src/ltp/corridor/session.py`.

Covers the three things `attest()` cannot do on its own: accept partials one
at a time from an untrusted network, refuse to let a node equivocate against
itself, and prove it when someone else does.
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.attestation import (
    AttestationPayload,
    BadCorridorSize,
    Corridor,
    InvalidSignature,
    UnknownWitness,
    WitnessSignature,
    verify_attestation,
)
from src.ltp.corridor.bls import corridor_sign, keygen
from src.ltp.corridor.constants import (
    LTP_ATTESTATION_QUORUM_SIZE,
    LTP_ATTESTATION_QUORUM_THRESHOLD,
)
from src.ltp.corridor.enrollment import announce
from src.ltp.corridor.membership import CorridorRegistry
from src.ltp.corridor.session import (
    CorridorSigner,
    DoubleSignAttempt,
    EquivocationEvidence,
    EquivocationMonitor,
    NotEquivocation,
    QuorumNotReached,
    SessionKey,
    SigningSession,
    WrongPayload,
)
from src.ltp.corridor.wire import (
    WireFormatError,
    equivocation_evidence_from_dict,
    equivocation_evidence_to_dict,
)

try:
    from src.ltp.corridor.bls import _blst_available, _py_ecc_available

    _HAS_BLS_BACKEND = _blst_available or _py_ecc_available
except (ImportError, AttributeError):  # pragma: no cover — backend detection
    _HAS_BLS_BACKEND = False

pytestmark = pytest.mark.skipif(
    not _HAS_BLS_BACKEND, reason="no BLS backend (blst or py_ecc) installed"
)

CORRIDOR = 7


@pytest.fixture(scope="module")
def roster():
    """A real 9-member corridor plus the signers that hold its keys.

    Module-scoped because nine BLS keygens plus their PoPs is the slowest
    thing in this file by an order of magnitude, and every test wants the
    same roster.
    """
    keys = [keygen() for _ in range(LTP_ATTESTATION_QUORUM_SIZE)]
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    for i, (pk, sk) in enumerate(keys):
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, i))
    signers = [CorridorSigner(i, sk) for i, (_, sk) in enumerate(keys)]
    secret_keys = [sk for _, sk in keys]
    # The raw keys are handed out so the equivocation tests can sign conflicting
    # payloads directly — `CorridorSigner.sign` refuses to, which is the point.
    return reg.finalize(), signers, secret_keys


def _payload(height: int = 100, root: bytes = b"\xaa" * 32) -> AttestationPayload:
    return AttestationPayload(
        source_chain=1,
        target_chain=2,
        source_height=height,
        state_root=root,
        timestamp_round=42,
    )


# -- collecting to quorum ---------------------------------------------------


def test_seven_partials_finalize_into_a_verifiable_attestation(roster):
    corridor, signers, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)

    for signer in signers[:LTP_ATTESTATION_QUORUM_THRESHOLD]:
        assert session.submit(signer.sign(payload)) is True

    assert session.has_quorum
    attestation = session.finalize()
    verify_attestation(corridor, attestation)  # does not raise
    assert len(attestation.signers) == LTP_ATTESTATION_QUORUM_THRESHOLD


def test_a_session_below_quorum_says_how_many_are_missing(roster):
    corridor, signers, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)

    for signer in signers[:4]:
        session.submit(signer.sign(payload))

    assert not session.has_quorum
    assert session.have == 4
    assert session.missing() == LTP_ATTESTATION_QUORUM_THRESHOLD - 4
    with pytest.raises(QuorumNotReached) as exc:
        session.finalize()
    assert exc.value.have == 4
    assert exc.value.need == LTP_ATTESTATION_QUORUM_THRESHOLD


def test_partials_may_arrive_in_any_order(roster):
    corridor, signers, secret_keys = roster
    payload = _payload()

    a = SigningSession(corridor, payload)
    b = SigningSession(corridor, payload)
    chosen = signers[:LTP_ATTESTATION_QUORUM_THRESHOLD]
    for signer in chosen:
        a.submit(signer.sign(payload))
    for signer in reversed(chosen):
        b.submit(signer.sign(payload))

    assert a.signers == b.signers
    assert a.partials() == b.partials()
    assert a.finalize().aggregate_signature == b.finalize().aggregate_signature


def test_a_resent_partial_is_not_an_error(roster):
    """Peers legitimately resend; a resend must not raise and must not count twice."""
    corridor, signers, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)

    ws = signers[0].sign(payload)
    assert session.submit(ws) is True
    assert session.submit(ws) is False
    assert session.have == 1


def test_a_non_member_partial_is_rejected(roster):
    corridor, _, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)

    outsider_pk, outsider_sk = keygen()
    ws = WitnessSignature(
        witness=99, signature=corridor_sign(outsider_sk, payload.canonical_digest())
    )
    with pytest.raises(UnknownWitness):
        session.submit(ws)
    assert session.have == 0
    assert outsider_pk not in [m.bls_public_key for m in corridor.members]


def test_a_garbage_signature_from_a_real_member_is_rejected(roster):
    corridor, signers, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)

    forged = WitnessSignature(witness=0, signature=b"\x00" * 96)
    with pytest.raises(InvalidSignature):
        session.submit(forged)
    assert session.have == 0

    # And the session still works afterwards — a rejection is not corrupting.
    session.submit(signers[0].sign(payload))
    assert session.have == 1


def test_a_partial_for_another_payload_is_rejected(roster):
    """A peer a round behind must not have its stale signature counted."""
    corridor, signers, secret_keys = roster
    session = SigningSession(corridor, _payload(height=100))

    stale_payload = _payload(height=99)
    stale = signers[0].sign(stale_payload)

    with pytest.raises(WrongPayload):
        session.submit_for_payload(stale_payload, stale)
    # Submitted bare, it fails signature verification instead — either way, out.
    with pytest.raises(InvalidSignature):
        session.submit(stale)
    assert session.have == 0


def test_outstanding_names_who_has_not_signed(roster):
    corridor, signers, secret_keys = roster
    payload = _payload()
    session = SigningSession(corridor, payload)
    for signer in signers[:3]:
        session.submit(signer.sign(payload))

    assert session.outstanding() == tuple(range(3, LTP_ATTESTATION_QUORUM_SIZE))


def test_session_refuses_a_corridor_that_is_not_nine(roster):
    corridor, _, secret_keys = roster
    short = Corridor(id=CORRIDOR, members=corridor.members[:5])
    with pytest.raises(BadCorridorSize):
        SigningSession(short, _payload())


def test_session_refuses_an_impossible_threshold(roster):
    corridor, _, secret_keys = roster
    with pytest.raises(ValueError):
        SigningSession(corridor, _payload(), threshold=0)
    with pytest.raises(ValueError):
        SigningSession(corridor, _payload(), threshold=LTP_ATTESTATION_QUORUM_SIZE + 1)


# -- the local double-sign guard --------------------------------------------


def test_a_signer_refuses_to_sign_a_conflicting_payload(roster):
    """Paper §6.4: equivocation forfeits 100% of bonded stake. An honest node
    should decline to produce the evidence rather than emit it by accident."""
    _, signers, secret_keys = roster
    signer = signers[0]

    signer.sign(_payload(height=100, root=b"\xaa" * 32))
    with pytest.raises(DoubleSignAttempt) as exc:
        signer.sign(_payload(height=100, root=b"\xbb" * 32))
    assert exc.value.authority == signer.authority
    assert exc.value.round_key == SessionKey(1, 2, 100)


def test_re_signing_the_same_payload_is_allowed_and_stable(roster):
    """A retry after a dropped response is not equivocation, and BLS is
    deterministic, so the second signature must be byte-identical."""
    _, signers, secret_keys = roster
    signer = signers[1]
    payload = _payload(height=200)

    first = signer.sign(payload)
    second = signer.sign(payload)
    assert first == second


def test_a_signer_may_sign_different_rounds(roster):
    _, signers, secret_keys = roster
    signer = signers[2]
    signer.sign(_payload(height=300))
    signer.sign(_payload(height=301, root=b"\xcc" * 32))  # different round: fine
    assert signer.has_signed(SessionKey(1, 2, 300))
    assert signer.has_signed(SessionKey(1, 2, 301))
    assert not signer.has_signed(SessionKey(1, 2, 302))


# -- proving someone else's equivocation ------------------------------------


def _equivocate(sk: bytes, authority: int, a, b):
    """Sign two conflicting payloads directly, bypassing the local guard."""
    return (
        WitnessSignature(authority, corridor_sign(sk, a.canonical_digest())),
        WitnessSignature(authority, corridor_sign(sk, b.canonical_digest())),
    )


def test_monitor_emits_evidence_for_two_state_roots_at_one_height(roster):
    corridor, signers, secret_keys = roster
    sk = secret_keys[0]
    a = _payload(height=500, root=b"\x01" * 32)
    b = _payload(height=500, root=b"\x02" * 32)
    ws_a, ws_b = _equivocate(sk, 0, a, b)

    monitor = EquivocationMonitor()
    assert monitor.observe(a, ws_a) is None
    evidence = monitor.observe(b, ws_b)

    assert evidence is not None
    assert evidence.witness == 0
    assert evidence.key == SessionKey(1, 2, 500)
    evidence.verify(corridor)  # anyone can re-check it without trusting us


def test_monitor_stays_quiet_for_honest_signing(roster):
    corridor, signers, secret_keys = roster
    monitor = EquivocationMonitor()
    for height in (600, 601, 602):
        payload = _payload(height=height)
        for signer in signers[:3]:
            assert monitor.observe(payload, signer.sign(payload)) is None
    assert monitor.tracked_rounds == 3
    assert corridor.id == CORRIDOR


def test_monitor_treats_a_resent_partial_as_a_retry(roster):
    _, signers, secret_keys = roster
    payload = _payload(height=700)
    ws = signers[0].sign(payload)

    monitor = EquivocationMonitor()
    monitor.observe(payload, ws)
    assert monitor.observe(payload, ws) is None


def test_monitor_forgets_finalized_rounds(roster):
    _, signers, secret_keys = roster
    monitor = EquivocationMonitor()
    for height in (800, 801, 802):
        payload = _payload(height=height)
        monitor.observe(payload, signers[0].sign(payload))

    assert monitor.tracked_rounds == 3
    assert monitor.forget_through(801) == 2
    assert monitor.tracked_rounds == 1


def test_evidence_against_a_non_member_is_refused(roster):
    corridor, _, secret_keys = roster
    _, outsider_sk = keygen()
    a = _payload(height=900, root=b"\x01" * 32)
    b = _payload(height=900, root=b"\x02" * 32)
    ws_a, ws_b = _equivocate(outsider_sk, 99, a, b)

    evidence = EquivocationEvidence(99, a, ws_a.signature, b, ws_b.signature)
    with pytest.raises(UnknownWitness):
        evidence.verify(corridor)


def test_evidence_for_two_different_rounds_is_not_equivocation(roster):
    """Signing height 100 and height 101 is the job, not an offence."""
    corridor, signers, secret_keys = roster
    sk = secret_keys[0]
    a = _payload(height=1000)
    b = _payload(height=1001)
    ws_a, ws_b = _equivocate(sk, 0, a, b)

    evidence = EquivocationEvidence(0, a, ws_a.signature, b, ws_b.signature)
    with pytest.raises(NotEquivocation):
        evidence.verify(corridor)


def test_evidence_citing_one_payload_twice_is_not_equivocation(roster):
    corridor, signers, secret_keys = roster
    payload = _payload(height=1100)
    ws = signers[0].sign(payload)

    evidence = EquivocationEvidence(0, payload, ws.signature, payload, ws.signature)
    with pytest.raises(NotEquivocation):
        evidence.verify(corridor)


def test_fabricated_evidence_does_not_verify(roster):
    """An accusation nobody signed must not stick to an honest member."""
    corridor, signers, secret_keys = roster
    a = _payload(height=1200, root=b"\x01" * 32)
    b = _payload(height=1200, root=b"\x02" * 32)
    real = signers[0].sign(a)

    evidence = EquivocationEvidence(0, a, real.signature, b, b"\x00" * 96)
    with pytest.raises(InvalidSignature):
        evidence.verify(corridor)


def test_evidence_survives_a_wire_round_trip(roster):
    corridor, signers, secret_keys = roster
    sk = secret_keys[0]
    a = _payload(height=1300, root=b"\x01" * 32)
    b = _payload(height=1300, root=b"\x02" * 32)
    ws_a, ws_b = _equivocate(sk, 0, a, b)

    monitor = EquivocationMonitor()
    monitor.observe(a, ws_a)
    evidence = monitor.observe(b, ws_b)
    assert evidence is not None

    restored = equivocation_evidence_from_dict(equivocation_evidence_to_dict(evidence))
    assert restored == evidence
    restored.verify(corridor)


def test_wire_rejects_evidence_with_a_truncated_signature(roster):
    _, signers, secret_keys = roster
    a = _payload(height=1400, root=b"\x01" * 32)
    b = _payload(height=1400, root=b"\x02" * 32)
    ws_a, ws_b = _equivocate(secret_keys[0], 0, a, b)

    d = equivocation_evidence_to_dict(EquivocationEvidence(0, a, ws_a.signature, b, ws_b.signature))
    d["signature_b"] = d["signature_b"][:-2]
    with pytest.raises(WireFormatError):
        equivocation_evidence_from_dict(d)


# -- the whole loop ---------------------------------------------------------


def test_a_round_runs_end_to_end_with_a_liar_in_the_set(roster):
    """Seven honest signers reach quorum while an eighth equivocates; the
    attestation is valid and the equivocation is caught, in one pass."""
    corridor, signers, secret_keys = roster
    payload = _payload(height=1500, root=b"\x0f" * 32)
    conflicting = _payload(height=1500, root=b"\xf0" * 32)

    session = SigningSession(corridor, payload)
    monitor = EquivocationMonitor()
    caught = []

    for signer in signers[:LTP_ATTESTATION_QUORUM_THRESHOLD]:
        ws = signer.sign(payload)
        session.submit(ws)
        monitor.observe(payload, ws)

    liar = signers[8]
    ws_honest = liar.sign(payload)
    session.submit(ws_honest)
    monitor.observe(payload, ws_honest)

    ws_liar = WitnessSignature(
        liar.authority, corridor_sign(secret_keys[8], conflicting.canonical_digest())
    )
    evidence = monitor.observe(conflicting, ws_liar)
    if evidence is not None:
        evidence.verify(corridor)
        caught.append(evidence.witness)

    attestation = session.finalize()
    verify_attestation(corridor, attestation)
    assert caught == [liar.authority]


# -- surviving a restart ----------------------------------------------------


def test_signer_rejects_a_wrong_length_secret_key():
    """A bad key should fail at startup, not halfway through a round."""
    with pytest.raises(ValueError):
        CorridorSigner(0, b"\x00" * 31)
    with pytest.raises(ValueError):
        CorridorSigner(-1, b"\x00" * 32)


def test_a_restored_signer_still_refuses_to_equivocate(roster):
    """The restart case: a node that forgot what it signed is the one that
    equivocates by accident and loses its bond."""
    _, _, secret_keys = roster
    before = CorridorSigner(0, secret_keys[0])
    payload = _payload(height=1600, root=b"\x01" * 32)
    before.sign(payload)
    persisted = before.signed_rounds()

    after = CorridorSigner(0, secret_keys[0])  # fresh process, empty guard
    after.sign(_payload(height=1600, root=b"\x02" * 32))  # would have equivocated

    restored = CorridorSigner(0, secret_keys[0])
    restored.restore(persisted)
    with pytest.raises(DoubleSignAttempt):
        restored.sign(_payload(height=1600, root=b"\x02" * 32))


def test_restore_surfaces_an_equivocation_already_committed(roster):
    """If the persisted record and the live one disagree, this node already
    signed twice; picking one silently would bury it."""
    _, _, secret_keys = roster
    signer = CorridorSigner(0, secret_keys[0])
    signer.sign(_payload(height=1700, root=b"\x01" * 32))

    conflicting = {SessionKey(1, 2, 1700): _payload(1700, b"\x02" * 32).canonical_digest()}
    with pytest.raises(DoubleSignAttempt):
        signer.restore(conflicting)


def test_restore_is_idempotent_and_merges(roster):
    _, _, secret_keys = roster
    signer = CorridorSigner(0, secret_keys[0])
    a = _payload(height=1800)
    signer.sign(a)
    records = signer.signed_rounds()

    signer.restore(records)  # same record again: fine
    signer.restore({SessionKey(1, 2, 1801): b"\x07" * 32})
    assert signer.has_signed(SessionKey(1, 2, 1800))
    assert signer.has_signed(SessionKey(1, 2, 1801))


def test_restore_rejects_a_wrong_length_digest(roster):
    _, _, secret_keys = roster
    signer = CorridorSigner(0, secret_keys[0])
    with pytest.raises(ValueError):
        signer.restore({SessionKey(1, 2, 1900): b"\x00" * 16})
