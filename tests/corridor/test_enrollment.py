"""Enrollment announcements — `src/ltp/corridor/enrollment.py`.

The property under test is one the bare PoP does not have: an announcement
must not be replayable into a seat, corridor, or epoch its owner never claimed.
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.attestation import CorridorPopVerificationFailed, SuperNode
from src.ltp.corridor.bls import corridor_sign, keygen
from src.ltp.corridor.constants import (
    DOMAIN_TAG_CORRIDOR_ENROLL,
    LTP_ATTESTATION_QUORUM_SIZE,
)
from src.ltp.corridor.enrollment import (
    BindingVerificationFailed,
    EnrollmentAnnouncement,
    EpochMismatch,
    MalformedAnnouncement,
    announce,
    build_enrollment_message,
    verify_announcement,
)
from src.ltp.corridor.membership import CorridorRegistry, DuplicateBlsKey
from src.ltp.corridor.wire import (
    WireFormatError,
    enrollment_announcement_from_dict,
    enrollment_announcement_to_dict,
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


def test_a_freshly_made_announcement_verifies():
    pk, sk = keygen()
    ann = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)

    verify_announcement(ann)  # does not raise
    assert ann.super_node.authority == 3
    assert ann.super_node.corridor == CORRIDOR
    assert ann.epoch == 0


def test_binding_message_layout_is_fixed_width_and_ordered():
    pk, _ = keygen()
    msg = build_enrollment_message(CORRIDOR, 5, 3, pk)
    assert msg == (
        DOMAIN_TAG_CORRIDOR_ENROLL
        + CORRIDOR.to_bytes(4, "big")
        + (5).to_bytes(4, "big")
        + (3).to_bytes(4, "big")
        + pk
    )


@pytest.mark.parametrize(
    "corridor_id, epoch, authority",
    [(-1, 0, 0), (0, -1, 0), (0, 0, -1), (1 << 32, 0, 0), (0, 1 << 32, 0), (0, 0, 1 << 32)],
)
def test_binding_message_rejects_out_of_range_fields(corridor_id, epoch, authority):
    pk, _ = keygen()
    with pytest.raises(ValueError):
        build_enrollment_message(corridor_id, epoch, authority, pk)


def test_binding_message_rejects_a_wrong_length_key():
    with pytest.raises(ValueError):
        build_enrollment_message(CORRIDOR, 0, 0, b"\x00" * 47)


# -- the replay this module exists to stop ----------------------------------


def _replay(ann: EnrollmentAnnouncement, **changes) -> EnrollmentAnnouncement:
    """Rebroadcast someone's announcement with altered claims, PoP untouched."""
    node = ann.super_node
    return EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=changes.get("authority", node.authority),
            corridor=changes.get("corridor", node.corridor),
            bls_public_key=node.bls_public_key,
            pop=node.pop,  # genuine, and genuinely useless to the attacker
        ),
        epoch=changes.get("epoch", ann.epoch),
        binding=ann.binding,
    )


@pytest.mark.parametrize("changes", [{"authority": 8}, {"corridor": CORRIDOR + 5}, {"epoch": 1}])
def test_a_replayed_announcement_fails_on_the_binding(changes):
    """The PoP still verifies — that is the whole point. The binding does not."""
    pk, sk = keygen()
    honest = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)
    verify_announcement(honest)

    with pytest.raises(BindingVerificationFailed):
        verify_announcement(_replay(honest, **changes))


def test_seat_squatting_is_blocked_end_to_end():
    """Without the binding, a squatter's replay would take the seat and the
    honest operator's real enrollment would then fail as a duplicate key."""
    pk, sk = keygen()
    honest = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)
    squat = _replay(honest, authority=8)

    reg = CorridorRegistry(corridor_id=CORRIDOR, epoch=0)
    with pytest.raises(BindingVerificationFailed):
        reg.enroll_announcement(squat)
    assert reg.size == 0

    reg.enroll_announcement(honest)
    assert reg.ordered_members()[0].authority == 3

    # And the same squat after the fact still cannot take a second seat.
    with pytest.raises(BindingVerificationFailed):
        reg.enroll_announcement(squat)
    assert reg.size == 1


def test_without_the_binding_the_squat_would_have_worked():
    """Pins the vulnerability the binding closes: `enroll` alone accepts the
    replay, because a bare PoP carries no seat or corridor claim."""
    pk, sk = keygen()
    honest = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)
    squat = _replay(honest, authority=8)

    reg = CorridorRegistry(corridor_id=CORRIDOR, epoch=0)
    reg.enroll(squat.super_node)  # the PoP is genuine, so this passes
    assert reg.size == 1
    with pytest.raises(DuplicateBlsKey):
        reg.enroll(honest.super_node)  # ... and the real operator is locked out


def test_a_binding_for_a_different_key_is_rejected():
    """Holding some key does not let you bind someone else's key to a seat."""
    victim_pk, _ = keygen()
    _, attacker_sk = keygen()
    forged = corridor_sign(attacker_sk, build_enrollment_message(CORRIDOR, 0, 3, victim_pk))
    _, victim_sk = keygen()

    ann = EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=3,
            corridor=CORRIDOR,
            bls_public_key=victim_pk,
            pop=corridor_sign(victim_sk, b"whatever"),
        ),
        epoch=0,
        binding=forged,
    )
    with pytest.raises(BindingVerificationFailed):
        verify_announcement(ann)


def test_a_valid_binding_with_a_broken_pop_is_still_rejected():
    """Both signatures are required; the binding does not subsume the PoP."""
    pk, sk = keygen()
    ann = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)
    broken = EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=3,
            corridor=CORRIDOR,
            bls_public_key=pk,
            pop=corridor_sign(sk, b"not a pop message"),
        ),
        epoch=0,
        binding=ann.binding,
    )
    with pytest.raises(CorridorPopVerificationFailed):
        verify_announcement(broken)


# -- structural validation --------------------------------------------------


@pytest.mark.parametrize("length", [0, 95, 97])
def test_wrong_length_binding_is_malformed(length):
    pk, sk = keygen()
    ann = announce(sk, pk, corridor_id=CORRIDOR, authority=3)
    bad = EnrollmentAnnouncement(super_node=ann.super_node, epoch=0, binding=b"\x00" * length)
    with pytest.raises(MalformedAnnouncement):
        verify_announcement(bad)


def test_wrong_length_key_is_malformed():
    ann = EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=1, corridor=CORRIDOR, bls_public_key=b"\x00" * 10, pop=b"\x00" * 96
        ),
        epoch=0,
        binding=b"\x00" * 96,
    )
    with pytest.raises(MalformedAnnouncement):
        verify_announcement(ann)


def test_out_of_range_epoch_is_malformed():
    pk, sk = keygen()
    ann = announce(sk, pk, corridor_id=CORRIDOR, authority=3)
    bad = EnrollmentAnnouncement(super_node=ann.super_node, epoch=1 << 32, binding=ann.binding)
    with pytest.raises(MalformedAnnouncement):
        verify_announcement(bad)


# -- registry integration ---------------------------------------------------


def test_registry_rejects_an_announcement_from_another_epoch():
    """A retired member's old announcement must not re-seat into a new roster."""
    pk, sk = keygen()
    old = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=0)

    reg = CorridorRegistry(corridor_id=CORRIDOR, epoch=1)
    with pytest.raises(EpochMismatch) as exc:
        reg.enroll_announcement(old)
    assert exc.value.expected == 1
    assert exc.value.got == 0
    assert reg.size == 0


def test_a_full_roster_assembles_from_announcements():
    reg = CorridorRegistry(corridor_id=CORRIDOR, epoch=2)
    for i in range(LTP_ATTESTATION_QUORUM_SIZE):
        pk, sk = keygen()
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, i, epoch=2))

    corridor = reg.finalize()
    assert len(corridor.members) == LTP_ATTESTATION_QUORUM_SIZE
    corridor.verify_pops()


def test_roster_digest_is_bound_to_the_epoch():
    """Same corridor, same nine keys, different epoch — different digest."""
    keys = [keygen() for _ in range(LTP_ATTESTATION_QUORUM_SIZE)]

    digests = []
    for epoch in (0, 1):
        reg = CorridorRegistry(corridor_id=CORRIDOR, epoch=epoch)
        for i, (pk, sk) in enumerate(keys):
            reg.enroll_announcement(announce(sk, pk, CORRIDOR, i, epoch=epoch))
        digests.append(reg.roster_digest())

    assert digests[0] != digests[1]


# -- wire -------------------------------------------------------------------


def test_announcement_survives_a_wire_round_trip():
    pk, sk = keygen()
    ann = announce(sk, pk, corridor_id=CORRIDOR, authority=3, epoch=4)

    restored = enrollment_announcement_from_dict(enrollment_announcement_to_dict(ann))
    assert restored == ann
    verify_announcement(restored)


def test_wire_rejects_a_truncated_binding():
    pk, sk = keygen()
    d = enrollment_announcement_to_dict(announce(sk, pk, CORRIDOR, 3))
    d["binding"] = d["binding"][:-2]
    with pytest.raises(WireFormatError):
        enrollment_announcement_from_dict(d)
