"""Seat entitlement — `src/ltp/corridor/policy.py`.

The gap this closes is narrow and easy to miss: the enrollment binding stops
someone *replaying your announcement*, but it does nothing at all against a
stranger who generates their own keypair and announces for your seat. That
announcement is genuinely signed, by a key its sender genuinely holds, and
`verify_announcement` passes it. `test_the_binding_alone_does_not_stop_an_outsider`
pins that, and the rest of this file is about the policy that does.
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.bls import keygen
from src.ltp.corridor.constants import LTP_ATTESTATION_QUORUM_SIZE
from src.ltp.corridor.enrollment import announce, verify_announcement
from src.ltp.corridor.membership import CorridorRegistry, NoEnrollmentPolicy
from src.ltp.corridor.policy import (
    EnrollmentPolicy,
    OpenEnrollment,
    SeatAllowlist,
    SeatNotAuthorized,
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
def keys():
    """Nine keypairs, generated once — keygen dominates this file's runtime."""
    return [keygen() for _ in range(LTP_ATTESTATION_QUORUM_SIZE)]


@pytest.fixture(scope="module")
def allowlist(keys):
    return SeatAllowlist(corridor_id=CORRIDOR, seats={i: pk for i, (pk, _) in enumerate(keys)})


# -- the gap the policy exists to close -------------------------------------


def test_the_binding_alone_does_not_stop_an_outsider(keys):
    """A stranger's own-key announcement for someone else's seat is valid.

    Nothing is forged here: they hold the key, they signed the binding, and it
    verifies. Entitlement is a separate question from authenticity, and this is
    why `enroll_announcement` refuses to run without a policy."""
    outsider_pk, outsider_sk = keygen()
    squat = announce(outsider_sk, outsider_pk, CORRIDOR, authority=3)

    verify_announcement(squat)  # does not raise — the announcement is genuine

    open_reg = CorridorRegistry(corridor_id=CORRIDOR, policy=OpenEnrollment())
    open_reg.enroll_announcement(squat)
    assert open_reg.size == 1  # ... and with no entitlement policy, they are in


def test_the_allowlist_stops_that_outsider(allowlist):
    outsider_pk, outsider_sk = keygen()
    squat = announce(outsider_sk, outsider_pk, CORRIDOR, authority=3)

    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=allowlist)
    with pytest.raises(SeatNotAuthorized) as exc:
        reg.enroll_announcement(squat)
    assert exc.value.authority == 3
    assert "not the key published for it" in exc.value.reason
    assert reg.size == 0


def test_an_allowlisted_operator_cannot_take_a_colleagues_seat(keys, allowlist):
    """The allowlist binds seat → key, not merely "is an approved key", so an
    insider cannot rearrange the seating."""
    pk_2, sk_2 = keys[2]
    wrong_seat = announce(sk_2, pk_2, CORRIDOR, authority=5)

    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=allowlist)
    with pytest.raises(SeatNotAuthorized):
        reg.enroll_announcement(wrong_seat)

    reg.enroll_announcement(announce(sk_2, pk_2, CORRIDOR, authority=2))
    assert reg.size == 1


def test_a_seat_not_on_the_list_is_refused(keys):
    """Growing the corridor must be an explicit edit, not an omission."""
    partial = SeatAllowlist(corridor_id=CORRIDOR, seats={0: keys[0][0], 1: keys[1][0]})
    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=partial)

    pk, sk = keys[2]
    with pytest.raises(SeatNotAuthorized) as exc:
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, authority=2))
    assert "not on the allowlist" in exc.value.reason


def test_an_allowlist_for_another_corridor_refuses(keys, allowlist):
    """A key published for corridor 7 must not carry into corridor 12."""
    pk, sk = keys[0]
    reg = CorridorRegistry(corridor_id=CORRIDOR + 5, policy=allowlist)

    with pytest.raises(SeatNotAuthorized) as exc:
        reg.enroll_announcement(announce(sk, pk, CORRIDOR + 5, authority=0))
    assert "corridor" in exc.value.reason


def test_a_full_allowlisted_roster_assembles(keys, allowlist):
    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=allowlist)
    for i, (pk, sk) in enumerate(keys):
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, i))

    corridor = reg.finalize()
    assert len(corridor.members) == LTP_ATTESTATION_QUORUM_SIZE
    corridor.verify_pops()


# -- fail-closed ------------------------------------------------------------


def test_announcements_are_refused_without_a_policy(keys):
    """The default must not be "anyone", because that is the corridor going to
    whoever arrives first."""
    pk, sk = keys[0]
    reg = CorridorRegistry(corridor_id=CORRIDOR)

    with pytest.raises(NoEnrollmentPolicy) as exc:
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, 0))
    assert "OpenEnrollment" in str(exc.value)
    assert reg.size == 0


def test_the_local_enroll_path_is_unaffected(keys):
    """`enroll` is documented as the local path — the caller built the
    SuperNode and has already decided — so it needs no policy."""
    pk, sk = keys[0]
    ann = announce(sk, pk, CORRIDOR, 0)

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    reg.enroll(ann.super_node)
    assert reg.size == 1


def test_open_enrollment_must_be_named(keys):
    """It cannot be reached by omission — only by typing it."""
    pk, sk = keys[0]
    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=OpenEnrollment())
    reg.enroll_announcement(announce(sk, pk, CORRIDOR, 0))
    assert reg.size == 1


def test_policy_runs_before_signature_verification(keys, allowlist):
    """Unauthorized seats must be rejected without spending a BLS pairing, or
    a stranger can make a node do expensive work for free."""
    pk, sk = keys[0]
    good = announce(sk, pk, CORRIDOR, 0)

    # An announcement whose binding is garbage AND whose seat is unauthorized.
    from src.ltp.corridor.attestation import SuperNode
    from src.ltp.corridor.enrollment import EnrollmentAnnouncement

    outsider_pk, _ = keygen()
    both_wrong = EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=0, corridor=CORRIDOR, bls_public_key=outsider_pk, pop=good.super_node.pop
        ),
        epoch=0,
        binding=b"\x00" * 96,
    )

    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=allowlist)
    # Entitlement is what it reports — not the signature failure that would
    # have come from doing the expensive check first.
    with pytest.raises(SeatNotAuthorized):
        reg.enroll_announcement(both_wrong)


# -- allowlist construction is the thing operators get wrong ----------------


def test_two_seats_sharing_one_key_is_refused_at_construction(keys):
    """Baked into config it would look deliberate, and it hands one operator
    two of nine votes — the threshold becomes a fiction."""
    pk = keys[0][0]
    with pytest.raises(ValueError) as exc:
        SeatAllowlist(corridor_id=CORRIDOR, seats={0: pk, 1: pk})
    assert "independent key" in str(exc.value)


def test_an_empty_allowlist_is_refused(keys):
    with pytest.raises(ValueError) as exc:
        SeatAllowlist(corridor_id=CORRIDOR, seats={})
    assert "OpenEnrollment" in str(exc.value)


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 47, b"\x00" * 49, "not-bytes"])
def test_a_malformed_key_is_refused_at_construction(bad_key):
    with pytest.raises(ValueError):
        SeatAllowlist(corridor_id=CORRIDOR, seats={0: bad_key})


@pytest.mark.parametrize("bad_seat", [-1, 1 << 32, True, "0"])
def test_a_malformed_seat_id_is_refused_at_construction(keys, bad_seat):
    with pytest.raises(ValueError):
        SeatAllowlist(corridor_id=CORRIDOR, seats={bad_seat: keys[0][0]})


def test_an_out_of_range_corridor_id_is_refused(keys):
    with pytest.raises(ValueError):
        SeatAllowlist(corridor_id=1 << 32, seats={0: keys[0][0]})


# -- the digest operators compare -------------------------------------------


def test_digest_is_stable_across_insertion_order(keys):
    forward = SeatAllowlist(CORRIDOR, {i: pk for i, (pk, _) in enumerate(keys)})
    backward = SeatAllowlist(CORRIDOR, dict(reversed([(i, pk) for i, (pk, _) in enumerate(keys)])))
    assert forward.digest() == backward.digest()
    assert len(forward.digest()) == 32


def test_digest_changes_when_a_seat_changes(keys, allowlist):
    other_pk, _ = keygen()
    swapped = dict(allowlist.seats)
    swapped[3] = other_pk

    assert SeatAllowlist(CORRIDOR, swapped).digest() != allowlist.digest()


def test_digest_is_bound_to_the_corridor(keys, allowlist):
    same_seats = SeatAllowlist(CORRIDOR + 1, dict(allowlist.seats))
    assert same_seats.digest() != allowlist.digest()


def test_allowlist_digest_is_not_a_roster_digest(keys, allowlist):
    """They answer different questions — who *may* enrol vs. who *did* — and a
    shared digest would make a correct roster look wrong."""
    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=allowlist)
    for i, (pk, sk) in enumerate(keys):
        reg.enroll_announcement(announce(sk, pk, CORRIDOR, i))

    assert reg.roster_digest() != allowlist.digest()


# -- the seam ---------------------------------------------------------------


def test_a_custom_policy_satisfies_the_protocol(keys):
    """Stake and governance policies are meant to land here later without the
    registry changing."""

    class RefuseEveryOddSeat:
        def authorize(self, announcement) -> None:
            seat = announcement.super_node.authority
            if seat % 2:
                raise SeatNotAuthorized(seat, "odd seats are closed today")

    policy = RefuseEveryOddSeat()
    assert isinstance(policy, EnrollmentPolicy)

    reg = CorridorRegistry(corridor_id=CORRIDOR, policy=policy)
    pk0, sk0 = keys[0]
    pk1, sk1 = keys[1]

    reg.enroll_announcement(announce(sk0, pk0, CORRIDOR, 0))
    with pytest.raises(SeatNotAuthorized):
        reg.enroll_announcement(announce(sk1, pk1, CORRIDOR, 1))
    assert reg.size == 1
