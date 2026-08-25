"""Enrollment announcements — the message an operator broadcasts to claim a seat.

`membership.py` answers "is this roster legitimate". This module answers the
question underneath it: *what does an operator actually send, and what stops
someone else sending it for them?*

The obvious answer — broadcast the `SuperNode` record and let the registry
check the PoP — does not hold up. `DOMAIN_TAG_CORRIDOR_POP` signs the public
key **alone**::

    pop = Sign(sk, DOMAIN_TAG_CORRIDOR_POP || pk)

That proves the sender holds `sk`. It says nothing about *which corridor*,
*which seat*, or *which roster epoch* they are claiming, because none of those
appear under the signature. So a PoP is replayable in a way that matters:

1. Operator A broadcasts a legitimate enrollment for corridor 7, seat 3.
2. Anyone who saw it rebroadcasts the same key and PoP as corridor 7, seat 8
   — or corridor 12, or next epoch's corridor 7.
3. The registry verifies the PoP (it is genuine), admits the squatter, and
   then rejects A's real enrollment with `DuplicateBlsKey`.

The attacker needs no key material and pays nothing. A's seat is simply gone
until somebody reconciles it by hand — which is exactly the human arrangement
the registry was built to remove. The same replay across epochs quietly
re-seats a retired member into a fresh roster.

The fix is a second signature over the fields that were missing::

    binding = Sign(sk, DOMAIN_TAG_CORRIDOR_ENROLL || corridor || epoch || authority || pk)

Both signatures come from the same key, so this adds no key management and no
round trip — the operator produces both offline, once, and the announcement is
then self-authenticating and safe to relay over any untrusted transport. The
PoP is kept as-is rather than replaced because its format is pinned across
repos (`suwappu-dag/crates/suwappu-ltp`); the binding is additive and
Python-side.

What this still does not do: nothing here decides *who is entitled* to a seat.
An announcement proves "the holder of this key wants seat 3 of corridor 7 in
epoch 0" — an authorization policy (an allowlist, a stake check, a governance
vote) is a separate concern and belongs above this layer.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import AuthorityId, CorridorId, LtpError, SuperNode
from .bls import corridor_sign, corridor_verify
from .constants import DOMAIN_TAG_CORRIDOR_ENROLL, DOMAIN_TAG_CORRIDOR_POP
from .membership import BLS_POP_BYTES, BLS_PUBKEY_BYTES, ID_MAX, build_pop_message


class EnrollmentError(LtpError):
    """Base class for enrollment-announcement failures."""


class MalformedAnnouncement(EnrollmentError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"enrollment announcement is malformed: {reason}")
        self.reason = reason


class BindingVerificationFailed(EnrollmentError):
    """The binding signature does not cover this (corridor, epoch, seat, key).

    Distinct from `CorridorPopVerificationFailed`: a replayed announcement
    carries a perfectly valid PoP and fails *here*, which is the signal that
    someone is claiming a seat with a key they may well hold but did not
    intend to enrol at this position.
    """

    def __init__(self, authority: AuthorityId) -> None:
        super().__init__(
            f"enrollment binding signature failed for seat {authority}; the PoP may "
            "be genuine but it was not issued for this corridor/epoch/seat"
        )
        self.authority = authority


class EpochMismatch(EnrollmentError):
    def __init__(self, expected: int, got: int) -> None:
        super().__init__(f"announcement is for epoch {got}, registry is at epoch {expected}")
        self.expected = expected
        self.got = got


def build_enrollment_message(
    corridor_id: CorridorId,
    epoch: int,
    authority: AuthorityId,
    bls_public_key: bytes,
) -> bytes:
    """The exact bytes an operator signs to bind a key to one seat.

    Layout: ``tag || corridor(u32 BE) || epoch(u32 BE) || authority(u32 BE) || pk``.
    Every field is fixed-width, so the concatenation is unambiguous and no
    length prefixes are needed.
    """
    if len(bls_public_key) != BLS_PUBKEY_BYTES:
        raise ValueError(
            f"BLS public key must be {BLS_PUBKEY_BYTES} bytes, got {len(bls_public_key)}"
        )
    for name, value in (
        ("corridor_id", corridor_id),
        ("epoch", epoch),
        ("authority", authority),
    ):
        if not 0 <= value <= ID_MAX:
            raise ValueError(f"{name} must fit in u32 (0..{ID_MAX}), got {value}")
    return (
        DOMAIN_TAG_CORRIDOR_ENROLL
        + corridor_id.to_bytes(4, "big")
        + epoch.to_bytes(4, "big")
        + authority.to_bytes(4, "big")
        + bls_public_key
    )


@dataclass(frozen=True)
class EnrollmentAnnouncement:
    """A self-authenticating claim to one corridor seat.

    Safe to relay over an untrusted transport: every field is covered by
    `binding`, and `binding` is only producible by the holder of the secret
    key for `super_node.bls_public_key`. A relay can drop it or delay it but
    cannot alter it into a claim on a different seat.
    """

    super_node: SuperNode
    epoch: int
    binding: bytes

    def message(self) -> bytes:
        """The bytes `binding` is expected to sign."""
        return build_enrollment_message(
            self.super_node.corridor,
            self.epoch,
            self.super_node.authority,
            self.super_node.bls_public_key,
        )


def announce(
    sk: bytes,
    bls_public_key: bytes,
    corridor_id: CorridorId,
    authority: AuthorityId,
    epoch: int = 0,
) -> EnrollmentAnnouncement:
    """Produce a complete, self-authenticating announcement for one seat.

    Both signatures come from `sk`, so an operator runs this once, offline,
    and publishes the result wherever the corridor collects enrollments.
    """
    pop = corridor_sign(sk, build_pop_message(bls_public_key))
    binding = corridor_sign(
        sk, build_enrollment_message(corridor_id, epoch, authority, bls_public_key)
    )
    return EnrollmentAnnouncement(
        super_node=SuperNode(
            authority=authority,
            corridor=corridor_id,
            bls_public_key=bls_public_key,
            pop=pop,
        ),
        epoch=epoch,
        binding=binding,
    )


def verify_announcement(ann: EnrollmentAnnouncement) -> None:
    """Check both signatures. Raises on failure; returns `None` on success.

    Verifies structure first, then the binding, then the PoP. Binding before
    PoP is deliberate: a replay carries a valid PoP, so checking the binding
    first means the *first* error a replay produces is the one that names the
    actual problem.
    """
    node = ann.super_node

    if not 0 <= ann.epoch <= ID_MAX:
        raise MalformedAnnouncement(f"epoch must fit in u32 (0..{ID_MAX}), got {ann.epoch}")
    if not 0 <= node.authority <= ID_MAX:
        raise MalformedAnnouncement(
            f"authority must fit in u32 (0..{ID_MAX}), got {node.authority}"
        )
    if not 0 <= node.corridor <= ID_MAX:
        raise MalformedAnnouncement(f"corridor must fit in u32 (0..{ID_MAX}), got {node.corridor}")
    if len(node.bls_public_key) != BLS_PUBKEY_BYTES:
        raise MalformedAnnouncement(
            f"BLS public key is {len(node.bls_public_key)} bytes, expected {BLS_PUBKEY_BYTES}"
        )
    if len(ann.binding) != BLS_POP_BYTES:
        raise MalformedAnnouncement(
            f"binding signature is {len(ann.binding)} bytes, expected {BLS_POP_BYTES}"
        )
    if len(node.pop) != BLS_POP_BYTES:
        raise MalformedAnnouncement(f"PoP is {len(node.pop)} bytes, expected {BLS_POP_BYTES}")

    if not corridor_verify(node.bls_public_key, ann.message(), ann.binding):
        raise BindingVerificationFailed(node.authority)

    pop_msg = DOMAIN_TAG_CORRIDOR_POP + node.bls_public_key
    if not corridor_verify(node.bls_public_key, pop_msg, node.pop):
        from .attestation import CorridorPopVerificationFailed

        raise CorridorPopVerificationFailed(node.authority)
