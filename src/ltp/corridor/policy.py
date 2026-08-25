"""Who is *entitled* to a corridor seat.

`enrollment.py` answers "is this announcement genuine" — the binding signature
proves the holder of this key wants seat 3 of corridor 7 in epoch 0, and that
nobody else forged that claim on their behalf. It deliberately stops there.
Genuine is not the same as permitted: without a policy, the first nine keys to
show up own the corridor, and a 7-of-9 quorum means whatever those nine
happen to be.

Three ways to decide entitlement get discussed for a corridor. Only one of
them can be built today:

- **Stake.** Not implementable here. There is no escrowed bond anywhere in
  this repo to check a claim against — declared stake is an integer somebody
  asserts (the same gap `suwappu-dag`'s tracker records as A9), so a
  stake-gated policy would read a number the claimant chose.
- **Governance vote.** Not implementable here. There is no corridor
  governance surface — no proposal, no vote, no on-chain seat registry — so
  there is nothing to consult.
- **Allowlist.** Implementable, and what `SeatAllowlist` below does.

That is not a ranking, it is an availability check: an allowlist is the
strongest policy that can actually be enforced right now. The `EnrollmentPolicy`
protocol exists so the other two can land later as additional implementations
rather than as a rewrite of the registry.

`SeatAllowlist` binds a seat to a *specific key*, not merely to a set of
approved keys. Combined with the enrollment binding this gives a property
neither has alone: seat N can only ever be held by the key published for seat
N. An allowlisted operator cannot take a colleague's seat, and an operator
whose key was published for one corridor cannot carry it into another.

The one thing no policy here can do is establish that the allowlist itself is
right. That is an out-of-band human agreement, which is what
`SeatAllowlist.digest()` is for — nine operators compare one 32-byte value
before enrollment opens, and a misconfiguration surfaces as one mismatched
digest instead of an unexplained storm of rejected announcements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping, Protocol, runtime_checkable

from .attestation import AuthorityId, CorridorId
from .constants import DOMAIN_TAG_CORRIDOR_ALLOWLIST
from .digest import sha3_256_domain
from .membership import BLS_PUBKEY_BYTES, ID_MAX, CorridorMembershipError

if TYPE_CHECKING:  # pragma: no cover — type-only, avoids an import cycle
    from .enrollment import EnrollmentAnnouncement


class SeatNotAuthorized(CorridorMembershipError):
    """The announcement is genuine but this seat is not theirs to claim.

    Deliberately distinct from every signature failure: an operator hitting
    this has working keys and a correctly formed announcement, and the fix is
    a configuration change by whoever maintains the allowlist, not a
    regenerated key. Conflating the two sends people to debug the wrong thing.
    """

    def __init__(self, authority: AuthorityId, reason: str) -> None:
        super().__init__(f"seat {authority} is not authorized: {reason}")
        self.authority = authority
        self.reason = reason


@runtime_checkable
class EnrollmentPolicy(Protocol):
    """Decides whether a verified announcement may take the seat it claims.

    `authorize` is called with an announcement whose signatures have **not**
    been checked yet, because the check is a BLS pairing and a policy lookup
    is a dict access — rejecting an unauthorized seat first means a stranger
    cannot make a node do expensive work by spraying announcements. A policy
    must therefore treat the announcement's contents as unauthenticated
    claims: decide on `(corridor, epoch, authority, bls_public_key)` as
    asserted, and let the registry's signature checks establish that the
    claimant really holds the key.

    Raise `SeatNotAuthorized` to reject. Returning normally means permitted.
    """

    def authorize(self, announcement: "EnrollmentAnnouncement") -> None: ...


@dataclass(frozen=True)
class OpenEnrollment:
    """Permits any seat. First nine keys to arrive own the corridor.

    Named rather than defaulted so it cannot be selected by accident: a
    registry with no policy refuses to accept announcements at all, and
    reaching this class requires typing its name into the call. Appropriate
    for a local devnet or a test; never for a corridor whose attestations
    anyone relies on.
    """

    def authorize(self, announcement: "EnrollmentAnnouncement") -> None:
        return None


@dataclass(frozen=True)
class SeatAllowlist:
    """A published map of seat → the BLS key permitted to hold it.

    Usage::

        allowlist = SeatAllowlist(corridor_id=7, seats={0: pk_a, 1: pk_b, ...})
        print(allowlist.digest().hex())   # compare with the other operators
        registry = CorridorRegistry(corridor_id=7, policy=allowlist)

    The map is exhaustive: a seat that is not a key of `seats` is not
    claimable, so growing the corridor is an explicit edit rather than an
    omission.
    """

    corridor_id: CorridorId
    seats: Mapping[AuthorityId, bytes]

    def __post_init__(self) -> None:
        if not 0 <= self.corridor_id <= ID_MAX:
            raise ValueError(f"corridor id must fit in u32 (0..{ID_MAX}), got {self.corridor_id}")
        if not self.seats:
            raise ValueError(
                "a seat allowlist with no seats permits nothing and is almost "
                "certainly a configuration mistake; use OpenEnrollment if you "
                "really mean to allow anyone"
            )
        seen: dict[bytes, AuthorityId] = {}
        for authority, key in self.seats.items():
            if not isinstance(authority, int) or isinstance(authority, bool):
                raise ValueError(f"seat id must be an integer, got {authority!r}")
            if not 0 <= authority <= ID_MAX:
                raise ValueError(f"seat id must fit in u32 (0..{ID_MAX}), got {authority}")
            if not isinstance(key, (bytes, bytearray)):
                raise ValueError(
                    f"key for seat {authority} must be bytes, got {type(key).__name__}"
                )
            if len(key) != BLS_PUBKEY_BYTES:
                raise ValueError(
                    f"key for seat {authority} is {len(key)} bytes, expected {BLS_PUBKEY_BYTES}"
                )
            # One key across two seats would hand one operator two of nine
            # votes — the same independence failure `CorridorRegistry` rejects
            # at enrollment, but here it would be baked into the configuration
            # and look deliberate.
            previous = seen.get(bytes(key))
            if previous is not None:
                raise ValueError(
                    f"seats {previous} and {authority} share one BLS key; a corridor "
                    "seat must be an independent key or the quorum threshold is a fiction"
                )
            seen[bytes(key)] = authority

    def authorize(self, announcement: "EnrollmentAnnouncement") -> None:
        node = announcement.super_node

        if node.corridor != self.corridor_id:
            raise SeatNotAuthorized(
                node.authority,
                f"allowlist is for corridor {self.corridor_id}, announcement targets "
                f"corridor {node.corridor}",
            )

        expected = self.seats.get(node.authority)
        if expected is None:
            raise SeatNotAuthorized(
                node.authority,
                f"seat is not on the allowlist for corridor {self.corridor_id}",
            )
        if not _constant_time_eq(bytes(expected), node.bls_public_key):
            raise SeatNotAuthorized(
                node.authority,
                "the key claiming this seat is not the key published for it",
            )

    def digest(self) -> bytes:
        """Canonical digest of the permitted seat set, for out-of-band comparison.

        Domain-separated so it cannot be confused with a roster digest — the
        two answer different questions (who *may* enrol vs. who *did*) and
        mixing them up would make a correct roster look wrong.
        """
        blob = b"".join(
            authority.to_bytes(4, "big") + bytes(self.seats[authority])
            for authority in sorted(self.seats)
        )
        header = self.corridor_id.to_bytes(4, "big") + len(self.seats).to_bytes(2, "big")
        return sha3_256_domain(DOMAIN_TAG_CORRIDOR_ALLOWLIST, header + blob)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare public keys without leaking a match position through timing.

    These are public values, so this is belt-and-braces rather than a
    load-bearing defence — but a policy check sits on an unauthenticated path
    an attacker can drive at will, and there is no reason to hand out a
    timing oracle for free.
    """
    from hmac import compare_digest

    return compare_digest(a, b)
