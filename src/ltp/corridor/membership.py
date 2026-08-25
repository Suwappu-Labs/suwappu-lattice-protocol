"""Corridor membership assembly — turning nine separate operators into one roster.

The corridor cryptography in this package is complete: `Corridor.verify_pops`
checks proofs of possession, `corridor/bls.py` aggregates signatures, and
`verify_attestation` enforces the 7-of-9 threshold. What has been missing is the
step *before* any of that — how nine independently operated super-nodes arrive at
the same `Corridor` object in the first place. Until now that was a human
arrangement: somebody constructed the tuple in Python and every node trusted it.

This module is the data layer for that step. It is deliberately
transport-agnostic — no HTTP, no sockets, no daemon. Enrollments arrive as
`SuperNode` records from wherever the operator chooses to put them (a gossip
message, a REST endpoint, a checked-in file), and this module answers one
question: *is this a legitimate roster, and does everyone compute it identically?*

Three properties it enforces that nothing else did:

1. **PoP is verified on enrollment, not only on use.** `Corridor.verify_pops`
   exists but is opt-in at verification time. Checking at the door means a rogue
   key never enters the roster at all, which is the adaptive-attacker defense
   LTP-A-015 asks for.

2. **Distinct authorities AND distinct keys.** `Corridor`'s docstring promises
   "distinct ids" but nothing enforced it, and nothing anywhere checked for a
   repeated BLS public key. Two authority ids sharing one key means a single
   operator quietly holds two of nine seats, so a "7-of-9" quorum can be reached
   by fewer real parties than it appears. That is a threshold failure that no
   signature check would ever surface.

3. **Deterministic ordering.** `Corridor.members` is a tuple, so member order is
   part of its identity. Two nodes that enrolled the same nine operators in
   different orders would otherwise build different tuples, hash them
   differently, and conclude they disagree. Members are sorted by authority id
   before the roster is finalized, so assembly order cannot affect the result.

The roster digest lets operators confirm agreement out-of-band — read it aloud
on a call, post it, diff it in CI — before the corridor signs anything.

Two things this module does *not* settle on its own. A bare `SuperNode`
carries a PoP over the public key alone, which names no corridor, seat, or
epoch, so it can be replayed into a seat its owner never claimed —
`enrollment.py` adds the binding signature that closes that. And a genuine
announcement is still not a *permitted* one; `policy.py` decides entitlement.
`enroll_announcement` requires both, and is the entry point to prefer for
anything arriving over a transport.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .attestation import (
    AuthorityId,
    Corridor,
    CorridorId,
    CorridorPopVerificationFailed,
    LtpError,
    SuperNode,
)
from .bls import corridor_verify
from .constants import (
    DOMAIN_TAG_CORRIDOR_POP,
    DOMAIN_TAG_CORRIDOR_ROSTER,
    LTP_ATTESTATION_QUORUM_SIZE,
)
from .digest import sha3_256_domain

if TYPE_CHECKING:  # pragma: no cover — import cycle: both import this module
    from .enrollment import EnrollmentAnnouncement
    from .policy import EnrollmentPolicy

#: A BLS12-381 compressed G1 public key.
BLS_PUBKEY_BYTES = 48
#: A BLS12-381 signature (compressed G2), which is what a PoP is.
BLS_POP_BYTES = 96
#: Authority and corridor ids are serialized as u32 in the roster digest, so
#: the registry refuses ids that would not survive that encoding rather than
#: letting `roster_digest` raise `OverflowError` at the worst possible moment.
ID_MAX = 0xFFFFFFFF


class CorridorMembershipError(LtpError):
    """Base class for enrollment failures."""


class WrongCorridor(CorridorMembershipError):
    def __init__(self, expected: CorridorId, got: CorridorId) -> None:
        super().__init__(f"super-node targets corridor {got}, registry is {expected}")
        self.expected = expected
        self.got = got


class DuplicateAuthority(CorridorMembershipError):
    def __init__(self, authority: AuthorityId) -> None:
        super().__init__(f"authority {authority} is already enrolled")
        self.authority = authority


class DuplicateBlsKey(CorridorMembershipError):
    """Two authority ids presenting the same BLS key.

    Rejected because it collapses the quorum's independence assumption: the
    member count would say nine while the number of distinct key holders is
    eight or fewer.
    """

    def __init__(self, authority: AuthorityId, existing: AuthorityId) -> None:
        super().__init__(
            f"authority {authority} presents the same BLS key as already-enrolled "
            f"authority {existing}; a corridor seat must be an independent key"
        )
        self.authority = authority
        self.existing = existing


class MalformedSuperNode(CorridorMembershipError):
    def __init__(self, authority: AuthorityId, reason: str) -> None:
        super().__init__(f"super-node {authority} is malformed: {reason}")
        self.authority = authority
        self.reason = reason


class RosterNotReady(CorridorMembershipError):
    def __init__(self, have: int, need: int) -> None:
        super().__init__(f"roster has {have} of {need} members")
        self.have = have
        self.need = need


class NoEnrollmentPolicy(CorridorMembershipError):
    """`enroll_announcement` was called on a registry with no policy.

    Fail-closed on purpose: without one, every genuine announcement is also a
    permitted one and the corridor belongs to whoever arrives first.
    """

    def __init__(self) -> None:
        super().__init__(
            "enroll_announcement requires a policy deciding which keys may hold "
            "which seats — pass `policy=SeatAllowlist(...)`, or "
            "`policy=OpenEnrollment()` if you genuinely want to admit anyone "
            "(dev and test only). `enroll` is the path for a SuperNode you "
            "built locally and have already vetted."
        )


class RosterFull(CorridorMembershipError):
    def __init__(self, size: int) -> None:
        super().__init__(f"roster already holds its full {size} members")
        self.size = size


@dataclass
class CorridorRegistry:
    """Accumulates super-node enrollments into a verifiable corridor roster.

    Usage::

        reg = CorridorRegistry(corridor_id=7, epoch=0, policy=allowlist)
        for ann in incoming:
            reg.enroll_announcement(ann)   # raises on a bad or duplicate member
        corridor = reg.finalize()          # exactly-9, deterministic order
        digest = reg.roster_digest()       # compare with peers out-of-band

    Use `enroll_announcement` for anything that arrived over a transport and
    `enroll` only for a `SuperNode` you constructed locally — see
    `enrollment.py` for why a bare PoP is replayable into a seat its owner
    never claimed.

    `enroll` is all-or-nothing: a rejected enrollment leaves the registry
    unchanged, so a malicious or buggy peer cannot half-insert a member.
    """

    corridor_id: CorridorId
    epoch: int = 0
    policy: "EnrollmentPolicy | None" = None
    quorum_size: int = LTP_ATTESTATION_QUORUM_SIZE
    _members: dict[AuthorityId, SuperNode] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not 0 <= self.corridor_id <= ID_MAX:
            raise ValueError(f"corridor id must fit in u32 (0..{ID_MAX}), got {self.corridor_id}")
        if not 0 <= self.epoch <= ID_MAX:
            raise ValueError(f"epoch must fit in u32 (0..{ID_MAX}), got {self.epoch}")
        if self.quorum_size < 1:
            raise ValueError(f"quorum size must be positive, got {self.quorum_size}")

    # -- enrollment ---------------------------------------------------------

    def enroll(self, node: SuperNode) -> None:
        """Validate and admit one super-node.

        Raises a `CorridorMembershipError` subclass on any failure; the registry
        is never partially mutated.
        """
        if node.corridor != self.corridor_id:
            raise WrongCorridor(self.corridor_id, node.corridor)

        if not 0 <= node.authority <= ID_MAX:
            raise MalformedSuperNode(
                node.authority,
                f"authority id must fit in u32 (0..{ID_MAX}) to be serializable "
                "into the roster digest",
            )

        if len(node.bls_public_key) != BLS_PUBKEY_BYTES:
            raise MalformedSuperNode(
                node.authority,
                f"BLS public key is {len(node.bls_public_key)} bytes, expected {BLS_PUBKEY_BYTES}",
            )
        if len(node.pop) != BLS_POP_BYTES:
            raise MalformedSuperNode(
                node.authority,
                f"PoP is {len(node.pop)} bytes, expected {BLS_POP_BYTES}"
                + ("; an empty PoP is never acceptable here" if not node.pop else ""),
            )

        if node.authority in self._members:
            raise DuplicateAuthority(node.authority)

        for existing in self._members.values():
            if existing.bls_public_key == node.bls_public_key:
                raise DuplicateBlsKey(node.authority, existing.authority)

        if len(self._members) >= self.quorum_size:
            raise RosterFull(self.quorum_size)

        # PoP at the door. `build_pop_message` is the single definition of
        # those bytes and matches Corridor.verify_pops, so a signature made
        # for any other purpose cannot be replayed into a corridor seat.
        msg = build_pop_message(node.bls_public_key)
        if not corridor_verify(node.bls_public_key, msg, node.pop):
            raise CorridorPopVerificationFailed(node.authority)

        self._members[node.authority] = node

    def enroll_announcement(self, ann: "EnrollmentAnnouncement") -> None:
        """Admit a super-node from a signed enrollment announcement.

        Prefer this over `enroll` for anything that arrived over a transport.
        A bare `SuperNode` carries a PoP that proves key possession but does
        not name a corridor, seat, or epoch, so it can be replayed into a seat
        its owner never claimed; an announcement's binding signature covers
        all three. See `enrollment.py` for the replay it prevents.

        Requires a `policy`. A genuine announcement is not the same as a
        permitted one — with nobody deciding entitlement, the first nine keys
        to arrive own the corridor — so this path is fail-closed and
        `policy.OpenEnrollment` is the explicit way to say you meant it.
        `enroll` is unaffected: it is documented as the local path, where the
        caller built the `SuperNode` itself and has already decided.

        Order is policy → signatures. The policy check is a dict lookup and
        signature verification is a BLS pairing, so rejecting an unauthorized
        seat first denies a stranger a cheap way to make this node do
        expensive work.
        """
        from .enrollment import EpochMismatch, verify_announcement

        if self.policy is None:
            raise NoEnrollmentPolicy()

        if ann.epoch != self.epoch:
            raise EpochMismatch(self.epoch, ann.epoch)
        self.policy.authorize(ann)
        verify_announcement(ann)
        self.enroll(ann.super_node)

    # -- inspection ---------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._members)

    @property
    def is_ready(self) -> bool:
        return len(self._members) == self.quorum_size

    def missing(self) -> int:
        return max(0, self.quorum_size - len(self._members))

    def ordered_members(self) -> tuple[SuperNode, ...]:
        """Members in canonical order (ascending authority id).

        Ordering is what makes two independently assembled registries produce
        byte-identical rosters and therefore identical digests.
        """
        return tuple(self._members[a] for a in sorted(self._members))

    # -- finalization -------------------------------------------------------

    def finalize(self) -> Corridor:
        """Build the `Corridor`, or explain exactly how many members are missing."""
        if not self.is_ready:
            raise RosterNotReady(len(self._members), self.quorum_size)
        corridor = Corridor(id=self.corridor_id, members=self.ordered_members())
        # Belt and braces: every PoP was checked at enrollment, but re-running
        # the package's own gate means a future refactor of enroll() cannot
        # silently produce a corridor whose PoPs were never verified.
        corridor.verify_pops()
        return corridor

    def roster_digest(self) -> bytes:
        """Canonical digest of the current member set, bound to corridor and epoch.

        Domain-separated and length-prefixed via the corridor's cross-repo hash
        helper, so it is stable across implementations and cannot collide with
        an attestation digest. Defined over whatever is enrolled so far, which
        makes it useful for spotting divergence *before* the roster is complete.
        """
        blob = b"".join(
            m.authority.to_bytes(4, "big") + m.bls_public_key for m in self.ordered_members()
        )
        header = (
            self.corridor_id.to_bytes(4, "big")
            + self.epoch.to_bytes(4, "big")
            + len(self._members).to_bytes(2, "big")
        )
        return sha3_256_domain(DOMAIN_TAG_CORRIDOR_ROSTER, header + blob)


def build_pop_message(bls_public_key: bytes) -> bytes:
    """The exact bytes a super-node must sign to prove key possession.

    Exposed so an operator can produce a PoP without importing the constant and
    getting the concatenation order wrong — the single most likely way to
    generate a PoP that fails verification for a reason nobody can see.
    """
    if len(bls_public_key) != BLS_PUBKEY_BYTES:
        raise ValueError(
            f"BLS public key must be {BLS_PUBKEY_BYTES} bytes, got {len(bls_public_key)}"
        )
    return DOMAIN_TAG_CORRIDOR_POP + bls_public_key
