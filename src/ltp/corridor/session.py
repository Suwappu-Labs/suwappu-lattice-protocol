"""Signing sessions — collecting nine operators' partial signatures into one attestation.

`attest()` takes an iterable of `WitnessSignature` and returns a
`CorridorAttestation`. That signature says everything about the cryptography
and nothing about the situation it is used in: the partials do not arrive all
at once, they arrive one at a time, from peers, over a network, out of order,
sometimes twice, sometimes from someone who is not a member, sometimes for a
payload that is not the one this node is signing. Handing them straight to
`attest()` means the whole batch fails on the first bad one with no way to
tell which peer sent it.

`SigningSession` is that missing middle. It is pinned to exactly one payload
digest, accepts partials one at a time, and answers three questions the
network layer actually asks: *is this one good*, *do we have seven yet*, and
*what do I do with a duplicate*. It holds no sockets and does no I/O — a
gossip loop, an HTTP handler, or a test can drive it identically.

Two safety properties live here that are not in `attest()`:

**A node must not sign two conflicting payloads.** Paper §6.4 makes fast-path
equivocation a 100%-slashing offence, and the cheapest way to lose a bond is a
crash-restart that loses track of what was already signed. `CorridorSigner`
keeps a per-round record and refuses the second signature rather than
producing the evidence that would slash its own operator. This is a local
guard, not a protocol rule: it protects an honest node from an accident, and
does nothing against a node that wants to equivocate.

**Equivocation by someone else must be provable.** `EquivocationMonitor`
watches partials as they arrive and, when one witness signs two different
state roots for the same (source chain, target chain, height), emits
`EquivocationEvidence` — a self-contained object that anyone can re-verify
against the roster without trusting the reporter. Detection is a side effect
of ordinary signature collection, so a node that never looks for equivocation
still finds it.

BLS signing is deterministic, so a witness cannot produce two different valid
signatures over the same digest; equivocation is always two *different*
payloads, never two signatures over one payload. That is why the monitor is
keyed on `(round, witness)` and compares digests rather than signature bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .attestation import (
    AttestationPayload,
    AuthorityId,
    Corridor,
    CorridorAttestation,
    InvalidSignature,
    LtpError,
    UnknownWitness,
    WitnessSignature,
    attest,
)
from .bls import SK_SIZE as BLS_SECRET_KEY_BYTES
from .bls import corridor_sign, corridor_verify
from .constants import (
    LTP_ATTESTATION_QUORUM_SIZE,
    LTP_ATTESTATION_QUORUM_THRESHOLD,
)


class SessionError(LtpError):
    """Base class for signing-session failures."""


class WrongPayload(SessionError):
    """A partial signature that is for a different payload than this session.

    Almost always a peer that is a round behind or ahead, not an attack — but
    silently accepting it would let a stale signature count toward a quorum on
    a payload its signer never saw.
    """

    def __init__(self, witness: AuthorityId) -> None:
        super().__init__(
            f"witness {witness} signed a different payload than this session's; "
            "the session is pinned to one digest"
        )
        self.witness = witness


class QuorumNotReached(SessionError):
    def __init__(self, have: int, need: int) -> None:
        super().__init__(f"session has {have} of {need} required signatures")
        self.have = have
        self.need = need


class DoubleSignAttempt(SessionError):
    """A signer was asked to sign a payload conflicting with one it already signed.

    Refused locally. Paper §6.4 makes equivocation a 100%-slashing offence, so
    the signer declines to produce the second signature at all rather than
    emit the evidence that would slash its own operator.
    """

    def __init__(self, authority: AuthorityId, round_key: "SessionKey") -> None:
        super().__init__(
            f"signer {authority} already signed a different payload for round "
            f"{round_key}; refusing to equivocate"
        )
        self.authority = authority
        self.round_key = round_key


@dataclass(frozen=True, order=True)
class SessionKey:
    """The round a payload belongs to: one state root per chain pair per height.

    Two payloads sharing a `SessionKey` but differing in `state_root` or
    `timestamp_round` are *conflicting* — they claim two different histories
    for the same point on the same chain pair. That is exactly what
    equivocation means here.

    The corridor id is deliberately not part of the key. It would be
    redundant: a node runs one session and one monitor per corridor, and
    `EquivocationEvidence.verify` takes the corridor explicitly. Anything
    multiplexing several corridors through one monitor must key on the
    corridor itself rather than relying on this type.
    """

    source_chain: int
    target_chain: int
    source_height: int

    @classmethod
    def of(cls, payload: AttestationPayload) -> "SessionKey":
        return cls(
            source_chain=payload.source_chain,
            target_chain=payload.target_chain,
            source_height=payload.source_height,
        )

    def __str__(self) -> str:
        return f"{self.source_chain}->{self.target_chain}@{self.source_height}"


class SigningSession:
    """Collects partial signatures for one payload until the 7-of-9 threshold.

    Usage::

        session = SigningSession(corridor, payload)
        for ws in incoming:           # from gossip, HTTP, a queue, a test
            session.submit(ws)        # returns False for a duplicate
            if session.has_quorum:
                break
        attestation = session.finalize()

    `submit` never partially mutates: a rejected partial leaves the session
    exactly as it was, so one hostile peer cannot corrupt a round in progress.
    """

    def __init__(
        self,
        corridor: Corridor,
        payload: AttestationPayload,
        threshold: int = LTP_ATTESTATION_QUORUM_THRESHOLD,
    ) -> None:
        if len(corridor.members) != LTP_ATTESTATION_QUORUM_SIZE:
            from .attestation import BadCorridorSize

            raise BadCorridorSize(LTP_ATTESTATION_QUORUM_SIZE, len(corridor.members))
        if not 1 <= threshold <= len(corridor.members):
            raise ValueError(
                f"threshold must be between 1 and {len(corridor.members)}, got {threshold}"
            )
        self.corridor = corridor
        self.payload = payload
        self.threshold = threshold
        self.digest = payload.canonical_digest()
        self.key = SessionKey.of(payload)
        self._signatures: dict[AuthorityId, bytes] = {}

    # -- collection ---------------------------------------------------------

    def submit(self, ws: WitnessSignature) -> bool:
        """Verify and record one partial. Returns `True` if it was new.

        A duplicate from a witness already recorded returns `False` rather
        than raising — peers legitimately resend, and a resend is not an
        error. Anything else raises: `UnknownWitness` for a non-member,
        `InvalidSignature` for a signature that does not verify.

        The duplicate check runs *before* signature verification, which means
        a partial claiming an already-recorded witness is dropped without a
        pairing check. That is deliberate: verifying it would let anyone burn
        a node's CPU by replaying the same witness id, and the stored
        signature is already verified, so there is nothing the second one
        could correct. The cost is that this returns `False` rather than
        `InvalidSignature` for a forgery aimed at a seat that has already
        signed — no worse an outcome, but not an attack signal either.
        """
        pk = self.corridor.member_pubkey(ws.witness)
        if pk is None:
            raise UnknownWitness(ws.witness)
        if ws.witness in self._signatures:
            return False
        if not corridor_verify(pk, self.digest, ws.signature):
            raise InvalidSignature(ws.witness)
        self._signatures[ws.witness] = ws.signature
        return True

    def submit_for_payload(self, payload: AttestationPayload, ws: WitnessSignature) -> bool:
        """Submit a partial that arrived with its own copy of the payload.

        Real transports carry the payload alongside the signature so a
        receiver can tell a stale round from a forgery. This checks the two
        agree before doing any signature work, and raises `WrongPayload` when
        they do not — which a caller can route to `EquivocationMonitor`
        instead of dropping.
        """
        if payload.canonical_digest() != self.digest:
            raise WrongPayload(ws.witness)
        return self.submit(ws)

    # -- inspection ---------------------------------------------------------

    @property
    def signers(self) -> frozenset[AuthorityId]:
        return frozenset(self._signatures)

    @property
    def have(self) -> int:
        return len(self._signatures)

    @property
    def has_quorum(self) -> bool:
        return len(self._signatures) >= self.threshold

    def missing(self) -> int:
        return max(0, self.threshold - len(self._signatures))

    def outstanding(self) -> tuple[AuthorityId, ...]:
        """Members who have not signed yet, in canonical order — who to chase."""
        return tuple(
            m.authority for m in self.corridor.members if m.authority not in self._signatures
        )

    def partials(self) -> tuple[WitnessSignature, ...]:
        """Collected partials in canonical signer order."""
        return tuple(
            WitnessSignature(witness=a, signature=self._signatures[a])
            for a in sorted(self._signatures)
        )

    # -- completion ---------------------------------------------------------

    def finalize(self) -> CorridorAttestation:
        """Aggregate into a `CorridorAttestation`, or say how many are missing."""
        if not self.has_quorum:
            raise QuorumNotReached(len(self._signatures), self.threshold)
        return attest(self.corridor, self.payload, self.partials())


class CorridorSigner:
    """One operator's signing half, with a local guard against equivocating.

    The guard is per-round state. Held only in memory it is lost on restart,
    which is precisely the failure mode that slashes operators in practice — a
    node comes back up, has forgotten what it signed, and signs a conflicting
    payload for the same height. `signed_rounds()` and `restore()` exist so a
    deployment can persist that record alongside its keys and hand it back at
    startup. This class makes the guard a place that exists rather than a
    paragraph in a runbook; it does not make it durable on its own.
    """

    def __init__(self, authority: AuthorityId, secret_key: bytes) -> None:
        if len(secret_key) != BLS_SECRET_KEY_BYTES:
            raise ValueError(
                f"secret key must be {BLS_SECRET_KEY_BYTES} bytes, got {len(secret_key)}"
            )
        if not 0 <= authority <= 0xFFFFFFFF:
            raise ValueError(f"authority must fit in u32, got {authority}")
        self.authority = authority
        self._sk = secret_key
        self._signed: dict[SessionKey, bytes] = {}

    def sign(self, payload: AttestationPayload) -> WitnessSignature:
        """Sign `payload`, refusing to conflict with anything already signed.

        Re-signing the *same* payload is allowed and returns the same
        signature — BLS is deterministic, so a retry after a dropped network
        response is safe and must not be mistaken for equivocation.
        """
        key = SessionKey.of(payload)
        digest = payload.canonical_digest()
        previous = self._signed.get(key)
        if previous is not None and previous != digest:
            raise DoubleSignAttempt(self.authority, key)
        self._signed[key] = digest
        return WitnessSignature(witness=self.authority, signature=corridor_sign(self._sk, digest))

    def has_signed(self, key: SessionKey) -> bool:
        return key in self._signed

    def signed_rounds(self) -> dict[SessionKey, bytes]:
        """A copy of the round record: which round, and the digest signed for it.

        Persist this to survive a restart with the double-sign guard intact.
        """
        return dict(self._signed)

    def restore(self, records: dict[SessionKey, bytes]) -> None:
        """Reinstate a persisted round record, e.g. after a process restart.

        Merges into whatever is already held and refuses to overwrite a round
        with a conflicting digest — if the stored record and the live one
        disagree, this signer has already equivocated and silently picking one
        would hide it.
        """
        for key, digest in records.items():
            if len(digest) != 32:
                raise ValueError(f"round digest for {key} must be 32 bytes, got {len(digest)}")
            existing = self._signed.get(key)
            if existing is not None and existing != digest:
                raise DoubleSignAttempt(self.authority, key)
            self._signed[key] = digest


class NotEquivocation(SessionError):
    """The submitted evidence does not show equivocation.

    Raised rather than returning False so that a caller cannot accidentally
    treat an unchecked accusation as a proven one.
    """


@dataclass(frozen=True)
class EquivocationEvidence:
    """Proof that one witness signed two conflicting payloads for one round.

    Self-contained: `verify` re-checks both signatures against the roster and
    re-checks that the payloads genuinely conflict, so a recipient never has
    to trust whoever reported it.
    """

    witness: AuthorityId
    payload_a: AttestationPayload
    signature_a: bytes
    payload_b: AttestationPayload
    signature_b: bytes

    @property
    def key(self) -> SessionKey:
        return SessionKey.of(self.payload_a)

    def verify(self, corridor: Corridor) -> None:
        """Raise unless this really is evidence of equivocation.

        Checks, in order: the witness is a corridor member; the two payloads
        are for the same round; they are genuinely different; and both
        signatures verify under the witness's key.
        """
        pk = corridor.member_pubkey(self.witness)
        if pk is None:
            raise UnknownWitness(self.witness)

        key_a = SessionKey.of(self.payload_a)
        key_b = SessionKey.of(self.payload_b)
        if key_a != key_b:
            raise NotEquivocation(
                f"payloads are for different rounds ({key_a} and {key_b}); signing both "
                "is normal behaviour, not equivocation"
            )

        digest_a = self.payload_a.canonical_digest()
        digest_b = self.payload_b.canonical_digest()
        if digest_a == digest_b:
            raise NotEquivocation(
                "both payloads are identical; a witness re-signing the same payload is a "
                "retry, not equivocation"
            )

        if not corridor_verify(pk, digest_a, self.signature_a):
            raise InvalidSignature(self.witness)
        if not corridor_verify(pk, digest_b, self.signature_b):
            raise InvalidSignature(self.witness)


@dataclass
class EquivocationMonitor:
    """Spots a witness signing two different state roots for the same round.

    Feed it every `(payload, partial)` a node sees — including ones rejected
    by a session as `WrongPayload`, which is precisely where equivocation
    shows up. It keeps one record per `(round, witness)` and returns
    `EquivocationEvidence` the moment a second, conflicting one arrives.

    Memory grows with the number of rounds observed; `forget_through` drops
    rounds a node no longer cares about (anything at or below a finalized
    height).
    """

    _seen: dict[tuple[SessionKey, AuthorityId], tuple[AttestationPayload, bytes]] = field(
        default_factory=dict, repr=False
    )

    def observe(
        self, payload: AttestationPayload, ws: WitnessSignature
    ) -> EquivocationEvidence | None:
        """Record one partial. Returns evidence if it conflicts with a prior one.

        The caller is expected to have verified the signature (a session's
        `submit` does). An unverified signature recorded here would produce
        evidence that fails `verify`, which is safe but wasteful.
        """
        key = (SessionKey.of(payload), ws.witness)
        previous = self._seen.get(key)
        if previous is None:
            self._seen[key] = (payload, ws.signature)
            return None

        prev_payload, prev_signature = previous
        if prev_payload.canonical_digest() == payload.canonical_digest():
            return None

        return EquivocationEvidence(
            witness=ws.witness,
            payload_a=prev_payload,
            signature_a=prev_signature,
            payload_b=payload,
            signature_b=ws.signature,
        )

    def forget_through(self, source_height: int) -> int:
        """Drop records for rounds at or below `source_height`. Returns the count."""
        stale = [k for k in self._seen if k[0].source_height <= source_height]
        for k in stale:
            del self._seen[k]
        return len(stale)

    @property
    def tracked_rounds(self) -> int:
        return len({k[0] for k in self._seen})
