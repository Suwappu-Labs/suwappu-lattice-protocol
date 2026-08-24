"""Corridor roster assembly — `src/ltp/corridor/membership.py`.

The properties under test are the ones that no signature check would ever
surface: a rogue key admitted at the door, one operator holding two of nine
seats, or two honest operators building rosters that disagree only because
they enrolled peers in a different order.
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.attestation import (
    Corridor,
    CorridorPopVerificationFailed,
    SuperNode,
)
from src.ltp.corridor.bls import corridor_sign, keygen
from src.ltp.corridor.constants import (
    DOMAIN_TAG_CORRIDOR_POP,
    DOMAIN_TAG_CORRIDOR_ROSTER,
    LTP_ATTESTATION_QUORUM_SIZE,
)
from src.ltp.corridor.membership import (
    BLS_POP_BYTES,
    BLS_PUBKEY_BYTES,
    CorridorMembershipError,
    CorridorRegistry,
    DuplicateAuthority,
    DuplicateBlsKey,
    MalformedSuperNode,
    RosterFull,
    RosterNotReady,
    WrongCorridor,
    build_pop_message,
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


def _node(authority: int, corridor: int = CORRIDOR) -> SuperNode:
    """A super-node with a real keypair and a valid PoP over its own key."""
    pk, sk = keygen()
    pop = corridor_sign(sk, build_pop_message(pk))
    return SuperNode(authority=authority, corridor=corridor, bls_public_key=pk, pop=pop)


def _full_roster(corridor: int = CORRIDOR) -> list[SuperNode]:
    return [_node(i, corridor) for i in range(LTP_ATTESTATION_QUORUM_SIZE)]


# -- the happy path ---------------------------------------------------------


def test_nine_enrollments_finalize_into_a_corridor():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    for node in _full_roster():
        reg.enroll(node)

    assert reg.is_ready
    assert reg.size == LTP_ATTESTATION_QUORUM_SIZE
    assert reg.missing() == 0

    corridor = reg.finalize()
    assert isinstance(corridor, Corridor)
    assert corridor.id == CORRIDOR
    assert len(corridor.members) == LTP_ATTESTATION_QUORUM_SIZE
    # finalize() re-runs the package's own PoP gate; reaching here means it passed.
    corridor.verify_pops()


def test_registry_reports_how_many_members_are_missing():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    roster = _full_roster()
    for i, node in enumerate(roster[:4]):
        reg.enroll(node)
        assert reg.size == i + 1
        assert reg.missing() == LTP_ATTESTATION_QUORUM_SIZE - (i + 1)
        assert not reg.is_ready


# -- PoP at the door --------------------------------------------------------


def test_pop_signed_by_a_different_key_is_rejected():
    """The classic rogue-key setup: advertise a key you do not hold."""
    victim_pk, _ = keygen()
    attacker_pk, attacker_sk = keygen()
    # PoP is a valid signature — but over the attacker's key, presented
    # alongside the victim's public key.
    pop = corridor_sign(attacker_sk, build_pop_message(attacker_pk))
    rogue = SuperNode(authority=1, corridor=CORRIDOR, bls_public_key=victim_pk, pop=pop)

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(CorridorPopVerificationFailed):
        reg.enroll(rogue)
    assert reg.size == 0


def test_pop_over_the_bare_key_without_the_domain_tag_is_rejected():
    """A signature made for any other purpose cannot be replayed into a seat."""
    pk, sk = keygen()
    untagged = corridor_sign(sk, pk)  # missing DOMAIN_TAG_CORRIDOR_POP prefix
    node = SuperNode(authority=1, corridor=CORRIDOR, bls_public_key=pk, pop=untagged)

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(CorridorPopVerificationFailed):
        reg.enroll(node)


def test_empty_pop_is_rejected_as_malformed():
    """`SuperNode.pop` defaults to b"" for legacy fixtures; the registry is
    the surface where that default stops being acceptable."""
    pk, _ = keygen()
    node = SuperNode(authority=1, corridor=CORRIDOR, bls_public_key=pk)

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(MalformedSuperNode) as exc:
        reg.enroll(node)
    assert "never acceptable" in str(exc.value)


def test_build_pop_message_matches_what_verify_pops_checks():
    """The helper and `Corridor.verify_pops` must agree byte-for-byte, or a
    correctly generated PoP would fail for a reason nobody could see."""
    pk, _ = keygen()
    assert build_pop_message(pk) == DOMAIN_TAG_CORRIDOR_POP + pk

    with pytest.raises(ValueError):
        build_pop_message(b"\x00" * 47)


# -- independence of seats --------------------------------------------------


def test_duplicate_authority_id_is_rejected():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    reg.enroll(_node(3))
    with pytest.raises(DuplicateAuthority) as exc:
        reg.enroll(_node(3))
    assert exc.value.authority == 3
    assert reg.size == 1


def test_two_authorities_sharing_one_bls_key_are_rejected():
    """Nine seats held by eight keys is a 7-of-9 quorum that fewer than seven
    real parties can reach. Nothing in the signature path would notice."""
    first = _node(1)
    twin = SuperNode(
        authority=2,
        corridor=CORRIDOR,
        bls_public_key=first.bls_public_key,
        pop=first.pop,
    )

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    reg.enroll(first)
    with pytest.raises(DuplicateBlsKey) as exc:
        reg.enroll(twin)
    assert exc.value.authority == 2
    assert exc.value.existing == 1
    assert reg.size == 1


# -- structural validation --------------------------------------------------


def test_super_node_for_a_different_corridor_is_rejected():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(WrongCorridor) as exc:
        reg.enroll(_node(1, corridor=CORRIDOR + 1))
    assert exc.value.expected == CORRIDOR
    assert exc.value.got == CORRIDOR + 1


@pytest.mark.parametrize("length", [0, 47, 49, 96])
def test_wrong_length_bls_key_is_rejected(length):
    node = SuperNode(
        authority=1,
        corridor=CORRIDOR,
        bls_public_key=b"\x11" * length,
        pop=b"\x22" * BLS_POP_BYTES,
    )
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(MalformedSuperNode) as exc:
        reg.enroll(node)
    assert str(BLS_PUBKEY_BYTES) in str(exc.value)


@pytest.mark.parametrize("length", [48, 95, 97])
def test_wrong_length_pop_is_rejected(length):
    node = SuperNode(
        authority=1,
        corridor=CORRIDOR,
        bls_public_key=b"\x11" * BLS_PUBKEY_BYTES,
        pop=b"\x22" * length,
    )
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(MalformedSuperNode):
        reg.enroll(node)


@pytest.mark.parametrize("authority", [-1, 1 << 32])
def test_authority_id_outside_u32_is_rejected(authority):
    """Ids are serialized as u32 in the roster digest. Refusing them here beats
    an OverflowError from `roster_digest` after the roster looks complete."""
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    with pytest.raises(MalformedSuperNode):
        reg.enroll(_node(authority))


def test_registry_rejects_an_out_of_range_corridor_id():
    with pytest.raises(ValueError):
        CorridorRegistry(corridor_id=1 << 32)
    with pytest.raises(ValueError):
        CorridorRegistry(corridor_id=CORRIDOR, quorum_size=0)


def test_enrolling_past_the_quorum_size_is_rejected():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    for node in _full_roster():
        reg.enroll(node)
    with pytest.raises(RosterFull):
        reg.enroll(_node(LTP_ATTESTATION_QUORUM_SIZE))
    assert reg.size == LTP_ATTESTATION_QUORUM_SIZE


def test_every_rejection_leaves_the_registry_unchanged():
    """A malicious or buggy peer must not be able to half-insert a member."""
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    good = _node(1)
    reg.enroll(good)
    before = reg.roster_digest()

    bad_nodes = [
        _node(2, corridor=CORRIDOR + 1),  # wrong corridor
        SuperNode(authority=3, corridor=CORRIDOR, bls_public_key=b"\x00" * 10),
        _node(1),  # duplicate authority
        SuperNode(
            authority=4,
            corridor=CORRIDOR,
            bls_public_key=good.bls_public_key,
            pop=good.pop,
        ),  # duplicate key
    ]
    for node in bad_nodes:
        with pytest.raises(CorridorMembershipError):
            reg.enroll(node)

    assert reg.size == 1
    assert reg.roster_digest() == before


# -- determinism ------------------------------------------------------------


def test_finalize_before_the_roster_is_full_explains_the_shortfall():
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    for node in _full_roster()[:6]:
        reg.enroll(node)
    with pytest.raises(RosterNotReady) as exc:
        reg.finalize()
    assert exc.value.have == 6
    assert exc.value.need == LTP_ATTESTATION_QUORUM_SIZE


def test_members_are_ordered_by_authority_id_regardless_of_arrival():
    roster = _full_roster()
    shuffled = [roster[i] for i in (4, 0, 8, 2, 6, 1, 7, 3, 5)]

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    for node in shuffled:
        reg.enroll(node)

    ids = [m.authority for m in reg.ordered_members()]
    assert ids == sorted(ids)
    assert ids == list(range(LTP_ATTESTATION_QUORUM_SIZE))


def test_two_nodes_enrolling_in_different_orders_agree():
    """The property that makes the digest worth reading aloud on a call."""
    roster = _full_roster()
    order_a = list(roster)
    order_b = list(reversed(roster))

    reg_a = CorridorRegistry(corridor_id=CORRIDOR)
    reg_b = CorridorRegistry(corridor_id=CORRIDOR)
    for node in order_a:
        reg_a.enroll(node)
    for node in order_b:
        reg_b.enroll(node)

    assert reg_a.roster_digest() == reg_b.roster_digest()
    assert reg_a.finalize().members == reg_b.finalize().members


def test_digest_changes_when_the_member_set_changes():
    roster = _full_roster()
    reg = CorridorRegistry(corridor_id=CORRIDOR)
    seen = set()
    for node in roster:
        reg.enroll(node)
        digest = reg.roster_digest()
        assert len(digest) == 32
        assert digest not in seen, "digest must distinguish partial rosters"
        seen.add(digest)


def test_digest_is_bound_to_the_corridor_id():
    """The same nine operators on two corridors must not produce one digest."""
    roster = _full_roster(corridor=1)
    reg_1 = CorridorRegistry(corridor_id=1)
    for node in roster:
        reg_1.enroll(node)

    reg_2 = CorridorRegistry(corridor_id=2)
    for node in roster:
        reg_2.enroll(
            SuperNode(
                authority=node.authority,
                corridor=2,
                bls_public_key=node.bls_public_key,
                pop=node.pop,
            )
        )

    assert reg_1.roster_digest() != reg_2.roster_digest()


def test_digest_uses_its_own_domain_tag():
    """A roster digest must never be mistakable for an attestation digest."""
    from src.ltp.corridor.digest import sha3_256_domain

    reg = CorridorRegistry(corridor_id=CORRIDOR)
    node = _node(0)
    reg.enroll(node)

    payload = (
        CORRIDOR.to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + node.authority.to_bytes(4, "big")
        + node.bls_public_key
    )
    assert reg.roster_digest() == sha3_256_domain(DOMAIN_TAG_CORRIDOR_ROSTER, payload)
