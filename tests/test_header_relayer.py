"""
Unit tests for the GSX-DAG HeaderRelayer aggregator (pure, no anvil).

These assert the relayer's *liveness-trusted, cannot-forge* aggregation
behavior at the byte level:

  - quorum-consistent aggregation (all signers over one header survive)
  - strict keccak256(pubkey) sort + duplicate drop (the contract's dedup)
  - conflicting-header handling: two distinct state_roots are NEVER merged;
    the majority root wins
  - empty / null attestations -> None
  - a malformed attestation view is skipped, not fatal

None of these require web3, anvil, or any network. They exercise the
relayer's *selection* logic only — actual quorum SAFETY is re-enforced
on-chain (covered by the integration test).
"""

from __future__ import annotations

from eth_hash.auto import keccak

from src.ltp.bridge.header_relayer import (
    AggregatedHeader,
    HeaderAttestation,
    HeaderRelayer,
)

# A fixed network_id + oracle so the group key is stable across an attestation set.
NETWORK_ID = (7777).to_bytes(32, "big")
ORACLE = "0x00000000000000000000000000000000000000aa"

# Two distinct mock state roots (for conflict tests).
ROOT_A = bytes([0xAA]) * 32
ROOT_B = bytes([0xBB]) * 32


def _pubkey(i: int) -> bytes:
    """Deterministic 32-byte mock pubkey for validator i (mirrors the contract test)."""
    return keccak(b"validator" + i.to_bytes(32, "big"))


def _att(
    i: int,
    *,
    state_root: bytes = ROOT_A,
    block_number: int = 100,
    sig: bytes | None = None,
    pubkey: bytes | None = None,
) -> HeaderAttestation:
    pk = pubkey if pubkey is not None else _pubkey(i)
    return HeaderAttestation(
        block_number=block_number,
        state_root=state_root,
        authority_id=i,
        pubkey=pk,
        signature=sig if sig is not None else keccak(b"sig" + pk),
        network_id=NETWORK_ID,
        oracle=ORACLE,
    )


def _expected_sorted_pubkeys(indices: list[int]) -> list[bytes]:
    """Independently compute the strict-keccak(pubkey) order the relayer must produce."""
    pks = [_pubkey(i) for i in indices]
    return sorted(pks, key=keccak)


# --------------------------------------------------------------------------- 1
def test_aggregate_quorum_consistent_keeps_all_signers_over_one_header():
    relayer = HeaderRelayer()
    atts = [_att(i) for i in range(4)]  # 4 distinct validators, same header

    agg = relayer.aggregate(atts)

    assert agg is not None
    assert agg.block_number == 100
    assert agg.state_root == ROOT_A
    assert agg.signer_count == 4
    # All four pubkeys present, index-aligned with their sigs.
    assert set(agg.pubkeys) == {_pubkey(i) for i in range(4)}
    assert len(agg.sigs) == len(agg.pubkeys)
    for pk, sig in zip(agg.pubkeys, agg.sigs):
        assert sig == keccak(b"sig" + pk)


# --------------------------------------------------------------------------- 2
def test_aggregate_sorts_strictly_increasing_by_keccak_pubkey():
    relayer = HeaderRelayer()
    # Feed in a deliberately UN-sorted order; relayer must re-order.
    atts = [_att(3), _att(0), _att(2), _att(1)]

    agg = relayer.aggregate(atts)
    assert agg is not None

    expected = _expected_sorted_pubkeys([0, 1, 2, 3])
    # NON-VACUOUS: assert the exact produced order, not just monotonicity.
    assert agg.pubkeys == expected
    # And it is strictly increasing under keccak (the contract's hard contract).
    hashes = [keccak(pk) for pk in agg.pubkeys]
    assert hashes == sorted(hashes)
    assert len(set(hashes)) == len(hashes)
    # sigs stay aligned to their (now reordered) pubkeys.
    for pk, sig in zip(agg.pubkeys, agg.sigs):
        assert sig == keccak(b"sig" + pk)


# --------------------------------------------------------------------------- 3
def test_aggregate_drops_duplicate_pubkeys():
    relayer = HeaderRelayer()
    dup_pk = _pubkey(1)
    atts = [
        _att(0),
        _att(1),  # pubkey == dup_pk
        _att(1, pubkey=dup_pk, sig=keccak(b"sig" + dup_pk)),  # exact duplicate signer
        _att(2),
    ]

    agg = relayer.aggregate(atts)
    assert agg is not None

    # Duplicate collapsed: 3 unique signers, sorted by keccak(pubkey).
    assert agg.pubkeys == _expected_sorted_pubkeys([0, 1, 2])
    assert agg.signer_count == 3
    assert len(set(agg.pubkeys)) == 3


# --------------------------------------------------------------------------- 4
def test_aggregate_conflicting_headers_picks_majority_never_merges():
    relayer = HeaderRelayer()
    # 3 validators attest ROOT_A, 2 attest ROOT_B -> ROOT_A is the majority.
    atts = [
        _att(0, state_root=ROOT_A),
        _att(1, state_root=ROOT_A),
        _att(2, state_root=ROOT_A),
        _att(3, state_root=ROOT_B),
        _att(4, state_root=ROOT_B),
    ]

    agg = relayer.aggregate(atts)
    assert agg is not None

    # Majority root chosen, and ONLY its 3 signers — never unioned across roots.
    assert agg.state_root == ROOT_A
    assert agg.signer_count == 3
    assert agg.pubkeys == _expected_sorted_pubkeys([0, 1, 2])
    # Explicitly: the ROOT_B signers are absent (no cross-root merge).
    assert _pubkey(3) not in agg.pubkeys
    assert _pubkey(4) not in agg.pubkeys


def test_aggregate_below_set_is_exactly_what_relayer_produces():
    """A minority/below-quorum input yields a below-quorum aggregate verbatim.

    The relayer is stake-blind: if only one validator attests, it produces a
    single-signer aggregate (which the ORACLE would reject as BelowQuorum). We
    assert the relayer faithfully produces that sub-quorum set, not a forged one.
    """
    relayer = HeaderRelayer()
    agg = relayer.aggregate([_att(2)])
    assert agg is not None
    assert agg.pubkeys == [_pubkey(2)]
    assert agg.sigs == [keccak(b"sig" + _pubkey(2))]
    assert isinstance(agg, AggregatedHeader)


# --------------------------------------------------------------------------- 5
def test_aggregate_empty_returns_none():
    relayer = HeaderRelayer()
    assert relayer.aggregate([]) is None


# --------------------------------------------------------------------------- 6
def test_poll_skips_null_and_malformed_via_parser():
    """from_view parses a good view and rejects a malformed one (poll skips it)."""
    good_view = {
        "block_number": 100,
        "state_root": "0x" + "aa" * 32,
        "authority_id": 7,
        "pubkey": "0x" + _pubkey(0).hex(),
        "signature": "0x" + (keccak(b"sig" + _pubkey(0))).hex(),
        "network_id": "0x" + (7777).to_bytes(32, "big").hex(),
        "oracle": ORACLE,
    }
    att = HeaderAttestation.from_view(good_view)
    assert att.block_number == 100
    assert att.state_root == ROOT_A
    assert att.pubkey == _pubkey(0)
    assert att.network_id == (7777).to_bytes(32, "big")
    assert att.oracle == ORACLE

    # Missing a required field -> KeyError, which poll() catches and skips.
    malformed = dict(good_view)
    del malformed["signature"]
    raised = False
    try:
        HeaderAttestation.from_view(malformed)
    except (KeyError, ValueError, TypeError):
        raised = True
    assert raised, "malformed view must raise so poll() can skip it"


def test_poll_monkeypatched_skips_null_unreachable_and_malformed(monkeypatch):
    """End-to-end poll() over a mix of null / unreachable / malformed / good RPCs."""
    import src.ltp.bridge.header_relayer as hr

    good_pk = _pubkey(0)
    good_view = {
        "block_number": 100,
        "state_root": "0x" + "aa" * 32,
        "authority_id": 0,
        "pubkey": "0x" + good_pk.hex(),
        "signature": "0x" + keccak(b"sig" + good_pk).hex(),
        "network_id": "0x" + (7777).to_bytes(32, "big").hex(),
        "oracle": ORACLE,
    }

    class _Resp:
        def __init__(self, payload, raise_http=False):
            self._payload = payload
            self._raise_http = raise_http

        def raise_for_status(self):
            if self._raise_http:
                raise RuntimeError("HTTP 500")

        def json(self):
            return self._payload

    responses = {
        "http://good": _Resp({"jsonrpc": "2.0", "id": 1, "result": good_view}),
        "http://null": _Resp({"jsonrpc": "2.0", "id": 1, "result": None}),
        "http://malformed": _Resp(
            {"jsonrpc": "2.0", "id": 1, "result": {"block_number": 1}}  # missing fields
        ),
        "http://http500": _Resp({}, raise_http=True),
    }

    class _FakeRequests:
        @staticmethod
        def post(url, **kwargs):
            if url == "http://unreachable":
                raise ConnectionError("refused")
            return responses[url]

    monkeypatch.setitem(__import__("sys").modules, "requests", _FakeRequests)

    relayer = hr.HeaderRelayer()
    out = relayer.poll(
        [
            "http://good",
            "http://null",
            "http://malformed",
            "http://http500",
            "http://unreachable",
        ]
    )

    # Only the single good attestation survives; everything else is safely skipped.
    assert len(out) == 1
    assert out[0].pubkey == good_pk
    assert out[0].block_number == 100
