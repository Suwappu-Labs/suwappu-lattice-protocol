"""Bridge wire format — `src/ltp/bridge/wire.py`.

The relayer hop is the one link the trust model assumes is hostile, so these
tests are mostly about what happens when it misbehaves. The load-bearing pair
is `test_a_wire_round_tripped_packet_still_materializes` (the wire preserves
everything verification depends on) and the tamper tests below it (the wire
does not launder a modification into something that verifies).
"""

from __future__ import annotations

import json

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge import (
    BridgeMessage,
    BridgeWireError,
    L1Anchor,
    L2Materializer,
    Relayer,
    RelayPacket,
)
from src.ltp.bridge.wire import (
    MAX_ENVELOPE_PAYLOAD_BYTES,
    MAX_SEALED_KEY_BYTES,
    relay_packet_from_dict,
    relay_packet_from_json,
    relay_packet_to_dict,
    relay_packet_to_json,
    signed_envelope_from_dict,
    signed_envelope_to_dict,
)
from src.ltp.domain import DOMAIN_BRIDGE_MSG
from src.ltp.envelope import SignedEnvelope


@pytest.fixture(scope="module")
def l1_operator() -> KeyPair:
    return KeyPair.generate("wire-l1-operator")


@pytest.fixture(scope="module")
def l2_verifier() -> KeyPair:
    return KeyPair.generate("wire-l2-verifier")


@pytest.fixture(scope="module")
def relay_operator() -> KeyPair:
    return KeyPair.generate("wire-relay-operator")


@pytest.fixture
def protocol() -> LTPProtocol:
    net = CommitmentNetwork()
    for node_id, region in [
        ("wire-us-1", "US-East"),
        ("wire-us-2", "US-West"),
        ("wire-eu-1", "EU-West"),
        ("wire-eu-2", "EU-East"),
        ("wire-ap-1", "AP-East"),
        ("wire-ap-2", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return LTPProtocol(net)


def _message(nonce: int = 0) -> BridgeMessage:
    return BridgeMessage(
        msg_type="token_lock",
        source_chain="ethereum",
        dest_chain="optimism",
        sender="0xSender",
        recipient="0xRecipient",
        payload={"token": "USDC", "amount": 100, "decimals": 6},
        nonce=nonce,
    )


@pytest.fixture
def relayed(protocol: LTPProtocol, l1_operator: KeyPair, l2_verifier: KeyPair):
    """A real packet straight out of a real COMMIT + LATTICE, unsigned relay."""
    anchor = L1Anchor(protocol, l1_operator, chain_id="ethereum")
    commitment, cek = anchor.commit_message(_message())
    packet = Relayer(protocol).relay(commitment, cek, l2_verifier)
    return packet, protocol


@pytest.fixture
def signed_relayed(
    protocol: LTPProtocol,
    l1_operator: KeyPair,
    l2_verifier: KeyPair,
    relay_operator: KeyPair,
):
    """The same, but the relay operator signs the hop."""
    anchor = L1Anchor(protocol, l1_operator, chain_id="ethereum")
    commitment, cek = anchor.commit_message(_message())
    relayer = Relayer(protocol, relay_keypair=relay_operator)
    return relayer.relay(commitment, cek, l2_verifier), protocol


def _materializer(protocol: LTPProtocol, l2_verifier: KeyPair) -> L2Materializer:
    m = L2Materializer(protocol, l2_verifier, chain_id="optimism", required_confirmations=1)
    m.set_l1_block_height(10)
    return m


# -- the property that matters ----------------------------------------------


def test_a_wire_round_tripped_packet_still_materializes(relayed, l2_verifier):
    """Relayer and materializer in two different processes must behave exactly
    as they do in one. This is the whole reason the module exists."""
    packet, protocol = relayed

    on_the_wire = relay_packet_to_json(packet)
    received = relay_packet_from_json(on_the_wire)

    result = _materializer(protocol, l2_verifier).materialize(received)
    assert result is not None
    assert result.payload == {"token": "USDC", "amount": 100, "decimals": 6}
    assert result.sender == "0xSender"
    assert result.nonce == 0


def test_a_signed_hop_survives_the_wire(signed_relayed, l2_verifier, relay_operator):
    packet, protocol = signed_relayed
    assert packet.relay_envelope is not None

    received = relay_packet_from_json(relay_packet_to_json(packet))
    assert received.relay_envelope is not None
    assert received.relay_envelope.verify()
    assert received.relay_envelope.signer_vk == relay_operator.vk

    assert _materializer(protocol, l2_verifier).materialize(received) is not None


def test_every_field_survives_the_round_trip(signed_relayed):
    packet, _ = signed_relayed
    received = relay_packet_from_json(relay_packet_to_json(packet))

    assert received.sealed_key == packet.sealed_key
    assert received.source_chain == packet.source_chain
    assert received.dest_chain == packet.dest_chain
    assert received.nonce == packet.nonce
    assert received.source_block == packet.source_block
    assert received.entity_id == packet.entity_id
    assert signed_envelope_to_dict(received.relay_envelope) == signed_envelope_to_dict(
        packet.relay_envelope
    )


def test_encoding_is_canonical(relayed):
    """Two encodings of one packet must be byte-identical, so a packet can be
    hashed for dedup and diffed in a log."""
    packet, _ = relayed
    assert relay_packet_to_json(packet) == relay_packet_to_json(packet)

    blob = relay_packet_to_json(packet)
    assert blob == relay_packet_to_json(relay_packet_from_json(blob))
    keys = list(json.loads(blob).keys())
    assert keys == sorted(keys)
    assert b", " not in blob and b": " not in blob  # compact separators


# -- the wire must not launder tampering ------------------------------------


def test_a_tampered_sealed_key_does_not_materialize(relayed, l2_verifier):
    packet, protocol = relayed
    d = relay_packet_to_dict(packet)
    raw = bytearray(bytes.fromhex(d["sealed_key"]))
    raw[len(raw) // 2] ^= 0xFF
    d["sealed_key"] = bytes(raw).hex()

    tampered = relay_packet_from_dict(d)
    assert tampered.sealed_key != packet.sealed_key  # decoding accepted it...
    # ...and materialization is where it dies.
    assert _materializer(protocol, l2_verifier).materialize(tampered) is None


@pytest.mark.parametrize(
    "field, value",
    [
        ("signer_id", "someone-else"),
        ("payload_type", "not-what-was-signed"),
        ("timestamp", 1.0),
    ],
)
def test_a_tampered_envelope_field_breaks_the_signature(signed_relayed, field, value):
    """Every field `signable_content()` covers must be covered on the wire too;
    if the wire dropped one, a relayer could change it undetected."""
    packet, _ = signed_relayed
    d = signed_envelope_to_dict(packet.relay_envelope)
    assert d[field] != value
    d[field] = value

    assert signed_envelope_from_dict(d).verify() is False


def test_a_swapped_signer_key_breaks_the_kid_binding(signed_relayed, l1_operator):
    """Substituting a different vk must not verify even though the kid still
    matches the original — `verify()` re-derives the binding."""
    packet, _ = signed_relayed
    d = signed_envelope_to_dict(packet.relay_envelope)
    d["signer_vk"] = l1_operator.vk.hex()

    assert signed_envelope_from_dict(d).verify() is False


def test_a_forged_envelope_on_a_real_packet_is_rejected(signed_relayed, l2_verifier):
    """A relayer that re-signs someone else's packet with its own key is only
    stopped if the materializer verifies — which it does."""
    packet, protocol = signed_relayed
    d = relay_packet_to_dict(packet)
    d["relay_envelope"]["signature"] = "00" * (len(d["relay_envelope"]["signature"]) // 2)

    assert _materializer(protocol, l2_verifier).materialize(relay_packet_from_dict(d)) is None


def test_rerouting_to_another_chain_is_rejected(relayed, l2_verifier):
    packet, protocol = relayed
    d = relay_packet_to_dict(packet)
    d["dest_chain"] = "arbitrum"

    assert _materializer(protocol, l2_verifier).materialize(relay_packet_from_dict(d)) is None


# -- surviving a hostile sender ---------------------------------------------


def test_decoding_never_raises_something_a_caller_would_not_catch(relayed):
    """A network reader wrapping this in `except BridgeWireError` must be
    enough — no bare KeyError or TypeError may escape."""
    packet, _ = relayed
    good = relay_packet_to_dict(packet)

    hostile_inputs = [
        {},
        {"sealed_key": "zz"},
        dict(good, sealed_key=None),
        dict(good, sealed_key=12345),
        dict(good, sealed_key="abc"),  # odd-length hex
        dict(good, nonce="0"),
        dict(good, nonce=-1),
        dict(good, nonce=True),
        dict(good, source_block=2**64),
        dict(good, dest_chain=None),
        dict(good, dest_chain=["optimism"]),
        dict(good, entity_id="x" * 100_000),
        dict(good, relay_envelope="not-an-object"),
        dict(good, relay_envelope={"version": 1}),
    ]
    for bad in hostile_inputs:
        with pytest.raises(BridgeWireError):
            relay_packet_from_dict(bad)


@pytest.mark.parametrize(
    "blob",
    [b"", b"not json", b"[]", b'"a string"', b"123", b"\xff\xfe invalid utf-8"],
)
def test_malformed_json_is_a_wire_error(blob):
    with pytest.raises(BridgeWireError):
        relay_packet_from_json(blob)


def test_from_json_rejects_a_non_bytes_argument(relayed):
    packet, _ = relayed
    with pytest.raises(BridgeWireError):
        relay_packet_from_json(relay_packet_to_json(packet).decode())


def test_an_oversized_sealed_key_is_rejected_on_its_length(relayed):
    """The cap must be checked against the encoded string, before decoding —
    otherwise the allocation the cap exists to prevent has already happened."""
    packet, _ = relayed
    d = relay_packet_to_dict(packet)
    d["sealed_key"] = "ab" * (MAX_SEALED_KEY_BYTES + 1)

    with pytest.raises(BridgeWireError) as exc:
        relay_packet_from_dict(d)
    assert "cap" in str(exc.value)


def test_an_oversized_envelope_payload_is_rejected(signed_relayed):
    packet, _ = signed_relayed
    d = relay_packet_to_dict(packet)
    d["relay_envelope"]["payload"] = "ab" * (MAX_ENVELOPE_PAYLOAD_BYTES + 1)

    with pytest.raises(BridgeWireError):
        relay_packet_from_dict(d)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_timestamp_is_rejected(signed_relayed, value):
    """A NaN timestamp compares false against every freshness window, so it
    would read as permanently stale rather than as malformed input."""
    packet, _ = signed_relayed
    d = signed_envelope_to_dict(packet.relay_envelope)
    d["timestamp"] = value

    with pytest.raises(BridgeWireError):
        signed_envelope_from_dict(d)


def test_extra_unknown_fields_are_ignored(relayed, l2_verifier):
    """Forward compatibility: a newer relayer's extra field must not break an
    older receiver, and must not smuggle anything into the decoded packet."""
    packet, protocol = relayed
    d = relay_packet_to_dict(packet)
    d["some_future_field"] = {"nested": [1, 2, 3]}

    received = relay_packet_from_dict(d)
    assert received.sealed_key == packet.sealed_key
    assert not hasattr(received, "some_future_field")
    assert _materializer(protocol, l2_verifier).materialize(received) is not None


def test_encoding_refuses_a_non_envelope_in_the_envelope_slot():
    """`relay_envelope` used to be typed `object`; encoding must not silently
    emit whatever happens to be sitting there."""
    packet = RelayPacket(
        sealed_key=b"\x01\x02",
        source_chain="ethereum",
        dest_chain="optimism",
        nonce=0,
        source_block=1,
        entity_id="sha3-256:abcd",
        relay_envelope={"looks": "envelope-ish"},
    )
    with pytest.raises(BridgeWireError):
        relay_packet_to_dict(packet)


def test_an_absent_envelope_is_omitted_not_null(relayed):
    packet, _ = relayed
    assert packet.relay_envelope is None
    d = relay_packet_to_dict(packet)
    assert "relay_envelope" not in d
    assert relay_packet_from_dict(d).relay_envelope is None


def test_an_explicit_null_envelope_decodes_as_absent(relayed):
    """Some encoders emit `null` rather than omitting; both must mean the same."""
    packet, _ = relayed
    d = relay_packet_to_dict(packet)
    d["relay_envelope"] = None
    assert relay_packet_from_dict(d).relay_envelope is None


def test_envelope_round_trips_independently(relay_operator):
    """The envelope codec is usable on its own, not only inside a packet."""
    env = SignedEnvelope.create(
        domain=DOMAIN_BRIDGE_MSG,
        signer_vk=relay_operator.vk,
        signer_sk=relay_operator,
        signer_id="wire-relay-operator",
        payload_type="test/payload",
        payload=b"hello wire",
    )
    restored = signed_envelope_from_dict(signed_envelope_to_dict(env))

    assert restored == env
    assert restored.verify()
    assert restored.fingerprint() == env.fingerprint()
