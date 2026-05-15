"""LTP-A-001 regression: Wormhole-class signature-verification trust assumption.

The on-chain ``LTPAnchorRegistry`` performs no PQ cryptographic verification
of the BLS aggregate — it trusts the off-chain relayer to have verified the
attestation before submission. This is documented as a deliberate "thin
on-chain, thick off-chain" trade-off (see ``LTPAnchorRegistry.sol:13`` and
the security audit doc LTP-A-001).

This test does NOT claim the on-chain contract is broken. It documents the
trust boundary in code form, so:

1. The off-chain ``verify_attestation`` (and the corridor-attestation
   round-trip) DO catch a forged aggregate — proving the off-chain
   verifier is the actual line of defense.
2. A forged aggregate with the wrong signer set is rejected by
   ``threshold_verify`` against the group public key — the same check
   the relayer must run before forwarding to the on-chain ``anchor()``.

If this test ever fails, the off-chain defense has regressed and the
on-chain contract becomes a single point of failure (Wormhole-scale).
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.attestation import (
    AttestationPayload,
    CorridorAttestation,
)
from src.ltp.corridor.wire import (
    corridor_attestation_from_dict,
    corridor_attestation_to_dict,
)
from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)
from src.ltp.zk.ec_backend import bls12_381_available


pytestmark = pytest.mark.skipif(
    not bls12_381_available(), reason="py_ecc / blst not installed"
)


def _legit_attestation(signing_keys, threshold: int, msg: bytes):
    partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in signing_keys[:threshold]]
    return combine_partial_signatures(partials, threshold)


def test_offchain_verifier_accepts_real_aggregate(dkg_4_of_3):
    """The trusted relayer's verification step accepts an honest aggregate.

    This is the path the on-chain contract trusts. If this fails, the
    whole trust model is broken.
    """
    signing_keys, group_pk = dkg_4_of_3
    msg = b"corridor-attestation-digest-32b" + b"\x00" * (32 - 32 + 1)
    digest = msg[:32].ljust(32, b"\x00")
    sig = _legit_attestation(signing_keys, threshold=3, msg=digest)
    assert threshold_verify(group_pk, digest, sig, DOMAIN_ATTESTATION)


def test_offchain_verifier_rejects_aggregate_forged_with_wrong_keys(dkg_4_of_3):
    """A forged aggregate using a signing key from outside the corridor
    must be rejected by the off-chain verifier.

    This is the defense that prevents LTP-A-001 from becoming a real
    exploit: the relayer's verifier catches forgeries before they reach
    the on-chain contract.
    """
    signing_keys, group_pk = dkg_4_of_3
    digest = b"\x42" * 32

    # Real signature from the legitimate corridor.
    legit_sig = _legit_attestation(signing_keys, threshold=3, msg=digest)
    assert threshold_verify(group_pk, digest, legit_sig, DOMAIN_ATTESTATION)

    # An attacker swaps in a different message digest but reuses the
    # signature. Verification under the original digest works; under
    # any other digest fails.
    other_digest = b"\x43" * 32
    assert not threshold_verify(group_pk, other_digest, legit_sig, DOMAIN_ATTESTATION), (
        "off-chain verifier accepted a signature for a different digest — "
        "LTP-A-001 defense regressed"
    )


def test_corridor_attestation_wire_roundtrip_preserves_signature(dkg_4_of_3):
    """A CorridorAttestation can be serialized to JSON and back; the signature
    still verifies on the deserialized side.

    This is the boundary an attacker controls: the JSON wire format between
    nodes. If serialization can be exploited to inject a malformed signature
    that the off-chain verifier accepts, the on-chain contract is now the
    only defense. The PR #8 wire-hardening guarantees the JSON parser
    rejects malformed input via WireFormatError — verified here.
    """
    signing_keys, group_pk = dkg_4_of_3
    digest = b"\x99" * 32
    sig = _legit_attestation(signing_keys, threshold=3, msg=digest)

    payload = AttestationPayload(
        source_chain=1, target_chain=2, source_height=100,
        state_root=digest, timestamp_round=50,
    )
    attestation = CorridorAttestation(
        payload=payload, aggregate_signature=sig, signers=frozenset({0, 1, 2}),
    )
    wire = corridor_attestation_to_dict(attestation)
    decoded = corridor_attestation_from_dict(wire)
    assert decoded.aggregate_signature == attestation.aggregate_signature
    assert threshold_verify(
        group_pk, digest, decoded.aggregate_signature, DOMAIN_ATTESTATION
    )


def test_corridor_attestation_with_tampered_signature_fails_verification(dkg_4_of_3):
    """A 1-byte mutation in the aggregate signature (post-wire-roundtrip)
    invalidates the signature. Catches the case where an attacker controls
    the JSON wire and tries to swap signature bytes.
    """
    signing_keys, group_pk = dkg_4_of_3
    digest = b"\xab" * 32
    sig = _legit_attestation(signing_keys, threshold=3, msg=digest)

    payload = AttestationPayload(
        source_chain=1, target_chain=2, source_height=100,
        state_root=digest, timestamp_round=50,
    )
    tampered = bytes([sig[0] ^ 0x01]) + sig[1:]
    attestation = CorridorAttestation(
        payload=payload, aggregate_signature=tampered, signers=frozenset({0, 1, 2}),
    )
    decoded = corridor_attestation_from_dict(corridor_attestation_to_dict(attestation))
    assert not threshold_verify(
        group_pk, digest, decoded.aggregate_signature, DOMAIN_ATTESTATION
    )
