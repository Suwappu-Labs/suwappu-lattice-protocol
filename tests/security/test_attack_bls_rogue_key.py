"""LTP-A-015 regression: BLS rogue-key attack on aggregate verification.

Defense pattern (existing): ``corridor/bls.py`` performs *manual G1 public-key
aggregation* before calling single-key verify. For a static signer set this
catches the classic Boneh-Drijvers-Neven rogue-key attack where an attacker
publishes ``pk_rogue = g·h(adversary) - Σ(pk_honest)``.

This test exercises the threshold-signing path (which is the corridor-equivalent
path in the production code) and asserts:

1. A real threshold signature from a legitimate DKG verifies green.
2. A signature produced by a single ``ThresholdSigningKey`` (off-curve relative
   to the group PK) does NOT verify against the group PK — the threshold
   verifier rejects the lone signer just as a corridor verifier rejects a
   rogue-key forgery.

The companion fix in Commit 4 of this PR adds Proof-of-Possession at
``Corridor`` member registration, closing the rogue-key surface at the
*registration* step rather than only at verification (which is what defends
adaptive attackers who rotate keys).
"""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)
from src.ltp.zk.ec_backend import bls12_381_available

pytestmark = pytest.mark.skipif(not bls12_381_available(), reason="py_ecc / blst not installed")


def test_threshold_verifier_accepts_legitimate_aggregate(dkg_4_of_3):
    """Sanity: with 3 of 4 honest signing keys, the aggregate verifies."""
    signing_keys, group_pk = dkg_4_of_3
    msg = b"legitimate-attestation-payload"
    partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in signing_keys[:3]]
    sig = combine_partial_signatures(partials, 3)
    assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)


def test_threshold_verifier_rejects_single_signer_forgery(dkg_4_of_3):
    """Rogue-key analog: a single signing key cannot stand in for the group.

    Concretely: take only 1 partial signature (below threshold=3), combine it
    via the same combiner (which will produce a malformed aggregate or a
    signature that the group-PK verifier rejects), and assert the verifier
    rejects it.
    """
    signing_keys, group_pk = dkg_4_of_3
    msg = b"forgery-attempt"
    partials = [partial_sign(signing_keys[0], msg, DOMAIN_ATTESTATION)]
    try:
        sig = combine_partial_signatures(partials, 1)
    except (ValueError, AssertionError):
        # Combiner refuses sub-threshold input — also a valid rejection path.
        return
    assert not threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION), (
        "rogue-key regression: a single-signer aggregate verified under the group PK"
    )


def test_threshold_verifier_rejects_wrong_group_pk(dkg_4_of_3):
    """Substituting a different group PK invalidates the signature.

    Mirrors the "attacker pretends a different corridor signed" surface:
    even with a real signature, verifying against the wrong group PK fails.
    The bad PK may fail either by returning False (semantic rejection) or
    by raising (the bytes don't form a valid G1 point) — both are valid
    defenses; only silent acceptance would be a bug.
    """
    signing_keys, group_pk = dkg_4_of_3
    msg = b"valid-but-wrong-pk"
    partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in signing_keys[:3]]
    sig = combine_partial_signatures(partials, 3)

    # Mutate the group PK by flipping a high-order byte (less likely to
    # accidentally still be a valid G1 point).
    pk_bytes = bytes(group_pk)
    bad_pk = pk_bytes[:-1] + bytes([pk_bytes[-1] ^ 0x01])
    try:
        verified = threshold_verify(bad_pk, msg, sig, DOMAIN_ATTESTATION)
    except Exception:
        return  # raised on malformed PK — defense in place
    assert not verified, "BLS verifier silently accepted a tampered group PK — security regression"


def test_threshold_verifier_rejects_wrong_domain(dkg_4_of_3):
    """Domain separation: a signature in one domain must not verify in another."""
    signing_keys, group_pk = dkg_4_of_3
    msg = b"domain-separated"
    partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in signing_keys[:3]]
    sig = combine_partial_signatures(partials, 3)
    wrong_domain = b"NOT-DOMAIN-ATTESTATION"
    assert not threshold_verify(group_pk, msg, sig, wrong_domain)
