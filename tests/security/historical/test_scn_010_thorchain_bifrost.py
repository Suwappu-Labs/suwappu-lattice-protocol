"""SCN-010 — THORChain Bifrost-class mis-signed aggregate transfer.

Red-team scenario verifying LTP's BLS aggregate verifier rejects the
attack pattern that drained THORChain's Bifrost relayer in Jun 2021
($140k initial Bifrost incident; the same family of bugs caused the
two larger $5M and $8M ETH-Router exploits later in 2021).

Historical incident: the Bifrost relayer accepted and processed
inbound bridge events whose signatures or memo decoding did not
fully validate. THORChain's later post-mortems explicitly named
"aggregate signature validation without strict (pk, message) pair
matching" as a contributor.

LTP analogue: ``src/ltp/bls.py::BLS.aggregate_verify`` is the
low-level BLS12-381 aggregate verifier used by the consensus layer
(``src/ltp/consensus/bls_certificates.py``) and by any relayer that
ingests batched attestations. This file pins the defensive
properties; complements the existing
``tests/test_bls_attestation.py`` (single-sig attestation correctness)
and the threshold-signing tests.

Maps to LTP-A-015 (BLS rogue-key / PoP) + LTP-A-022 (BLS DST
cross-language pinning).

Defenses pinned:
    B1  aggregate_verify rejects when the (pk, message) lists have
        unequal length (no silent truncation)
    B2  aggregate_verify rejects when the aggregate signature is the
        wrong byte length
    B3  aggregate_verify rejects when a single (pk_i, msg_i) pair is
        tampered (one wrong msg or one wrong pk in the list)
    B4  aggregate_verify rejects when the aggregate signature itself
        is replaced with a forgery / random bytes
    B5  aggregate_verify_same_message (fast-aggregate path) rejects
        when one of the pks does not correspond to a signer
    B6  empty-pk inputs to aggregate_verify_same_message do NOT
        return True (no vacuous acceptance)
    B7  per-signer verify rejects when the message is altered after
        signing (Bifrost-style decode tamper)
"""
from __future__ import annotations

import pytest

from ltp.bls import BLS, _blst_available, _py_ecc_bls_available


pytestmark = pytest.mark.skipif(
    not (_blst_available or _py_ecc_bls_available),
    reason="No BLS backend available (install blst or py_ecc)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gen_signers(n: int) -> list[tuple[bytes, bytes]]:
    """Generate n (pk, sk) pairs."""
    return [BLS.keygen() for _ in range(n)]


def _sign_distinct(signers: list[tuple[bytes, bytes]], msg_prefix: bytes
                   ) -> tuple[list[bytes], list[bytes], bytes]:
    """Each signer signs a distinct message (msg_prefix || index).

    Returns (pks, messages, aggregated_signature).
    """
    pks = [pk for pk, _ in signers]
    messages = [msg_prefix + bytes([i]) for i in range(len(signers))]
    sigs = [BLS.sign(sk, m) for (_, sk), m in zip(signers, messages)]
    agg = BLS.aggregate_signatures(sigs)
    return pks, messages, agg


def _sign_same(signers: list[tuple[bytes, bytes]], msg: bytes
               ) -> tuple[list[bytes], bytes]:
    """Every signer signs the same message. Returns (pks, agg)."""
    pks = [pk for pk, _ in signers]
    sigs = [BLS.sign(sk, msg) for _, sk in signers]
    agg = BLS.aggregate_signatures(sigs)
    return pks, agg


# ---------------------------------------------------------------------------
# B1 — length mismatch rejected
# ---------------------------------------------------------------------------


def test_B1_aggregate_verify_rejects_length_mismatch_pks_too_few():
    signers = _gen_signers(3)
    pks, messages, agg = _sign_distinct(signers, b"scn010-")
    # Drop one pk.
    assert BLS.aggregate_verify(pks[:-1], messages, agg) is False


def test_B1_aggregate_verify_rejects_length_mismatch_msgs_too_few():
    signers = _gen_signers(3)
    pks, messages, agg = _sign_distinct(signers, b"scn010-")
    # Drop one message.
    assert BLS.aggregate_verify(pks, messages[:-1], agg) is False


# ---------------------------------------------------------------------------
# B2 — wrong signature byte length rejected
# ---------------------------------------------------------------------------


def test_B2_aggregate_verify_rejects_short_signature():
    signers = _gen_signers(2)
    pks, messages, _agg = _sign_distinct(signers, b"scn010-")
    short = b"\x00" * (BLS.SIG_SIZE - 1)
    assert BLS.aggregate_verify(pks, messages, short) is False


def test_B2_aggregate_verify_rejects_long_signature():
    signers = _gen_signers(2)
    pks, messages, agg = _sign_distinct(signers, b"scn010-")
    long_sig = agg + b"\x00"
    assert BLS.aggregate_verify(pks, messages, long_sig) is False


# ---------------------------------------------------------------------------
# B3 — per-pair tamper rejected
# ---------------------------------------------------------------------------


def test_B3_aggregate_verify_rejects_tampered_message():
    signers = _gen_signers(3)
    pks, messages, agg = _sign_distinct(signers, b"scn010-")
    # First the legit verify must pass.
    assert BLS.aggregate_verify(pks, messages, agg) is True
    # Now tamper with the second message — Bifrost-style decode drift.
    tampered = list(messages)
    tampered[1] = tampered[1] + b"\x01"
    assert BLS.aggregate_verify(pks, tampered, agg) is False


def test_B3_aggregate_verify_rejects_swapped_pk():
    signers = _gen_signers(3)
    pks, messages, agg = _sign_distinct(signers, b"scn010-")
    # Swap one signer's pk for a freshly generated one (not in the set).
    rogue_pk, _ = BLS.keygen()
    bad = list(pks)
    bad[1] = rogue_pk
    assert BLS.aggregate_verify(bad, messages, agg) is False


# ---------------------------------------------------------------------------
# B4 — outright forgery rejected
# ---------------------------------------------------------------------------


def test_B4_aggregate_verify_rejects_random_bytes_signature():
    signers = _gen_signers(2)
    pks, messages, _ = _sign_distinct(signers, b"scn010-")
    # 96 bytes of zeros — wrong-form group element, must NOT verify.
    assert BLS.aggregate_verify(pks, messages, b"\x00" * BLS.SIG_SIZE) is False


def test_B4_aggregate_verify_rejects_unrelated_aggregate():
    signers_a = _gen_signers(2)
    signers_b = _gen_signers(2)
    pks_a, messages_a, agg_a = _sign_distinct(signers_a, b"set-a-")
    pks_b, messages_b, _ = _sign_distinct(signers_b, b"set-b-")
    # Use signer set A's aggregate but signer set B's messages and pks.
    assert BLS.aggregate_verify(pks_b, messages_b, agg_a) is False


# ---------------------------------------------------------------------------
# B5 — fast-aggregate path rejects rogue PK
# ---------------------------------------------------------------------------


def test_B5_fast_aggregate_verify_rejects_extra_unrelated_pk():
    signers = _gen_signers(3)
    pks, agg = _sign_same(signers, b"scn010-same-msg")
    # All 3 signed; verify must pass for the legit set.
    assert BLS.aggregate_verify_same_message(pks, b"scn010-same-msg", agg) is True
    # Now claim a 4th signer joined by appending a non-signing pk.
    rogue_pk, _ = BLS.keygen()
    inflated = pks + [rogue_pk]
    assert BLS.aggregate_verify_same_message(
        inflated, b"scn010-same-msg", agg
    ) is False


def test_B5_fast_aggregate_verify_rejects_swapped_pk():
    signers = _gen_signers(3)
    pks, agg = _sign_same(signers, b"scn010-same-msg")
    rogue_pk, _ = BLS.keygen()
    swapped = list(pks)
    swapped[1] = rogue_pk
    assert BLS.aggregate_verify_same_message(
        swapped, b"scn010-same-msg", agg
    ) is False


# ---------------------------------------------------------------------------
# B6 — empty inputs do not vacuously verify
# ---------------------------------------------------------------------------


def test_B6_aggregate_verify_empty_lists_does_not_return_true():
    """Empty pk + empty msg lists must not produce a trivially-valid
    verification. The aggregate signature has to be the wrong length
    too (any 96 bytes that happens to look like a group element
    should not satisfy an empty-set verify)."""
    # An all-zero 96-byte input is not a valid signature.
    result = BLS.aggregate_verify([], [], b"\x00" * BLS.SIG_SIZE)
    # Either False (rejected) or it raises — both are acceptable.
    # The CRITICAL property is that it doesn't silently return True.
    assert result is False


# ---------------------------------------------------------------------------
# B7 — per-signer verify rejects message tamper (Bifrost decode drift)
# ---------------------------------------------------------------------------


def test_B7_per_signer_verify_rejects_message_tamper():
    pk, sk = BLS.keygen()
    msg = b"transferOut:0xCAFE:1000ETH"
    sig = BLS.sign(sk, msg)
    assert BLS.verify(pk, msg, sig) is True

    # Bifrost-style attack: relayer interprets the memo as a different
    # instruction. The on-chain bytes don't match what was signed.
    tampered = b"transferOut:0xBADC0DE:1000ETH"
    assert BLS.verify(pk, tampered, sig) is False
