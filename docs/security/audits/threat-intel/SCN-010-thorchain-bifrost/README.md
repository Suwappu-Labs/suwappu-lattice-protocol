# SCN-010 — THORChain Bifrost mis-signed transfer

**Status.** VERIFIED-GREEN expected.
**Layer.** 2 — Validator / consensus / signing.
**Historical incident.** THORChain Bifrost, 22 Jun 2021, ~$140k.
**LTP-A-* link.** [LTP-A-015](../../internal/SECURITY_AUDIT_2026-05-15.md)
(BLS rogue-key / PoP) + [LTP-A-022](../../internal/SECURITY_AUDIT_2026-05-15.md)
(BLS DST cross-language pinning).

## What happened (THORChain Bifrost)

THORChain's Bifrost relayer processed inbound cross-chain transfers
by:
1. Reading on-chain events on the source chain.
2. Decoding the event payload (often containing a memo).
3. Computing the implied THORChain action.
4. Validating signatures on the resulting THORChain transaction.

The Jun 2021 ~$140k incident — and the family of bugs that
contributed to the larger Jul 2021 $5M and $8M ETH-Router
incidents — all share the same primitive: **at some point in the
inbound flow, an aggregate signature or per-event signature was
accepted without strictly matching the on-chain bytes to what the
signer attested to.**

Root primitive: **aggregate verifier accepted a (pks, messages,
agg_sig) triple where the messages did not exactly match the bytes
the signers had committed to**. A decode-time drift on the
relayer's side (or weak verifier behavior on length / order /
extra-pk) was enough.

## LTP analogue

`src/ltp/bls.py::BLS` is the low-level BLS12-381 implementation
used by the consensus layer (`bls_certificates.py`) and any
relayer that ingests batched attestations. The defenses pinned in
this scenario:

| ID | Defense | Source |
|----|---------|--------|
| B1 | `aggregate_verify` rejects when the (pk, message) lists have unequal length | `bls.py:167-168` |
| B2 | `aggregate_verify` rejects when `agg_sig` is the wrong byte length | `bls.py:169-170` |
| B3 | `aggregate_verify` rejects when any single (pk_i, msg_i) pair is tampered | (verifier-internal) |
| B4 | `aggregate_verify` rejects random / unrelated-aggregate forgeries | (verifier-internal) |
| B5 | `aggregate_verify_same_message` (fast-aggregate path) rejects when a non-signer pk is included | (verifier-internal) |
| B6 | empty input lists do not vacuously verify | `bls.py:167-170` |
| B7 | per-signer `verify` rejects when the message is altered after signing | `bls.py:129-148` |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| pytest | `tests/security/historical/test_scn_010_thorchain_bifrost.py` | B1×2 (pks-too-few + msgs-too-few), B2×2 (short + long sig), B3×2 (tampered message + swapped pk), B4×2 (random + unrelated aggregate), B5×2 (extra rogue pk + swapped pk), B6 (empty inputs), B7 (Bifrost-style memo tamper) |

The test pack is gated by `pytest.mark.skipif` so it only runs
when at least one BLS backend (blst or py_ecc) is installed. The
CI environment has py_ecc available.

## How to run

```bash
pip install -e '.[dev]'  # ensures py_ecc / blst is present
pytest tests/security/historical/test_scn_010_thorchain_bifrost.py -v
```

## Notes on cross-language interop (LTP-A-022)

The audit's LTP-A-022 finding flagged the BLS DST cross-language
pinning. This scenario does NOT re-test the DST pinning — that's
covered by `tests/test_bls_attestation.py` (single-sig attestation
correctness across backends) and the threshold-signing test suite.
The structural lesson lives in
[bls-dst-mismatch-cross-language-interop](skill registry) — both
Python (`py_ecc` / blst-bindings) and any Rust verifier must use
the same DST (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` in
the LTP convention).

## Findings opened

None expected. Aggregate-verify defenses are inherent to the
BLS12-381 spec when implemented correctly; the test pack pins
that the LTP backends (blst + py_ecc) implement them correctly.
