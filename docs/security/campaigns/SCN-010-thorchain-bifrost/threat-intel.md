# SCN-010 — Threat intelligence sources

Historical incident: **THORChain Bifrost incidents, June–August 2021, cumulative ~$13M.**

The Bifrost-class bugs spanned three incidents in 2021:
- **22 Jun 2021** — initial Bifrost mis-processing, ~$140k stolen.
- **15 Jul 2021** — ETH Router exploit, ~$5M (SCN-007 already
  covers the Router-side decode bug).
- **23 Jul 2021** — RUNE token contract exploit, ~$8M.

## Primary sources

- **THORChain post-mortems** — individual incidents published on
  the team's Substack and GitLab. (The earlier curated index page
  has moved; search "THORChain security incident response 2021"
  for the current location.)
- **Patch PRs** in `thorchain/thornode` and `thorchain/heimdall`
  closing the various Bifrost / Router paths.

## Secondary technical analyses

- **Halborn retrospective** — covers the Bifrost decode-and-relay
  trust boundary.
- **Rekt News** — https://rekt.news/thorchain-rekt/ (Router) and
  https://rekt.news/thorchain-rekt2/ (RUNE token).
- **samczsun threads** — early triage for both Jul incidents.

## Root primitive

A relayer / aggregator processes inbound events and computes
downstream actions on a trust assumption that signed off-chain
data exactly matches the on-chain bytes. The trust breaks when:

1. **Signatures attest to a message different from the
   downstream action**. Bifrost's decode of the memo produced an
   action the signers didn't commit to.
2. **Aggregate verification is loose** — accepts (pks, messages,
   sig) triples where one of the messages doesn't match what was
   signed, or where a non-signer pk is silently included in the
   set.
3. **Length / order / type checks are missing** — empty inputs
   vacuously verify, wrong-size signatures pass through, mismatched
   list lengths silently truncate.

## Related incidents

The same general primitive surfaced (in slightly different shape)
in:
- Wormhole signature-skip (SCN-001) — accepted a "verified"
  signal without checking the verifier provenance.
- Nomad init-bug (SCN-002) — accepted any-message-as-verified
  via a sentinel.
- Poly Network keeper-escalation (SCN-003) — accepted a caller-
  supplied target/method as a privileged dispatch.

The BLS aggregate-verifier failure mode is distinct because the
attack is purely cryptographic — the verifier mis-accepts a
forged/tampered triple — rather than logical.

## Mapping to LTP

LTP's `BLS.aggregate_verify` and `BLS.aggregate_verify_same_message`
explicitly:
- Reject mismatched (pk, message) list lengths.
- Reject wrong-size aggregate signatures.
- Verify each (pk_i, msg_i) pair against the aggregate.
- Reject inflated pk lists in the fast-aggregate path (so rogue-
  key inflation cannot pass).
- Reject empty inputs.

The test pack exercises these defenses against real BLS keypairs
and signatures, ensuring the backend (blst or py_ecc) faithfully
implements the spec.

## Date of last verification

2026-05-16 — SCN-010 added under R-3.
