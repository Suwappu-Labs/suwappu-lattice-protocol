# SCN-007 — Threat intelligence sources

Historical incident: **THORChain ETH Router exploit, 22 July 2021, ~$5M (with a separate ~$8M RUNE-token exploit a week later).**

## Primary sources

- **THORChain post-mortem** (project team) — published on the
  THORChain Substack / GitLab. Walks through the malicious memo
  pattern and the Bifrost relayer's vulnerable decode path.
- **Patch PRs** in `thorchain/thornode` and `thorchain/heimdall`
  closing the memo-based outbound-transfer path.

## Secondary technical analyses

- **Rekt News** — https://rekt.news/thorchain-rekt/ and
  https://rekt.news/thorchain-rekt2/ (the two incidents).
- **Halborn / Trail of Bits** — retrospective audits.
- **THORChain community wiki** — post-mortem of the followup
  attack on the RUNE token contract.

## Root primitive

User-supplied bytes were decoded into an instruction dispatch —
either on-chain or by a downstream trusted off-chain relayer.
Whoever did the decode trusted the bytes to be well-formed and to
represent the actor's intent. THORChain made TWO related mistakes:

1. The Router's `deposit(bytes memo)` shape implied the memo would
   be parsed by something. The Router itself didn't parse it, but
   that didn't matter — the Bifrost relayer did, and it trusted
   the emitted event.
2. The Router's subsequent `transferOut()` path could be invoked
   by the relayer based on memo content, with no on-chain check
   that the corresponding deposit existed.

Defenses against this class:
- **Emit-only policy**: contracts emit user-controlled bytes as
  opaque event fields, with downstream consumers explicitly NOT
  trusting them as instructions.
- **No on-chain dispatch on user bytes**: every downstream
  contract call is to a known target with known calldata.
- **Mode dispatch is admin-controlled**: any variant selection
  (verifier backend, encoding version, etc.) is set by privileged
  storage, never by caller input.

## Mapping to LTP

LTP's emitter is emit-only by design (`BridgeEmitter.sol:69`).
LTP's verifier is fixed-target by design (`ZKBridgeVerifier.sol:148`).
The Bifrost-equivalent off-chain consumer (LTP's gateway VM)
treats payloadHash as opaque and validates everything against
on-chain registry state — not against the payload content.

## Date of last verification

2026-05-16 — SCN-007 added under R-2.
