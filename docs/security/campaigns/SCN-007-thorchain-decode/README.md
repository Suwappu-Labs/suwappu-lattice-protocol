# SCN-007 — THORChain ETH router decode bug

**Status.** VERIFIED-GREEN expected — defenses are structural.
**Layer.** 1 — Smart-contract input validation.
**Historical incident.** THORChain ETH Router, 22 Jul 2021, ~$5M
(plus ~$8M follow-on a week later).
**LTP-A-* link.** No specific LTP-A-* — the defenses are structural
absence of the dangerous primitive. Adjacent to LTP-A-007
(simulated-mode production lock).

## What happened (THORChain)

THORChain's ETH Router accepted a `bytes memo` field on
`deposit()`. The off-chain Bifrost relayer parsed the memo to
determine how to react: `=:ETH.ETH:<recipient>` was a swap,
`OUT:<txid>` was an outbound transfer, etc. The attacker crafted
a memo that, when off-chain-decoded, caused Bifrost to dispatch
`transferOut()` on the Router back to the attacker — without
their corresponding deposit being valid. The Router itself trusted
the memo to be well-formed; the relayer trusted the Router's
emitted event. Same primitive showed up in the later "fake-
contract" exploit a week later.

Root primitive: **user-supplied bytes were decoded into an
instruction dispatch** — either on-chain or by a downstream
trusted relayer. Whoever did the decode trusted the bytes.

## LTP analogue

LTP's two user-controlled-bytes surfaces are:

- `BridgeEmitter.emitBridgeTransfer(string payloadHash)`
- `ZKBridgeVerifier.verifyAndFinalize(bytes proofBytes, ...)`

**Neither decodes user bytes into a control-flow dispatch.**

| ID | Defense | Source |
|----|---------|--------|
| T1 | BridgeEmitter ONLY emits `payloadHash` as an event field. Zero logic conditioned on its content. | BridgeEmitter.sol:69 |
| T2 | ZKBridgeVerifier slices `proofBytes` into fixed-purpose chunks (proof_hash + verification_tag) and uses them inside keccak256-based verification. Content cannot redirect control flow — at most it can fail verification. | ZKBridgeVerifier.sol:160-179 |
| T3 | Verifier mode dispatch (SIMULATED/SP1/STARK/RISC0) is gated by `verificationMode` storage, set by admin only. User input cannot select the backend. | ZKBridgeVerifier.sol:127-137 |
| T4 | `productionMode + MODE_SIMULATED` is fail-closed (LTP-A-007). | ZKBridgeVerifier.sol:122-125 |
| T5 | `verifyAndFinalize` only ever calls `challengeContract.finalizeWithZKProof(anchorDigest)` — ONE downstream target, not caller-supplied. | ZKBridgeVerifier.sol:148 |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_007_THORChain_DecodeBug.t.sol` | T1 (malicious payload only emitted), T1 fuzz (arbitrary bytes accepted without side effects), T3 (verificationMode admin-only), T5 (challengeContract reference immutable) |

No new invariant or Echidna harness — the defenses are structural
absence, not stateful runtime checks. The existing audit tests
already cover the admin-only / mode-dispatch surface (LTP-A-007).

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_007_*' -vvv
```

## Findings opened

None. The dangerous primitive (user-bytes → control-flow dispatch)
is structurally absent.
