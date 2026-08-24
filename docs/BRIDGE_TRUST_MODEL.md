# Bridge Trust Model — OptimisticBridgeChallenge + ZKBridgeVerifier

This document covers the on-chain optimistic-settlement bridge
(`contracts/src/OptimisticBridgeChallenge.sol` +
`contracts/src/ZKBridgeVerifier.sol`). It answers the question every
bridge user should be able to answer before moving funds: **what
exactly secures this, and what do I have to trust?**

It does not cover the LATTICE sealed-key relay path (untrusted-relay
model, see `docs/bridge-mvp-scope.md`) or the ML-DSA/BLS validator
signing surface (see `docs/THREAT_MODEL.md`) — those are different
subsystems with different trust properties.

**Status of this doc: describes the live deployments as of 2026-08-24.**
Several of the issues described here are already fixed *in source* (v7, see
`docs/DEPLOYED_CONTRACTS.md` "v7 Governance Hardening") but **not yet
deployed** — every live contract predates that fix. This doc will need a
follow-up pass once v7 actually deploys.

| Contract | Base Sepolia (`84532`) | Ethereum Sepolia (`11155111`) |
|---|---|---|
| `OptimisticBridgeChallenge` | `0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0` | `0x0af67a32d2578f57397f0022bff9ba2647d66b58` |
| `ZKBridgeVerifier` | `0x4Df2D23269D0841200b36106AA90ba653e30DFf3` | `0x4d687361cc02e134c70d1a0d3e2e9ee7cc51f1fa` |

**Everything in this document applies identically to both legs.** The Ethereum
Sepolia leg was deployed 2026-08-24 by the re-legging described in
`docs/plans/2026-08-24-testnet-cross-chain-relegging.md`, using the same testnet
scripts and the same parameters as Base Sepolia: 2-of-2 MultiSig, 60-second
Timelock, `MODE_SIMULATED` verifier, 3600-second challenge window, zero bonds.
A newer deployment date does **not** mean a stronger trust model — the second
leg exists so there are two live chains to bridge *between*, not because
anything was hardened. The original SUWAPPU Testnet leg (`103115120`) is retired
and unreachable; ignore any older text that treats it as live.

## 1. The two finality paths

A pending bridge anchor finalizes one of two ways:

1. **Optimistic path.** An operator opens a challenge window
   (`openWindow`). If nobody files a fraud challenge before the
   `challengePeriod` deadline, anyone can call the finalize path and
   the anchor is accepted.
2. **Fast path.** Whoever controls `ZKBridgeVerifier` can call
   `verifyAndFinalize` with a proof; if it passes, the anchor
   finalizes **instantly**, bypassing the challenge window entirely.

Both paths write to the same `OptimisticBridgeChallenge` state. The
fast path is strictly more powerful — it skips step 1 completely — so
its trustworthiness is the ceiling on the whole bridge's security.

## 2. Fast path: what "ZK proof" currently means

`ZKBridgeVerifier` has four verification modes:
`MODE_SIMULATED` (0), `MODE_SP1` (1), `MODE_RISC_ZERO` (2), `MODE_STARK` (3).

**The live Base Sepolia deployment is in `MODE_SIMULATED`** — this is
the constructor default (`contracts/script/DeployBridge.s.sol:19`,
`BRIDGE_ZK_MODE` defaults to `0`) and nothing in the deployment history
shows it being changed.

`MODE_SIMULATED`'s "proof" is not a stub with a placeholder key — it
is **not a zero-knowledge proof at all**. `_verifySimulated`
(`ZKBridgeVerifier.sol:152-168`) accepts any 64-byte value that
satisfies:

```
tag == keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || proofHash || "sim-verify")
```

Every input to that hash — including `proofHash` — is chosen by the
caller. **Anyone who can compute keccak256 can construct a "valid"
proof for any claim.** This is not "weak crypto"; it is no
cryptographic check whatsoever, dressed in a proof-shaped interface.

This is a known, already-triaged issue: internal audit finding
**LTP-A-007** (`docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md:218-233`,
severity **CRITICAL**) describes this exact exploit chain. The fix —
a `productionMode` flag plus `lockProduction()`, which irreversibly
disables `MODE_SIMULATED` once called — is written
(`ZKBridgeVerifier.sol`, `setVerificationMode` already enforces it at
`:294-302`) but **the deployed Base Sepolia contract predates this
change** (v7 is "source-only... pending deploy" per
`docs/DEPLOYED_CONTRACTS.md`). `lockProduction()` does not exist on
the live contract, so there is currently no way to lock out
`MODE_SIMULATED` on this deployment short of a redeploy.

**Practical honest disclosure:** as deployed today, the fast path
provides **no cryptographic guarantee**. A live-Base-Sepolia bridge
user's actual security comes entirely from the optimistic path (§3) —
*unless and until an operator actually calls `verifyAndFinalize`
through the simulated backend*, at which point an anchor can be forged
by anyone, instantly, with zero stake at risk. There is no evidence in
the repo that this has happened, only that it is currently possible.

Switching to a real backend (`MODE_SP1`, `MODE_RISC_ZERO`, `MODE_STARK`)
is not simply a config flip: as of this writing, ZK-proving of the
ML-DSA/Dilithium signatures this bridge would need to attest to has no
audited, production-grade implementation anywhere in the ecosystem
(the closest public prior art, `ZKNoxHQ/ETHDILITHIUM`, explicitly says
"experimental, not audited, DO NOT USE IN PRODUCTION"). There is
currently no real verifier to switch *to*.

## 3. Optimistic path: what the challenge mechanism actually checks

`submitChallenge` lets anyone post a `fraudProofHash` — **a hash of
off-chain data** — plus a bond, before the window's deadline.

**What this does NOT do:** the contract has no logic anywhere that
inspects the underlying anchor data, the claimed fraud, or the
off-chain proof the hash supposedly commits to. There is no on-chain
verification of correctness in the optimistic path at all.

**What actually decides a challenge**, one of three ways:
- `resolveChallenge` — the **admin** rules `fraudValid` true/false, at its own discretion. No on-chain check backs this ruling.
- `resolveChallengeByArbiter` — an appointed **arbiter** address rules instead.
- `resolveByTimeDecay` — if neither acts within `resolutionGracePeriod` (default 14 days, floor 24h), the challenger wins by default.

In other words: **the fraud proof is a bond-backed accusation, not a
cryptographic proof.** Correctness rests entirely on the honesty and
availability of two keys (admin + arbiter), with a 14-day timeout as
the only non-discretionary backstop. This is a materially different
(weaker) trust model than "optimistic rollup" language usually
implies — there is no on-chain fraud-proof *verification*, only
on-chain fraud-proof *arbitration*.

Both the admin and arbiter are controlled, on Base Sepolia, by a
2-of-2 MultiSig behind a 60-second Timelock (`docs/DEPLOYED_CONTRACTS.md`
"Governance Architecture"). 60 seconds and 2-of-2 are explicitly
testnet parameters; v7's pending hardening raises the mainnet target
to a Byzantine-safe multisig threshold (`>= ceil(N/2) + 1`) and a
24-48 hour timelock delay — neither is live yet.

## 4. Bonds and slashing

- `minOperatorBond` and `minChallengerBond` are admin-settable, and
  **currently both `0`** on the live deployment
  (`contracts/script/DeployBridge.s.sol:17-18` defaults, no override
  visible in `docs/DEPLOYED_CONTRACTS.md`'s Base Sepolia section).
- Slashing exists and works as designed: whichever side loses a
  resolved challenge has its bond transferred to the winner
  (`OptimisticBridgeChallenge.sol:213-217` and equivalent paths in the
  arbiter/time-decay resolution functions).
- **With bonds at 0, slashing has no economic effect today.** Anyone
  can open a challenge window, or file a challenge, with zero capital
  at risk. This is very likely an intentional testnet simplification
  (no faucet-funded bond flow needed to exercise the happy path) — but
  it is flagged here explicitly because it is not stated as
  intentional anywhere else in the docs, and a bond of 0 is
  indistinguishable, on-chain, from a misconfiguration. **This should
  be confirmed as intentional-for-testnet before any mainnet
  deployment, and mainnet bonds must be set to a value that makes
  griefing/spam economically irrational.**

## 5. Who can be an "operator"?

There is no registration or allowlist. Anyone can call `openWindow`
for any `anchorDigest` by posting `msg.value >= minOperatorBond`
(currently 0, i.e. anyone, with nothing). "Operator" here means
"whoever opened this particular window," not a vetted or staked role
in the traditional bridge-operator sense.

## 6. Concrete risks, stated plainly (live deployment, as of this doc)

1. **Forged instant finality.** If the fast path is ever invoked in
   `MODE_SIMULATED` (the current live mode), anyone can finalize an
   anchor instantly with a self-computed hash — no real proof, no
   bond, no challenge window. This is the highest-severity live risk.
2. **Free-to-spam challenge windows.** With `minOperatorBond = 0`,
   anyone can open windows for arbitrary digests with zero cost,
   including for digests they have no legitimate claim to.
3. **Free-to-spam challenges.** With `minChallengerBond = 0`, the same
   applies to filing challenges — no cost to griefing a legitimate
   operator's window (though a frivolous challenge that loses
   arbitration costs the challenger nothing to *file*, it also gains
   them nothing, so this is a nuisance/DoS risk more than a theft
   risk).
4. **Centralized, discretionary dispute resolution.** A user's actual
   recourse if defrauded is: convince the admin or arbiter (2 keys,
   currently behind a 60s-delay 2-of-2 multisig) to rule in their
   favor, or wait up to 14 days for time-decay. There is no
   cryptographic fraud-proof verification on-chain today.
5. **Governance parameters are testnet-weak by design, but must not
   silently become the mainnet defaults.** 60-second timelock, 2-of-2
   multisig, and 0 bonds are appropriate for exercising the contract
   on testnet; none of them are safe mainnet values. v7 addresses the
   multisig threshold and timelock delay in source; it does not touch
   bond floors.

## 7. What would materially improve this (not a commitment, a map)

- Deploy v7 (or later) so `lockProduction()` exists and gets called,
  removing `MODE_SIMULATED` as a live option permanently.
- Set non-zero, economically meaningful `minOperatorBond` /
  `minChallengerBond` before any deployment handling real value.
- Either wire a real ZK backend (blocked on production-grade ML-DSA
  proving becoming available — an open cryptography-R&D problem
  industry-wide, not a suwappu-lattice-protocol-specific gap) or,
  short of that, keep the fast path administratively disabled
  (`verificationMode` left unset / never called) so the optimistic
  path is the only live finality path.
- Increase timelock delay and multisig threshold to mainnet-appropriate
  values (already scoped in v7).
- Consider whether "admin/arbiter rules on an unverified hash" is an
  acceptable long-run trust model for the optimistic path even with
  bonds in place, or whether an actual on-chain-verifiable fraud proof
  (e.g. a Merkle-inclusion or state-transition check the contract can
  evaluate itself) should replace pure arbitration.
