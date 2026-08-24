# Tempo × LTP — integration analysis

**Date:** 2026-08-24
**Status:** Analysis. No Tempo leg is deployed; the blocker is named in
[§5](#5-what-is-actually-blocking-a-tempo-leg).

[Tempo](https://tempo.xyz) is a payments-first Layer 1 incubated by Stripe and
Paradigm, purpose-built for stablecoin payments. This document records what was
measured against the live network, where LTP genuinely fits, and — more
usefully — where it does not.

Every fact in §1 was read from the live chain or the published docs on
2026-08-24, not inferred.

---

## 1. Measured facts

| Property | Value | How it was established |
|---|---|---|
| Mainnet chain ID | `4217` | `cast chain-id` against `https://rpc.tempo.xyz` |
| Testnet chain ID | `42431` ("moderato") | `cast chain-id` against `https://rpc.testnet.tempo.xyz` and `https://rpc.moderato.tempo.xyz` (both resolve to the same chain) |
| Client | `tempo/v1.13.1-6d9d0d5` | `web3_clientVersion` |
| Testnet head | ~32,319,823 | `eth_blockNumber` |
| Gas price (testnet) | 601000000 wei | `eth_gasPrice` |
| EVM target | Osaka | Tempo docs, "EVM compatibility" |
| Stablecoin standard | TIP-20 | Tempo docs |
| Native value transfer | **Rejected** — `Revm error: value transfer not allowed` | `cast estimate --value 1` |
| `eth_getBalance` | Returns sentinel `0x4242…4242` for **every** address | queried deployer, zero address, and a fresh random address — all identical |
| `eth_estimateGas` | Does **not** enforce a balance check | returned `274318` for an account whose real balance is `0` |
| Real spendable balance | `0` for an unfunded account | broadcast rejected: `insufficient funds for gas * price + value: have 0 want 3378` |

### 1.1 The balance sentinel is a real integration hazard

Three independent RPC behaviours combine into a trap for any tooling that
pre-flights a deploy:

1. `eth_getBalance` reports an enormous balance for every account.
2. `eth_estimateGas` succeeds against that non-existent balance.
3. The state transition still rejects the transaction with `have 0`.

Naive tooling therefore passes both cheap checks and fails at broadcast — after
signing. This repo's `scripts/deploy_testnet_leg.sh` hit exactly that: its
balance gate passed on the sentinel, the registry deploy *simulated* cleanly,
and the run died at broadcast. The script now detects an implausible reported
balance and says plainly that the check proves nothing, because **there is no
pre-broadcast RPC question on this chain that reliably answers "can this
account spend."** An estimate-based probe would have been false confidence, so
one was deliberately not shipped.

A useful side effect of the simulation succeeding: contract addresses are
CREATE-deterministic, so a Tempo leg deployed from the same deployer at the
same nonce lands on the *same addresses* as the Ethereum Sepolia leg.

---

## 2. Where LTP does **not** add value on Tempo

Stated first, because it is the larger half of the answer.

**Tempo does not need LTP to move value.** It already has production bridges —
LayerZero/Stargate (USDC, fee-free on the direct Ethereum↔Tempo route),
Chainlink CCIP, and Squid. These are audited, liquid, and operated by teams
whose entire business is bridging. LTP's `OptimisticBridgeChallenge` is a
2-of-2 governance, zero-bond, `MODE_SIMULATED` testnet artifact
([Whitepaper Appendix B](../WHITEPAPER.md#appendix-b-protocol-parameters)).
Positioning it as a value bridge against CCIP would be a claim the code cannot
support, and would invite a comparison LTP loses on every axis that matters for
moving money.

**Tempo does not need LTP for payment throughput.** Parallel execution,
sponsored fees, and an enshrined DEX are the chain's own core competencies.

---

## 3. Where LTP genuinely fits

LTP's actual product is not transport of value. It is a **constant-size,
post-quantum, on-chain attestation that some off-chain payload existed, is
retrievable, and has not changed** — with the payload itself never touching the
chain. That maps onto three Tempo-specific surfaces.

### 3.1 Payment-attached evidence (strongest fit)

Tempo payments carry an optional **memo** for reconciliation. A memo is a small
plaintext field — it cannot carry an invoice, a KYC bundle, a bill of lading, or
a contract, and anything sensitive must not be put there at all.

LTP's anchor is a fixed ~1,600 B commitment regardless of payload size. So:

- Commit the supporting document set to LTP; get an `entityIdHash`.
- Put that hash (32 B) in the Tempo memo.
- Counterparty, auditor, or regulator materializes the documents from the commitment network and verifies against the on-chain anchor.

The payment settles on Tempo at Tempo's speed and cost; the evidence is
verifiable, confidential, and post-quantum-durable — which matters precisely
because a payment record's audit life (7–10 years, longer under some regimes)
outlives current public-key cryptography's safe horizon. This is the one place
where "post-quantum" is a present-tense requirement rather than a talking point:
**harvest-now-decrypt-later against long-lived financial records is a real
threat model**, and it is the argument that survives contact with a CFO.

### 3.2 Tempo Zones ↔ LTP corridors

Tempo **Zones** are private zones running alongside the public chain, with
`pathUSD` routing value between them. That is structurally the same shape as an
LTP corridor: two domains that must exchange something without exposing its
contents to either side's general public.

Zones move *value* between private domains. LTP moves *data* between them with a
constant-size public commitment. A Zone participant can prove to a public-chain
counterparty that a document exists and matches, without revealing it or leaving
the Zone. This is the most interesting long-term fit and the least developed —
LTP's corridor daemon does not exist yet (membership registry, PoP exchange, and
partial-signature transport for the 7-of-9 quorum are all unimplemented), so
this is a direction, not a plan.

### 3.3 Machine Payments Protocol (agentic)

Tempo's **MPP** charges for APIs, MCP tools, and digital content in TIP-20
stablecoins. `suwappubot` already integrates Tempo (chain `4217`, a fee-sponsor
flag, explorer links) and already serves MCP tools.

An agent paying for a tool call has a matching evidentiary problem: proving
*what was delivered* for a payment, when the deliverable is data. An LTP anchor
referenced from the MPP payment gives a tamper-evident receipt of the artifact
itself, not merely of the transfer. This is the tightest fit to what Suwappu
already ships.

---

## 4. Deployment shape, if a leg goes ahead

Tempo is EVM-compatible and targets Osaka; this repo compiles with
`evm_version = "cancun"` (`contracts/foundry.toml`), which is older and
therefore accepted. The registry deploy already simulates cleanly against
Tempo testnet, so no contract changes are expected.

```bash
cp config/deploy/tempo-testnet.env.template config/deploy/tempo-testnet.env
# fill DEPLOYER_PRIVATE_KEY / operator, then fund the deployer (see §5)
scripts/deploy_testnet_leg.sh config/deploy/tempo-testnet.env
scripts/register_signer_leg.sh config/deploy/tempo-testnet.env
```

Two Tempo-specific cautions:

- **Fees.** Tempo supports paying fees in stablecoins and sponsoring them. Foundry assumes a native-gas model. Expect the standard path to need native gas even though the chain's own UX does not.
- **No native transfers.** `scripts/register_signer_leg.sh` funds the operator wallet by sending native value from the deployer. That call is rejected on Tempo. The operator must be funded through Tempo's own mechanism instead.

---

## 5. What is actually blocking a Tempo leg

Funding. Tempo's testnet faucet runs through Tempo Wallet, which authenticates
with a passkey — a human step by design, and correctly so. The deployer
`0xdC517061243D7659b5CeeCCAB5E1269cE3dcD1F1` has a real balance of `0` on chain
`42431` despite what `eth_getBalance` claims.

To unblock: fund that address on Tempo testnet via
[wallet.tempo.xyz](https://wallet.tempo.xyz) or the Tempo CLI
(`tempo wallet login && tempo wallet fund`). Everything else is prepared.

---

## 6. Recommendation

1. **Do not** position LTP as a value bridge on Tempo. CCIP and Stargate already own that, and LTP's current parameters cannot back the claim.
2. **Do** prototype §3.1 — an `entityIdHash` in a Tempo payment memo, resolvable to an LTP-committed document set. It is small, it is honest, and it is the only one of the three that can be demonstrated end to end with what exists today.
3. Treat §3.2 (Zones) as a research direction gated on the corridor daemon, and §3.3 (MPP) as the natural follow-on once §3.1 works.

Related: [`BRIDGE_TRUST_MODEL.md`](../BRIDGE_TRUST_MODEL.md),
[`DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md),
[Whitepaper Appendix B](../WHITEPAPER.md#appendix-b-protocol-parameters).
