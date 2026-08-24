# Tempo × LTP — integration analysis

**Date:** 2026-08-24
**Status:** **Deployed and proven end to end on Tempo testnet (42431).** A third
LTP leg is live, and an `entityIdHash` has been carried as the memo of a real
TIP-20 payment and resolved back to its on-chain anchor — see
[§3.1](#31-payment-attached-evidence-strongest-fit) and
[§5](#5-tempo-specific-gotchas-measured-the-hard-way).

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
| Per-tx gas cap | **30,000,000** | RPC rejected a 40M limit outright |
| Block gas limit | 500,000,000 | `eth_getBlockByNumber` |
| Gas metering | Heavy — a trivial CREATE costs 553,156 | measured deploy |
| Fee token | TIP-20 (`PathUSD` at `0x20c0…0000`), paid to a `0xfeec…` collector | receipt logs |
| Memo transfer | `transferWithMemo(address,uint256,bytes32)` = `0x95777d59` | executed successfully |

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

**Prototyped and verified end to end** — see
[`examples/tempo_memo_attestation.py`](../../examples/tempo_memo_attestation.py)
and `tests/test_tempo_memo_attestation.py` (14 tests).

The fit is exact rather than approximate. Tempo writes a memo as
`pad(stringToHex(memo), { size: 32 })` — a `bytes32` field. The on-chain LTP
`entityIdHash` is also `bytes32`. So the memo *is* the attestation pointer, with
no truncation, no wrapper, and no encoding overhead.

Live run against the Ethereum Sepolia leg on 2026-08-24:

| Step | Value |
|---|---|
| Document set | a 173-byte invoice (`INV-2026-0042`, `application/json`) |
| EntityID | `sha3-256:4543699361bd4d41…691fa8` |
| Tempo memo / `entityIdHash` | `0xc6e6fbd7965cec5914849d9cb74c00614fce15671f2beac06dda042d64cc1183` |
| Anchor tx | [`0x703e4002…f31100`](https://sepolia.etherscan.io/tx/0x703e4002dbb591a4ba884d8986b648aa52a6d5f7a69a3d43dfd9994b52f31100) |
| Resolution | `entity_state = ANCHORED`, bound to signer `0x4212a67b…64ed2541` |

Three cases were exercised against live chains, and the negative ones matter
more than the positive one:

1. **The anchored memo resolves** — `ANCHORED`, correct signer.
2. **A human memo does not.** `"INV-2026-0042"` encodes to `0x494e562d…0000` and returns `UNKNOWN`; the tool reports that it decodes as ASCII text, so a miss is explained rather than merely denied.
3. **The same memo on the wrong leg does not resolve.** Queried against the Base Sepolia registry it returns `UNKNOWN` — attestations are per-leg, and the tool does not paper over that.

Two implementation notes that cost real debugging and are pinned by tests:

- **The memo is not the digest in the EntityID string.** `EntityID` is `sha3-256:<hex>`; the on-chain bytes32 is `spec_hash_bytes(entity_id_string)` — SHA3-256 over the whole prefixed string (`src/ltp/bridge/live.py:247`). Using the inner digest produces a memo that silently never resolves against any registry.
- **No magic prefix.** A 4-byte tag plus 28 bytes of digest would let a parser recognise an LTP memo offline, but it spends 32 bits of collision resistance (2^128 → 2^112) to buy a guess. The registry is the discriminator instead: `getEntityState(memo) != UNKNOWN`.

**Proven end to end on Tempo itself, 2026-08-24.** Not a mock: a real TIP-20
payment on chain 42431 carries the memo, and the memo resolves to a real anchor
in a real LTP registry on the same chain.

| Step | Value |
|---|---|
| Document set | 173-byte invoice `INV-2026-0042` (`application/json`) |
| EntityID | `sha3-256:4543699361bd4d41…691fa8` |
| Memo / `entityIdHash` | `0xc6e6fbd7965cec5914849d9cb74c00614fce15671f2beac06dda042d64cc1183` |
| LTP registry (Tempo) | `0x76e9ec05745ce767e0d6f1c5f60980436a2894f6` |
| Anchor tx | `0x8ae2579f2c186d6cb26a0d6a4028d3237cd9703e7cfbd45304c840bff8c70b15` |
| **Payment tx** | `0x43354343824134cf98e53ee765c75adc826ad7b5f5aeacaddbd15245b1eb089c` |
| Payment | 100.000000 AlphaUSD via `transferWithMemo(address,uint256,bytes32)` (`0x95777d59`) |
| Result | memo recovered from the payment's calldata, resolved `ANCHORED`, bound to signer `0x4212a67b…64ed2541` |

The loop closes: **payment → memo → anchor → document set**, with the documents
never touching either chain. Machine-readable record:
[`deployments/tempo_memo_attestation_live.json`](../../deployments/tempo_memo_attestation_live.json).

The same memo was also anchored and resolved on Ethereum Sepolia
(tx `0x703e4002…f31100`), and — as it should — returns `UNKNOWN` against the
Base Sepolia registry, where it was never anchored. Attestations are per-leg.

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

## 4. Deploying a leg (as done)

Tempo is EVM-compatible and targets Osaka; this repo compiles with
`evm_version = "cancun"` (`contracts/foundry.toml`), which is older and
therefore accepted. **No contract changes were needed** — the same v6 bytecode
that runs on Base Sepolia and Ethereum Sepolia runs here.

```bash
cp config/deploy/tempo-testnet.env.template config/deploy/tempo-testnet.env
# fill DEPLOYER_PRIVATE_KEY / operator, fund the deployer at wallet.tempo.xyz
GAS_ESTIMATE_MULTIPLIER=1200 scripts/deploy_testnet_leg.sh config/deploy/tempo-testnet.env
# fund the operator in TIP-20 (see 5.3), then:
scripts/register_signer_leg.sh config/deploy/tempo-testnet.env
```

Live addresses are in [`DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md);
the machine-readable record is
[`deployments/tempo_testnet.json`](../../deployments/tempo_testnet.json).

---

## 5. Tempo-specific gotchas, measured the hard way

Each of these cost a failed transaction. None is documented as a porting note
anywhere obvious, so they are recorded here in the order they bite.

### 5.1 Gas estimates are far too low, and failures look like reverts

Tempo meters gas much more heavily than a mainnet-equivalent chain: a contract
creation returning empty runtime code still cost **553,156 gas**.
`LTPAnchorRegistry` actually consumes **10,576,216**, while `forge` estimated
**2,163,216**.

Worse, a gas-starved transaction on Tempo reports `gasUsed == gasLimit` with
`status 0` — indistinguishable at a glance from a revert. Two deploy attempts
were misread as contract failures before the pattern was clear: the giveaway is
that `gasUsed` equals the limit *exactly*, twice, at two different limits.

`forge script` has no `--gas-limit`, only `--gas-estimate-multiplier`, and a
single multiplier must satisfy contracts whose true cost is dominated by a large
fixed overhead:

| Multiplier | Registry (base 2.16M) | Small contract (base 0.17M) | Verdict |
|---|---|---|---|
| 400% | 8.65M | — | too low, registry OOG |
| 800% | 17.3M | 1.32M | too low, *small* contract OOG |
| **1200%** | **25.96M** | **1.99M** | **works** |
| 1400% | 30.29M | 2.32M | rejected, over the per-tx cap |

The usable window is narrow because of 5.2. `deploy_testnet_leg.sh` now takes
`GAS_ESTIMATE_MULTIPLIER`.

### 5.2 Hard 30M per-transaction gas cap

`transaction gas limit (40000000) is greater than the cap (30000000)`. The block
gas limit is 500M, so this is a per-transaction rule, and it is what bounds the
multiplier above.

### 5.3 No native value transfers; fees are paid in TIP-20

`cast estimate --value 1` returns `Revm error: value transfer not allowed`. Fees
are settled in a TIP-20 stablecoin — a transaction's receipt shows a token
transfer to the `0xfeec…` fee collector, and `forge` prints its cost estimate in
**USD**.

Consequence: `register_signer_leg.sh` funds the operator with a native transfer,
which cannot work here. Fund it with a TIP-20 transfer instead:

```bash
# PathUSD is the fee token; AlphaUSD is the demo payment token
cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC_URL" --gas-limit 5000000 \
  0x20c0000000000000000000000000000000000000 \
  "transfer(address,uint256)(bool)" "$OPERATOR" 50000000000   # 50,000 PathUSD (6 dp)
```

### 5.4 Balances are a sentinel until you look closely

Covered in [§1.1](#11-the-balance-sentinel-is-a-real-integration-hazard):
`eth_getBalance` returns `0x4242…4242` for every address and `eth_estimateGas`
ignores balance, so both cheap pre-flight checks pass for an account that cannot
pay. The one reliable signal is a broadcast attempt.

### 5.5 Funding is passkey-gated, by design

The testnet faucet runs through Tempo Wallet
([wallet.tempo.xyz](https://wallet.tempo.xyz), or
`tempo wallet login && tempo wallet fund`). This is a human step and correctly
so; it is the only part of this integration that cannot be automated. The grant
is generous — ~1,000,000 units each of PathUSD and AlphaUSD.

---

## 6. Recommendation

1. **Do not** position LTP as a value bridge on Tempo. CCIP and Stargate already own that, and LTP's current parameters cannot back the claim.
2. §3.1 is **done and proven on Tempo** — an `entityIdHash` in a real TIP-20 payment memo, resolving to an on-chain anchor. Next step is product, not research: decide whether the commitment network is operated for real counterparties, since the attestation is only as useful as the retrievability behind it.
3. Treat §3.2 (Zones) as a research direction gated on the corridor daemon, and §3.3 (MPP) as the natural follow-on once §3.1 works.

Related: [`BRIDGE_TRUST_MODEL.md`](../BRIDGE_TRUST_MODEL.md),
[`DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md),
[Whitepaper Appendix B](../WHITEPAPER.md#appendix-b-protocol-parameters).
