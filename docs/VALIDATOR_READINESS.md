# Validator Readiness — SUWAPPU Testnet

Status of the path from "team-operated testnet" to "external validators
participate in consensus." Last updated 2026-07-03.

## TL;DR

External validators cannot join yet. Consensus ordering (validator rings,
block DAG) is owned by the `suwappu-dag` repository — this repo is the
transfer/attestation/anchor layer, and everything consensus-shaped here
runs in-process for tests. What outsiders *can* run today is a
commitment/gateway node (see [`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md)).
The plan mirrors how Tempo and Arc launched: full nodes first, a small
permissioned validator set next, permissionless later.

## Where the pieces live

| Concern | Owner | Status |
|---|---|---|
| Validator rings, block ordering, certificate DAG | `suwappu-dag` (private) | External to this repo |
| State substrate, state roots, execution | `suwappu-db` (private) | External to this repo |
| 7-of-9 corridor attestation (verify + wire format) | this repo, `src/ltp/corridor/` | Real crypto, wire-parity locked against the Rust reference |
| Threshold DKG + BLS committee signing | this repo, `src/ltp/execution/committee/` | Real cryptography, in-process transport only |
| Consensus engine adapter | this repo, `src/ltp/consensus/` | `LocalConsensusBackend` (in-process); networked backend not yet implemented |
| Commitment-node networking (gRPC, PQ handshake, gossip) | this repo, `src/ltp/node/` | Real, deployable today |
| Anchor-signer registration (`registerSigner`) | this repo, `contracts/` | Deployed; governance-gated (MultiSig → Timelock) |

## Phase 0 — external full/commitment nodes (near-term)

Prerequisites, all in this repo or infra:

- [ ] Public RPC endpoint for SUWAPPU Testnet (current endpoint is
      internal-only)
- [ ] Published genesis/config packet (chain ID `103115120`, bootstrap
      peer list) for `etp-node` operators
- [x] Operator documentation ([`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md),
      [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md))
- [x] Node monitoring dashboards (`deploy/observability/`)

## Phase 1 — permissioned external validators

Gated on `suwappu-dag` (consensus join is not implementable from this
repo):

- [ ] Networked consensus backend (the `GrpcConsensusBackend` successor to
      `LocalConsensusBackend` — see `src/ltp/consensus/backend.py`)
- [ ] Networked DKG transport (today only the in-memory
      `FakeDKGTransport` exists; a real dealer↔participant share
      exchange is required)
- [ ] Validator state-sync / snapshot bootstrap for late joiners
- [ ] Genesis + validator-set distribution artifact

In this repo (tractable now):

- [x] Hardened corridor roster loading — `ltp.corridor.load_corridor_roster`
      validates structure and enforces Proof-of-Possession by default
      (LTP-A-015); template at `config/corridor-roster.template.json`
- [ ] Wire roster loading into node/gateway startup configuration
- [ ] Register each corridor witness's anchor-signer `vkHash` via the
      governance path (`registerSigner`: MultiSig propose → Timelock →
      execute; see [`DEPLOYED_CONTRACTS.md`](DEPLOYED_CONTRACTS.md))
- [ ] Live anchor submitter wiring (the corridor→anchor build exists in
      `src/ltp/corridor/submission.py`; the on-chain signature is owned
      by the chain-key custody surface)
- [ ] Validator onboarding runbook: key ceremony (BLS keypair + PoP),
      roster distribution, and rotation procedure
- [ ] Consensus/DKG health dashboards alongside the existing node
      dashboards

## Phase 2 — permissionless validators (later)

- [ ] On-chain (or equivalently auditable) validator/corridor registry
      with selection and rotation rules, replacing hand-distributed
      rosters
- [ ] Stake/bond or allowlist policy decision
- [ ] Published slashing/misbehavior policy (evidence surface exists in
      `src/ltp/evidence.py`)

## Security invariants for any external membership

1. **PoP is mandatory.** Never install a roster member without a verified
   Proof-of-Possession (`load_corridor_roster` enforces this by default;
   do not use `require_pop=False` outside tests).
2. **Roster is the root of trust.** Whoever controls the roster file
   controls which attestations a node accepts — distribute it through an
   authenticated channel and pin it in config management.
3. **Anchor-signer registration stays governance-gated.** `registerSigner`
   is intentionally admin/Timelock-only; permissionless registration is a
   Phase 2 design decision, not a default.
