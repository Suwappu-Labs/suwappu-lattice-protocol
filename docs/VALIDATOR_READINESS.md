# Validator Readiness — SUWAPPU Testnet

Status of the path from "team-operated testnet" to "external validators
participate in consensus." Last updated 2026-07-03, after a joint audit
of this repo and `suwappu-dag` @ `cc09a78`.

## TL;DR

External validators cannot join self-service yet, but the foundation is
further along than this repo alone suggests: `suwappu-dag` runs **real
multi-machine, cross-region TCP Mysticeti-C consensus today** among a
fixed, pre-configured validator set (the consensus code in this repo's
`src/ltp/consensus/` is an in-process mirror for the execution pipeline,
not the production engine). What blocks external joining is not the
consensus core — it is dynamic membership: static peer configuration,
no state sync for late joiners, hand-assembled genesis keys with no DKG
or Proof-of-Possession on the Rust side, and unauthenticated wire
identity. The plan mirrors how Tempo and Arc launched: full nodes first,
a small permissioned validator set next, permissionless later.

## Where the pieces live

| Concern | Owner | Status |
|---|---|---|
| Validator rings, block ordering, certificate DAG | `suwappu-dag` (`crates/suwappu-node`, `suwappu-consensus`) | **Real TCP wire** (`wire.rs`), multi-machine cross-region verified; static peer set |
| DAG gap-fill sync (`GetCert` parent pull) | `suwappu-dag` | Works for recent gaps; is **not** a state-sync mechanism |
| State substrate, state roots, execution | `suwappu-db` (private) + `suwappu-dag` in-memory substrate | Consensus nodes currently run an in-memory substrate — no persistence, no snapshot |
| 7-of-9 corridor attestation (verify + wire format) | both repos (`src/ltp/corridor/` ↔ `crates/suwappu-ltp`) | Real crypto both sides; **wire divergence: Rust `SuperNode` has no `pop` field** (see gap 4) |
| Threshold DKG + BLS committee signing | this repo only (`src/ltp/execution/committee/`) | Real cryptography, in-process transport; **no Rust counterpart exists** |
| Consensus engine adapter (Python) | this repo, `src/ltp/consensus/` | In-process mirror of the Rust engine, for the execution pipeline and tests |
| Commitment-node networking (gRPC, PQ handshake, gossip) | this repo, `src/ltp/node/` | Real, deployable today |
| Anchor-signer registration (`registerSigner`) | this repo, `contracts/` | Deployed; governance-gated (MultiSig → Timelock) |
| Validator governance intents (admit / exit / eject) | `suwappu-dag` | Exists, epoch-boundary applied; foundation-submitted only (phase G2: static ring + manual coordination) |

## Phase 0 — external full/commitment nodes (near-term)

Prerequisites, all in this repo or infra:

- [ ] Public RPC endpoint for SUWAPPU Testnet (current endpoint is
      internal-only; `suwappu-dag`'s public devnet RPC/faucet/explorer
      gates are terraform-drafted but not deployed)
- [ ] Published genesis/config packet (chain ID `103115120`, bootstrap
      peer list) for `etp-node` operators
- [x] Operator documentation ([`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md),
      [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md))
- [x] Node monitoring dashboards (`deploy/observability/`)

## Phase 1 — permissioned external validators

Gated on `suwappu-dag` (in its own priority order):

- [ ] **Dynamic peer admission.** The peer set is fixed at boot
      (`wire.rs` static peer map) and inbound connections from unknown
      peers are dropped — admitting a validator today means editing every
      seed's `node.toml` and restarting it, even though the
      `AdmitAuthority` governance intent already applies cleanly at epoch
      boundaries. Hot peer-map reload (or governance-driven peer
      updates) is the single highest-leverage gap.
- [ ] **State sync.** A late joiner starts with an empty DAG store and
      fresh in-memory substrate; recursive parent-pull fills recent gaps
      but cannot replay committed state from genesis or transfer a state
      root. Needs snapshot/checkpoint sync (persistence first).
- [ ] **Wire-level peer authentication.** Peer identity is a
      self-asserted hello string over plain TCP; mutual ML-DSA on the
      wire is tracked for mainnet but matters as soon as peers are not
      all foundation-operated.
- [ ] **Networked DKG (or an explicit decision to keep per-operator
      keygen).** Rust has no DKG; corridor/committee keys are minted
      individually (`suwappu-keygen`) and hand-pasted into
      `genesis.toml`. The Python DKG ceremony
      (`src/ltp/execution/committee/`) has no networked transport and no
      Rust counterpart.

In this repo (tractable now):

- [x] Hardened corridor roster loading — `ltp.corridor.load_corridor_roster`
      validates structure and enforces Proof-of-Possession by default
      (LTP-A-015); template at `config/corridor-roster.template.json`
- [ ] **Resolve the `SuperNode` wire divergence.** Rust
      `crates/suwappu-ltp` defines `SuperNode {authority, corridor,
      bls_public_key}` — no `pop` field and no PoP verification; this
      repo's wire format carries an optional `pop` and the roster loader
      requires it. Recommended: add `pop` to the Rust struct and verify
      at genesis load, so both sides enforce LTP-A-015. Until then,
      genesis-pinned keys are the only rogue-key defense on the Rust
      side.
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

Also worth noting: corridor attestations received without a genesis
`[[corridors]]` block are currently accepted **unverified** on the Rust
side (documented pre-S24 MVP behavior) — a testnet with external
validators must ship a corridor block in genesis from day one.

## Phase 2 — permissionless validators (later)

- [ ] On-chain (or equivalently auditable) validator/corridor registry
      with selection and rotation rules, replacing hand-distributed
      rosters (suwappu-dag governance phasing calls this G3,
      post-mainnet; stake is currently read from the genesis manifest,
      not bonded by the joiner)
- [ ] Stake/bond or allowlist policy decision
- [ ] Published slashing/misbehavior policy (evidence surface exists in
      `src/ltp/evidence.py`; `EjectAuthority` intent exists in
      suwappu-dag)

## Security invariants for any external membership

1. **PoP is mandatory.** Never install a roster member without a verified
   Proof-of-Possession (`load_corridor_roster` enforces this by default;
   do not use `require_pop=False` outside tests). The Rust side must
   grow the same check before external corridor membership.
2. **Roster is the root of trust.** Whoever controls the roster file
   controls which attestations a node accepts — distribute it through an
   authenticated channel and pin it in config management.
3. **Anchor-signer registration stays governance-gated.** `registerSigner`
   is intentionally admin/Timelock-only; permissionless registration is a
   Phase 2 design decision, not a default.
4. **No corridor without verification.** Never run a network where the
   corridor block is absent from genesis (unverified-attestation
   fallback).
