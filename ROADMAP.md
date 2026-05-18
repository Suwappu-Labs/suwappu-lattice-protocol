# Roadmap

`gsx-lattice-protocol` is the **Lattice Transfer Protocol** — the
constant-size, post-quantum-conservative cross-chain attestation layer
that bridges chains together under the Global Settlement Network. It is
the bridge/gateway tier sitting above the
[`gsx-dag`](https://github.com/GlobalSettlementNetwork/gsx-dag) L1.

See [`CHANGELOG.md`](./CHANGELOG.md) for the shipped versions and the
[GSX LTP academic paper](https://github.com/GlobalSettlementNetwork/gsx-papers/blob/main/papers/ltp/gsx_ltp_academic_v7.pdf)
for the formal specification.

---

## Phases

| Phase | Window | Headline | Status |
|---|---|---|---|
| **0** | Q1 2026 | Paper v7 ratified — constant-size (~1,600 B) commitment design closed | ✅ |
| **1** | Q1–Q2 2026 | Reference impl: super-node 7-of-9 attestation, ML-KEM-768 + BLS aggregate, DA SLA | ✅ |
| **2** | Q2 2026 | Gateway service — `deploy/run_gateway.sh`, docker compose + helm, preflight checks | ✅ |
| **3** | Q3 2026 | Multi-chain corridor expansion — onboard the second + third source chains | 🟡 In flight |
| **4** | Q3 2026 | DA non-availability slashing surface — substrate-side `Intent::SlashLTPProvider` follow-on | ⏳ Next |
| **5** | Q4 2026 | Cross-DID STARK pipeline closure (SP1 / Plonky3 integration with `gsx-dag` precompile) | ⏳ |
| **GA** | aligned with gsx-dag mainnet (M18–M24) | `gsx-lattice-protocol` v1.0 cut against mainnet genesis | ⏳ |

---

## Connection to the L1 roadmap

The LTP cadence is keyed to the L1's bridge readiness:

- LTP reference impl + gateway → consumed by `gsx-dag` Phase 4
  (devnet) and Phase 5 (testnet) to clear the cross-chain attestation
  surface.
- LTP DA-slashing → unblocks the substrate-side
  `Intent::SlashLTPProvider` in `gsx-dag` (planned for v0.4.x).
- LTP `v1.0` → cut against `gsx-dag` mainnet genesis.

See the
[`gsx-dag` ROADMAP](https://github.com/GlobalSettlementNetwork/gsx-dag/blob/main/ROADMAP.md)
for the full mainnet plan.

---

## How to contribute

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — dev workflow.
- [`SECURITY.md`](./SECURITY.md) — coordinated disclosure (don't open
  public issues for vulnerabilities).
- [`deploy/run_gateway.sh`](./deploy/run_gateway.sh) — gateway deploy
  orchestration; preflight checks gate the apply.
