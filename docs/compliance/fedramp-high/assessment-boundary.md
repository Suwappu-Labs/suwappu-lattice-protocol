# Assessment Boundary

## Repository Responsibilities

| Repository | Assessment responsibility |
|---|---|
| `suwappu-lattice-protocol` | transfer lifecycle, lattice keys, gateway VM, audit events, KMS/HSM hooks, mTLS hooks, anchor registry |
| `suwappu-dag` | Mysticeti-style ordering, validator consensus, LTP corridor attestation, execution adapter |
| `suwappu-db` | state mutation, canonical state roots, dual EVM/Move projections, recovery, L2 sync |

LTP must not claim embedded `suwappu-dag` validator consensus or embedded `suwappu-db`
state mutation behavior. Cross-repo release evidence must cite exact commits
or tags for all three repositories.

## Cross-Repo Evidence Required

| Evidence | Source repo | Required command |
|---|---|---|
| LTP local tests | `suwappu-lattice-protocol` | `python3 -m pytest tests/ -q` |
| LTP contracts | `suwappu-lattice-protocol` | `cd contracts && forge test -vvv` |
| LTP simulator | `suwappu-lattice-protocol` | `python3 -m src.simulator.ci_harness --seeds 42,123,777 --steps 500 --fault-rate 0.1` |
| DAG workspace tests | `suwappu-dag` | `cargo test --workspace` |
| DAG release property run | `suwappu-dag` | `PROPTEST_CASES=10000 cargo test --workspace --release` |
| DB workspace tests | `suwappu-db` | `cargo test --workspace` |
| DB lane separation | `suwappu-db` | `scripts/check-lane-separation.sh` |
| DB cross parity | `suwappu-db` | `scripts/cross-parity.sh` |
| DB release property run | `suwappu-db` | `PROPTEST_CASES=10000 cargo test --workspace --release` |

## Government Readiness Status

Current status is readiness-only. The repo contains technical gates and
evidence templates, but the deployment still needs:

- agency sponsor and authorization path
- official FedRAMP SSP/SAP/SAR package
- 3PAO assessment results
- POA&M owner and remediation dates
- continuous monitoring procedures
- cloud boundary diagrams for the actual environment
- KMS/HSM validation evidence for the deployed module boundary
