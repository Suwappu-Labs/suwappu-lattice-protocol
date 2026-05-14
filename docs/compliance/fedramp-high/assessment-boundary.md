# Assessment Boundary

## Repository Responsibilities

| Repository | Assessment responsibility |
|---|---|
| `gsx-lattice-protocol` | transfer lifecycle, lattice keys, gateway VM, audit events, KMS/HSM hooks, mTLS hooks, anchor registry |
| `gsx-dag` | Mysticeti-style ordering, validator consensus, LTP corridor attestation, execution adapter |
| `gsx-db` | state mutation, canonical state roots, dual EVM/Move projections, recovery, L2 sync |

LTP must not claim embedded `gsx-dag` validator consensus or embedded `gsx-db`
state mutation behavior. Cross-repo release evidence must cite exact commits
or tags for all three repositories.

## Cross-Repo Evidence Required

| Evidence | Source repo | Required command |
|---|---|---|
| LTP local tests | `gsx-lattice-protocol` | `python3 -m pytest tests/ -q` |
| LTP contracts | `gsx-lattice-protocol` | `cd contracts && forge test -vvv` |
| LTP simulator | `gsx-lattice-protocol` | `python3 -m src.simulator.ci_harness --seeds 42,123,777 --steps 500 --fault-rate 0.1` |
| DAG workspace tests | `gsx-dag` | `cargo test --workspace` |
| DAG release property run | `gsx-dag` | `PROPTEST_CASES=10000 cargo test --workspace --release` |
| DB workspace tests | `gsx-db` | `cargo test --workspace` |
| DB lane separation | `gsx-db` | `scripts/check-lane-separation.sh` |
| DB cross parity | `gsx-db` | `scripts/cross-parity.sh` |
| DB release property run | `gsx-db` | `PROPTEST_CASES=10000 cargo test --workspace --release` |

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
