# FedRAMP High Readiness Package

This package is the `suwappu-lattice-protocol` evidence overlay for a FedRAMP High
readiness review. It is not an authorization package, an agency sponsorship, a
3PAO assessment, or an ATO. A production authorization still requires the
official SSP, SAP, SAR, POA&M, continuous monitoring process, agency review,
and assessment evidence for the actual deployed cloud service offering.

## Profile Gate

Set the government deployment profile explicitly:

```bash
ETP_DEPLOYMENT_PROFILE=fedramp-high
```

In this profile `deploy/preflight_gateway.py` fails closed when it sees any of
these conditions:

- real crypto is not explicitly enabled
- mock, simulated, disabled, dev, or test bridge/prover modes are configured
- plaintext operator private keys are present in environment variables
- KMS/HSM key references are absent
- mTLS is absent or client certs are not required
- SIEM/audit export is absent
- local, placeholder, devnet, or known public testnet RPC endpoints are used
- source/destination chain IDs are unset or known dev/test chain IDs

Use `config/fedramp-high.env.template` as the starting point for deployment
environment variables.

## Package Contents

- `system-boundary.md`: LTP component boundary and external dependencies.
- `data-flow.md`: data flow, audit flow, and trust-boundary transitions.
- `trust-boundary.md`: trust zones and fail-closed expectations.
- `assessment-boundary.md`: cross-repo boundary across LTP, `suwappu-dag`, and `suwappu-db`.
- `control-matrix.md`: NIST SP 800-53 Rev. 5 High readiness crosswalk for repo evidence.
- `ssp-narratives.md`: SSP-style implementation narratives.
- `release-evidence.md`: release evidence and exact commit/tag requirements.
- `evidence-manifest.json`: machine-checkable local evidence manifest.

## Verification Commands

Local LTP gates:

```bash
python3 -m pytest tests/ -q
cd contracts && forge test -vvv
python3 -m src.simulator.ci_harness --seeds 42,123,777 --steps 500 --fault-rate 0.1
```

Cross-repo release gates:

```bash
cd ../suwappu-dag && cargo test --workspace
cd ../suwappu-dag && PROPTEST_CASES=10000 cargo test --workspace --release
cd ../suwappu-db && cargo test --workspace
cd ../suwappu-db && scripts/check-lane-separation.sh
cd ../suwappu-db && scripts/cross-parity.sh
cd ../suwappu-db && PROPTEST_CASES=10000 cargo test --workspace --release
```

## References

- FedRAMP Rev. 5 SSP guidance: https://www.fedramp.gov/docs/rev5/playbook/csp/authorization/ssp/
- FedRAMP control baseline guidance: https://www.fedramp.gov/preview/2026/providers/rev5/controls/
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/Pubs/sp/800/53/r5/upd1/Final
- FIPS 202 SHA-3: https://csrc.nist.gov/publications/detail/fips/202/final
- FIPS 203 ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
