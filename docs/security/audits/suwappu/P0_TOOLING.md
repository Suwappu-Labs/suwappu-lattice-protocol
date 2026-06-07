# P0 — Tooling hardening (status)

Date: 2026-06-07 · Branch: `feat/v7-testnet-upgrade`

## Baseline (before)
Only `forge`/`cast`/`anvil` 1.7.1 were installed. Slither/Echidna/Medusa/Halmos/Aderyn/Semgrep/solhint/solc all absent. `make contracts-secaudit`'s slither+solhint steps were `continue-on-error` (non-blocking) AND the binaries were missing, so the "security suite" was effectively just `forge test`.

## Installed + verified working
| Tool | Version | How | Smoke test |
|---|---|---|---|
| Foundry (forge/cast/anvil) | 1.7.1 | pre-existing | `forge build` green |
| solc | 0.8.24 | `solc-select install 0.8.24` | `solc --version` OK |
| Slither | latest | `pip3 install --user slither-analyzer` | ran on `SuwappuMintAdapter.sol` via forge compile, 90 detectors, 2 findings |
| Halmos | 0.1.13 | `pip3 install --user halmos` | `halmos --version` OK |
| Semgrep | latest | `pip3 install --user semgrep` | on PATH |

PATH note: pip `--user` scripts live in `~/Library/Python/3.9/bin` — export it in CI/shell.

## Still to install (P0 remainder)
- **Echidna**, **Medusa** — need prebuilt macOS binaries (no `brew` on this host) or the trailofbits docker image. Pending.
- **Aderyn** — `cargo install aderyn` (or npm). Pending.
- **solhint** — `npm i -g solhint`. Pending.

## Config changes applied
- `contracts/foundry.toml`: added `[invariant]` block — `runs=512, depth=100, fail_on_revert=false, shrink_run_limit=5000`. Verified: existing `OptimisticBridgeChallenge.invariant.t.sol` suite passes at this depth (5/5, 51200 calls each); new `SuwappuSupply` suite fails as designed (see P1).

## Still to wire (P0 remainder)
- Fold Echidna into `make contracts-secaudit`.
- Flip Slither/solhint to **blocking** (remove `continue-on-error`) once high-severity findings are triaged to zero (gate criterion 3).
- via_ir caveat confirmed: Slither drives `forge build` (via_ir) successfully; no special flags needed beyond the OZ remapping.
