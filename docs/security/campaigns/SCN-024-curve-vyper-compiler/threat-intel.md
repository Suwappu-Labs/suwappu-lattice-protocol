# SCN-024 — Threat intelligence sources

Historical incident: **Curve / Vyper compiler reentrancy exploit, 30 July 2023, ~\$73M.**

## Primary sources

- **Vyper team post-mortem** — published on the project's
  HackMD in July 2023 with follow-on technical writeups.
  (Original HackMD URL has moved; search "Vyper compiler
  reentrancy guard post-mortem 2023" for the current
  location.)
- **Curve team statements** during and after the incident.
- **Patched Vyper releases** — 0.3.7 / 0.2.16 fixes.

## Secondary technical analyses

- **Ottersec** — detailed compiler-bytecode analysis.
- **ChainSecurity** — affected-pools analysis.
- **OpenZeppelin** — retrospective on toolchain-integrity
  practices.

## Root primitive

A trusted compiler emitted bytecode that didn't match the
source-level semantics. Auditors who read the source saw a
`@nonreentrant` guard; the bytecode didn't actually enforce it
on the affected versions.

Generalization: **any layer of the toolchain (compiler, linker,
build cache, CI pipeline, base image) can drift from
source-level intent**. The defense class is:

1. Pin versions across the entire toolchain.
2. Differential testing where feasible.
3. Run static-analysis (Slither, solhint) AND dynamic-testing
   (Foundry invariants, Echidna) — both layers would catch
   most compiler-mismatch bugs because the same property would
   fail at the bytecode level.

Related incidents:
- Several smaller Vyper / Solidity compiler-version bugs over
  the years (e.g., the Solidity 0.5.5 ABI-encoder bug).
- Ledger Connect Kit npm compromise (Dec 2023, SCN-026) —
  toolchain-tier supply chain at the JS layer.

## Mapping to LTP

LTP uses Solidity (not Vyper); the specific bug doesn't apply.
The general toolchain-hardening class is addressed by:
- Solidity pragma pin (^0.8.24)
- GitHub Actions SHA-pin (LTP-A-025)
- Docker base image digest-pin (LTP-A-026)
- All contract dependencies via git submodules at specific
  commits

The existing CI pipeline (`make contracts-secaudit` runs
Slither + solhint + Foundry invariants) would surface most
compiler-mismatch bugs via the dynamic-test layer.

## Date of last verification

2026-05-17 — SCN-024 added under R-4.
