# SCN-024 — Test evidence

## Configuration-as-code verification

| ID | Defense | Verification |
|---|---|---|
| V1 | Solidity version pin | `grep -n "pragma solidity" contracts/src/*.sol` — all `^0.8.24` |
| V2 | GitHub Actions SHA-pin | `grep -E "uses: [^@]+@[a-f0-9]{40}" .github/workflows/*.yml` |
| V3 | Docker digest-pin | `grep "@sha256:" deploy/Dockerfile*` |
| V4 | Submodule commit pin | `git submodule status` shows specific commit hashes |
| V5 | Static + dynamic CI | `make contracts-secaudit` runs Slither + solhint + Foundry invariants on every PR |

## Adjacent test coverage

The reentrancy property itself is pinned by SCN-005 (Penpie)
plus the existing
`contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`
invariant suite. If a future compiler upgrade ever shipped a
Curve-Vyper-style broken guard, those invariants would catch
the bytecode-level failure.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/audits/threat-intel/SCN-024-curve-vyper-compiler/` |
