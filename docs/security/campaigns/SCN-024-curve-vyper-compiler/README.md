# SCN-024 — Curve Vyper compiler reentrancy

**Status.** VERIFIED-GREEN. LTP uses Solidity, not Vyper; compiler version is pinned.
**Layer.** 6 — Frontend / supply chain (toolchain).
**Historical incident.** Curve Finance, 30 Jul 2023, ~\$73M.
**LTP-A-* link.** [LTP-A-025](../../../SECURITY_AUDIT_2026-05-15.md)
(SHA-pinned GitHub Actions) is adjacent — same "toolchain
hardening" class.

## What happened (Curve / Vyper)

The Vyper compiler versions 0.2.15, 0.2.16, and 0.3.0 shipped
with a defective reentrancy guard. The `@nonreentrant` decorator
emitted bytecode that failed to revert on re-entry under certain
conditions. Several Curve pools compiled with those versions
were drained via reentrancy attacks. ~\$73M cumulative.

Root primitive: **the COMPILER produced bytecode that didn't
match the source-level semantics**. Auditors who read the
source saw a reentrancy guard; the bytecode didn't enforce it.

The defense class is **toolchain integrity**:

1. Pin compiler versions.
2. Read the compiler's CHANGELOG and known-bug list before
   upgrading.
3. Differential testing: deploy the same source to two compiler
   versions and assert identical behavior on a battery of
   adversarial inputs.

## LTP analogue

LTP uses Solidity (not Vyper), so the specific Vyper bug doesn't
apply. The general toolchain-hardening class does. LTP's
defenses:

| ID | Defense | Source |
|----|---------|--------|
| V1 | Solidity compiler version pinned via `foundry.toml` and `pragma solidity ^0.8.24` | `contracts/foundry.toml`, top-of-file pragmas |
| V2 | GitHub Actions SHA-pinned to specific commits (not floating major-version tags) | `.github/workflows/contracts.yml` per LTP-A-025 |
| V3 | Docker base images digest-pinned (Python 3.12 slim-bookworm at sha256:d193c6f5...) per LTP-A-026 | `deploy/Dockerfile*` |
| V4 | All contract dependencies pinned via submodules at specific commits (forge-std, openzeppelin-contracts) | `.gitmodules` |
| V5 | `make contracts-secaudit` runs Slither + solhint on every CI run — would catch obvious reentrancy patterns even with broken compiler-level guards | `Makefile` |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None new.** | The defenses are configuration-as-code, validated by inspection and by the existing CI pipeline. | `contracts/foundry.toml`, `deploy/Dockerfile`, `.github/workflows/*.yml` |

## Verification commands

```bash
# V1: Solidity version pin
grep -n "solc_version\|pragma solidity" contracts/foundry.toml contracts/src/*.sol | head

# V2: GitHub Actions SHA-pin
# Every `uses:` should have a 40-char SHA + a comment with the version
grep -nE "uses: [^@]+@[a-f0-9]{40}" .github/workflows/*.yml | wc -l

# V3: Docker digest pin
# Every FROM line should have @sha256:...
grep -E "^FROM " deploy/Dockerfile* | grep -E "@sha256:"
```

## Cross-references

- **SCN-005** (Penpie reentrancy) — pins LTP's own
  reentrancy-guard correctness via Foundry invariants. Even
  if the compiler shipped a Curve-Vyper-style bug, LTP's
  reentrancy invariants would surface it.
- **LTP-A-025** — SHA-pinned actions
- **LTP-A-026** — Docker digest pinning

## Findings opened

None. Toolchain-hardening defenses pre-exist.
