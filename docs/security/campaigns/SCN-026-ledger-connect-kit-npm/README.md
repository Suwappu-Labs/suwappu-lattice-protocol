# SCN-026 — Ledger Connect Kit npm supply-chain compromise

**Status.** VERIFIED-GREEN. LTP has zero JS/npm consumer surface; Docker base images digest-pinned.
**Layer.** 6 — Frontend / supply chain (npm + container layer).
**Historical incident.** Ledger Connect Kit, 14 Dec 2023, ~\$610k.
**LTP-A-* link.** [LTP-A-026](../../../SECURITY_AUDIT_2026-05-15.md)
(Docker base image not digest-pinned — REMEDIATED in audit).

## What happened (Ledger Connect Kit)

Ledger's Connect Kit npm package (`@ledgerhq/connect-kit-loader`)
was a popular dApp library. The package's npm publish account
belonged to a former Ledger employee. Attackers phished that
employee's credentials and published a malicious version
(`1.1.5` was clean; `1.1.6`, `1.1.7`, `1.1.8` were compromised).
The malicious version included a wallet-drainer payload.

Because npm pulls "latest" by default unless an exact version
is pinned, MANY dApps that depended on Connect Kit silently
pulled the compromised version. ~\$610k drained across multiple
dApps before Ledger noticed and pulled the package.

Root primitive: **TWO defenses failed simultaneously**:

1. **npm publish-credential security** — the publish account
   wasn't on hardware-token MFA, the employee was no longer at
   Ledger, the account hadn't been audited.
2. **Consumer pinning** — most dApps had `^1.1.5` or
   `~1.1.5`-style version specifiers, which auto-pulled the
   compromised release.

Either defense alone would have stopped this. The combination
failed.

## LTP analogue

LTP has **no npm/JS consumer surface at all today**:

```bash
$ find . -name "package.json" -not -path "*/node_modules/*" \
                              -not -path "*/lib/*"
# (no matches outside vendored dependencies)
```

The closest equivalent attack surface is the Docker base image
chain for the gateway VM. LTP's defense:

| ID | Defense | Source |
|----|---------|--------|
| LK1 | All Dockerfile `FROM` lines digest-pinned (`@sha256:...`) per LTP-A-026 | `deploy/Dockerfile`, `deploy/Dockerfile.gateway` |
| LK2 | GitHub Actions SHA-pinned per LTP-A-025 | `.github/workflows/*.yml` |
| LK3 | Contract submodules pinned to specific commits | `.gitmodules` |
| LK4 | Python dependencies pinned via `pyproject.toml` with `==` exact versions in production extras | `pyproject.toml` |
| LK5 | `make audit` runs `pip-audit` against installed dependencies for known CVEs | `Makefile`; runs in CI |

If LTP ever adds a dApp client library (JS or any other npm-
distributed package), the recommended additions:

| ID | Future policy |
|----|--------------|
| LK6 | Publish account on hardware-token MFA, separate from other GSX accounts |
| LK7 | npm provenance signatures on every release |
| LK8 | Integrators MUST use exact-version pinning (no `^` or `~` ranges); shipped as a hard documented requirement |
| LK9 | Subresource Integrity (SRI) hashes published alongside the package |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None new.** | The defenses are configuration-as-code, validated by inspection and existing CI (`pip-audit` runs every PR). | `deploy/Dockerfile*`, `.github/workflows/*.yml`, `pyproject.toml` |

## Verification commands

```bash
# LK1: every Docker FROM is digest-pinned
grep -E "^FROM " deploy/Dockerfile* | grep -v "@sha256:"
# Expected: no matches (every FROM HAS @sha256:)

# LK2: every Action use is SHA-pinned
grep -nE "uses: [^@]+@[^@\s]+" .github/workflows/*.yml \
  | grep -v -E "@[a-f0-9]{40}"
# Expected: no matches

# LK3: submodules at specific commits
git submodule status

# LK4: Python deps pinned (production extras)
grep -A 30 'production = \[' pyproject.toml
```

## Cross-references

- **LTP-A-025** — SHA-pinned actions (closed by previous audit work)
- **LTP-A-026** — Docker digest pinning (closed by previous audit work)
- **SCN-023, SCN-025** — frontend-tier attacks at DNS and CDN
  layers; complementary to this npm-layer attack
- **SCN-024** (Vyper compiler) — sibling toolchain-integrity
  scenario

## Findings opened

None. Toolchain pinning pre-exists across all relevant layers.
