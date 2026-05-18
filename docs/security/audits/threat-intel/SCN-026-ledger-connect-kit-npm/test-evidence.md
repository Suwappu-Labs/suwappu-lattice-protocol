# SCN-026 — Test evidence

## Configuration-as-code verification

| ID | Defense | Verification |
|---|---|---|
| LK1 | Docker FROM digest-pinned | `grep "@sha256:" deploy/Dockerfile*` — both files match |
| LK2 | GitHub Actions SHA-pinned | every `uses:` in `.github/workflows/*.yml` has 40-char SHA |
| LK3 | Submodules at specific commits | `git submodule status` returns specific commit hashes |
| LK4 | Python prod deps pinned | `pyproject.toml` `[project.optional-dependencies] production` block |
| LK5 | `make audit` runs pip-audit in CI | already runs on every PR (ETP CI / "Dependency vulnerability audit" job) |

## Adjacent CI coverage

`make audit` runs `pip-audit --strict --vulnerability-service osv`
against the installed dependencies on every PR. This catches
known CVEs in published packages — the SECONDARY defense after
version pinning.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/audits/threat-intel/SCN-026-ledger-connect-kit-npm/` |
| LK6-LK9 future-publisher policies | drafted in README | will activate when LTP first publishes an npm package |
