# CLAUDE.md — suwappu-lattice-protocol

Project-level guidance for Claude Code sessions in this repo. Last updated
2026-05-16. Pin against this date if behavior diverges from what's described.

## What this repo is

The **Lattice Transfer Protocol** (LTP) — post-quantum cryptographic data
transfer with on-chain anchors. Three independently-versioned surfaces:
Python SDK (`src/ltp/`), Solidity registry (`contracts/`), and corridor
wire format (`LTP-corridor-v1`). All three must remain mutually compatible
across deploys — see [`docs/STABILITY_PROMISES.md`](docs/STABILITY_PROMISES.md).

## Where things live

| Area | Path |
|---|---|
| Python SDK | `src/ltp/` |
| Solidity contracts | `contracts/` |
| Tests (Python) | `tests/` |
| Tests (Solidity) | `contracts/test/` |
| Deployed-contract record | `docs/DEPLOYED_CONTRACTS.md` |
| Operator runbook | `docs/OPERATOR_RUNBOOK.md` |
| Persona docs | `docs/personas/` |
| Compliance evidence | `docs/compliance/fedramp-high/` |

## How to verify a change

```bash
make test-python           # ~1,200 Python tests
make test-contracts        # 84 Solidity tests via forge
make contracts-secaudit    # Slither + Echidna + invariants (slow)
make docs-api              # regenerate Python API reference (3.10–3.13)
```

A docs-only change still needs `make docs-api` to succeed (it gates the CI).

## Dev tooling

- Developer command surface lives in `Justfile` at the repo root. Run
  `just` (no args) for the menu. The Justfile delegates test/audit/docs
  targets to `Makefile` so CI parity is unbreakable.
- Pre-commit is now mandatory: `pre-commit install` runs automatically
  in the devcontainer and via `just setup`. The hard rule
  "No `--no-verify` or hook bypasses" has teeth as of Track 2.
- For full onboarding (devcontainer, hook list, mypy scope), see
  [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## Hard rules

These come from prior audits and repo conventions; violating them gets a PR
rejected:

- **No `Co-Authored-By` footers in commits.** Repo convention.
- **No `git rebase` on shared branches.** Use `git merge` or
  `git pull --no-rebase`. Consensus / audit tests are commit-topology
  sensitive.
- **No `--no-verify` or hook bypasses** without explicit instruction.
- **SHA-pin every new GitHub Action** by commit SHA, not tag (audit
  finding LTP-A-025).
- **Never change a deployed-contract address** in
  `docs/DEPLOYED_CONTRACTS.md` without an upgrade plan under `plans/`.
  CODEOWNERS routes contract changes to the work account.
- **`make contracts-secaudit` must be green** before suggesting any
  change under `contracts/`.
- **License field in `pyproject.toml`** — do NOT touch. Resolution is
  pending in Linear GLO-785.

## Common gotchas

- The package's `__init__.py` asserts real PQ-crypto backends are
  installed. `python3 -c "import ltp"` fails on a stock interpreter; run
  `pip install -e '.[production]'` first or work inside a venv that has
  `pqcrypto` and `pynacl`.
- BLS DST strings must be byte-identical across Python and Solidity. No
  Unicode normalization, no trim. See LTP-A-022.
- `LTP_ENV=production` triggers fail-closed paths; don't override to make
  a test pass.
- Mac with Python 3.14 has a `pdoc` ForwardRef incompatibility — most
  submodules get skipped. Use 3.10–3.13 locally; CI pins 3.12.

## Linear / project tracking

- Workspace: `suwappu`
- Team: **Suwappu** (key `GLO`)
- Project: **LTP Dev Net** (most LTP work)
- Open audit-related tracking issues: GLO-785 (license), GLO-786 (GitBook).

## How to read the docs

- Start at [`docs/README.md`](docs/README.md) — persona-routed landing.
- For broad protocol questions:
  [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md) →
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) →
  [`docs/FORMAL_VERIFICATION_STATUS.md`](docs/FORMAL_VERIFICATION_STATUS.md).
- For operational questions:
  [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) →
  [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md).
- For agent-specific guidance:
  [`docs/AI_AGENTS.md`](docs/AI_AGENTS.md).

This file is shorter than `docs/AI_AGENTS.md` on purpose — that file has
the full agent guide; this file is the in-IDE quick reference.
