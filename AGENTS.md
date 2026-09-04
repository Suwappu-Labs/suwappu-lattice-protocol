# AGENTS.md

This file is the single source of truth for AI coding agents working in
this repository. `CLAUDE.md` and `.cursorrules` are symlinks to it, so every
tool reads the same text. Edit this file only.

Last verified against the tree: 2026-09-04. If a command or count here
disagrees with the repo, the repo wins. Fix this file in the same PR.

## Find it fast

| You want to… | Go to |
|---|---|
| Set up a working environment | [Environment setup](#environment-setup) |
| Run lint, tests, or docs checks | [Commands](#commands) |
| Know which directory owns what | [Repository structure](#repository-structure) |
| Know what you must never do | [Boundaries](#boundaries) |
| Change Solidity under `contracts/` | [Working in contracts/](#working-in-contracts) |
| Change Python under `src/ltp/` | [Working in srcltp](#working-in-srcltp) |
| Change docs under `docs/` or root `*.md` | [Working in docs/](#working-in-docs) |
| Change CI under `.github/workflows/` | [Working in .github/workflows/](#working-in-githubworkflows) |
| Open a commit or PR | [Commits and PRs](#commits-and-prs) |
| Avoid a known trap | [Known traps](#known-traps) |
| Report a regression you caused | [Reporting agent regressions](#reporting-agent-regressions) |
| Find the deeper docs | [References](#references) |

## What this repository is

The **Lattice Transfer Protocol** (LTP) moves data with post-quantum
cryptography and anchors it on-chain. It has three surfaces that are
versioned separately but must stay compatible with each other:

| Surface | Path | Versioning |
|---|---|---|
| Python SDK | `src/ltp/` | `pyproject.toml` (currently 3.0.0) |
| Solidity registry | `contracts/src/` | `version()` in `LTPAnchorRegistry.sol` |
| Corridor wire format | `docs/CORRIDOR_INTEGRATION.md` | `LTP-corridor-v1` |

The compatibility matrix lives in `docs/STABILITY_PROMISES.md`.

## Environment setup

Python 3.10 to 3.13. CI pins 3.12. Do not use 3.14 (see
[Known traps](#known-traps)).

```bash
python -m pip install -e ".[production,dev]"   # real PQ crypto + dev tools
pre-commit install                             # mandatory; `just setup` does both
```

`import ltp` asserts that real post-quantum backends (`pqcrypto`,
`pynacl`) are installed. A stock interpreter fails at import. Install the
`production` extra first.

Optional tools by lane:

| Tool | Needed for | Install |
|---|---|---|
| `just` | Developer menu (`just` with no args) | https://github.com/casey/just |
| `forge`, `anvil` | Solidity tests and integration tests | https://getfoundry.sh |
| `semgrep` | Project semgrep rules in `.semgrep/` | `pip install semgrep` |
| `slither`, `echidna` | `make contracts-secaudit` | see `docs/DEVELOPMENT.md` |
| Node 20+ | `solhint`, `markdownlint-cli2`, Mermaid checks | devcontainer ships it |

The devcontainer in `.devcontainer/` installs all of this. Full onboarding
is in `docs/DEVELOPMENT.md`.

## Commands

Use these exact commands. CI calls the same `Makefile` targets, so a green
local run predicts green CI. The `Justfile` wraps the `Makefile`; both are
fine.

```bash
# One entry point. Lanes: lint semgrep python fast contracts secaudit docs all
scripts/verify.sh            # all lanes (contracts only if forge is installed)
scripts/verify.sh fast       # fail-fast Python loop while iterating

# Lint and format
pre-commit run --all-files   # ruff, ruff-format, solhint, whitespace, YAML/TOML
ruff format . && ruff check --fix .
mypy                         # curated file list only; see pyproject [tool.mypy]
semgrep scan --config .semgrep/ --metrics=off --error src/ scripts/

# Tests
make test-python             # ~4,000 Python tests; skips tests/test_contract_integration.py
make test-python-fast        # same, -x -q
pytest tests/test_protocol.py -v                       # one file
pytest tests/test_protocol.py::TestCommitMaterialize::test_basic_transfer -v
make test-contracts          # ~340 Solidity test + invariant functions via forge
make test-integration        # starts anvil, deploys, runs Python <-> Solidity parity
make contracts-secaudit      # Slither + Echidna + invariants; slow; gate for contracts/

# Docs
make docs-api                # regenerates docs/api/python/; gates docs CI
npx markdownlint-cli2 'docs/**/*.md' '*.md'
lychee --config lychee.toml 'docs/**/*.md' '*.md'

# Housekeeping
make help                    # full Makefile target list
make abi                     # regenerate contracts/abi/*.json from contracts/out/
make audit                   # pip-audit against installed deps
```

Run scoped tests while you iterate. Run the full lane for the surface you
touched before you say "done".

## Repository structure

| Path | What lives there | Gate before merge |
|---|---|---|
| `src/ltp/` | Python SDK. Crypto core in `primitives.py`, `bls.py`, `hybrid.py`; corridor in `corridor/`; anchors in `anchor/` | `make test-python`, pre-commit, semgrep |
| `tests/` | Python tests. Sub-suites: `corridor/`, `security/`, `stress/`, `vectors/` | same |
| `contracts/src/` | Solidity: `LTPAnchorRegistry.sol`, `LTPMultiSig.sol`, `ETPGovernance.sol`, bridge contracts | `make contracts-secaudit` |
| `contracts/test/` | Foundry tests and invariants | `make test-contracts` |
| `contracts/script/` | Deploy and upgrade scripts (`UpgradeV4.s.sol` is the pattern) | secaudit + CODEOWNERS |
| `contracts/abi/` | Generated ABIs. Regenerate with `make abi`; never hand-edit | |
| `docs/` | All documentation. Start at `docs/README.md` | `make docs-api`, markdownlint, lychee |
| `docs/plans/` | Dated plans. Required for any deployed-address change | |
| `docs/api/python/` | Generated by pdoc. Do not hand-edit | |
| `docs/compliance/fedramp-high/` | Compliance evidence. CODEOWNERS-protected | |
| `docs/security/audits/` | Audit reports. Finding IDs look like `LTP-A-025` | |
| `.semgrep/` | Project rules: `api-validation`, `crypto-lane-separation`, `key-handling` | |
| `.github/workflows/` | CI. Every action is SHA-pinned | CODEOWNERS |
| `scripts/` | `verify.sh` and operator helpers | |
| `deploy/`, `infra/terraform/`, `infra/helm/` | Deployment. See `docs/DEPLOYMENT_GUIDE.md` | CODEOWNERS |
| `formal/`, `zkvm/`, `proto/` | Formal models, zkVM guest code, protobuf | |
| `examples/` | Runnable examples. `examples/quickstart.py` is the tutorial | |

`.github/CODEOWNERS` routes contracts, crypto core, corridor, anchors,
compliance docs, workflows, deploy, `Makefile`, and security docs to a
required reviewer. Expect review on those paths.

## Boundaries

These rules come from prior audits and repo convention. Breaking one gets
the PR rejected. Each carries its tracking ID so you can grep for it.

- **Never add `Co-Authored-By` footers** to commit messages. Repo
  convention. Strip them from generated messages.
- **Never `git rebase` a shared branch.** Use `git merge` or
  `git pull --no-rebase`. Consensus and audit tests are sensitive to
  commit topology.
- **Never bypass hooks.** No `--no-verify`, no `SKIP=`, unless the user
  says so in writing. Pre-commit is mandatory.
- **Always SHA-pin GitHub Actions and pre-commit hooks.** Pin by commit
  SHA, not tag. Audit finding LTP-A-025.
- **Never change a deployed contract address** in
  `docs/DEPLOYED_CONTRACTS.md` without an upgrade plan under
  `docs/plans/`. CODEOWNERS blocks it.
- **Never propose a change under `contracts/`** unless
  `make contracts-secaudit` is green on your branch.
- **Never touch the `license` field in `pyproject.toml`.** Resolution is
  pending in Linear GLO-785.
- **Never "clean up" a BLS domain-separation tag (DST) string.** It must
  be byte-identical in Python and Solidity. No Unicode normalization, no
  trim. Audit finding LTP-A-022.
- **Never set `LTP_ENV=development` to make a test pass.**
  `LTP_ENV=production` fails closed on purpose.
- **Never bump the wire format** (`LTP-corridor-v1` to `v2`) as a refactor.
  It needs a Linear ticket under the LTP Dev Net project first.
- **Never reopen a closed audit finding.** Check
  `docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md` before you
  change crypto, key handling, or deploy paths.
- **Never add a new third-party dependency to the core library** without
  asking. The PR checklist enforces this.

## Working in contracts/

1. Read `docs/CORRIDOR_INTEGRATION.md` for the on-chain ABI. Treat it as
   normative.
2. When you modify `LTPAnchorRegistry.sol`, bump the `version()` return
   value and update the test assertions for it.
3. Follow the upgrade-script pattern in `contracts/script/UpgradeV4.s.sol`.
4. Run `make test-contracts`, then `make contracts-secaudit`. Both must be
   green before you open the PR.
5. Run `make abi` if the ABI changed and commit the regenerated files.
6. After a deployment, verify on-chain state: version, admin, paused,
   threshold, EIP-1967 slot. The checklist is `docs/OPERATOR_RUNBOOK.md`
   section 13.

## Working in src/ltp/

- Use `logging`, never `print()`.
- Raise `ValueError` for input validation. Do not use `assert` for it.
- Add type annotations on every public API. The package ships `py.typed`.
- Use SHA3-256 on every settlement and on-chain path.
- Keep crypto lanes separate. The semgrep rule
  `.semgrep/crypto-lane-separation.yml` fails CI if you mix them.
- Follow existing patterns. Read the neighbouring module before you add
  one.
- `mypy` runs only on the curated `files` list in `pyproject.toml`. If
  you touch a listed file, keep it at zero errors.
- Python target is 3.12 for ruff, but the code must run on 3.10.

## Working in docs/

- A docs-only change still needs `make docs-api` to succeed. It gates CI.
- markdownlint enforces heading structure only: one H1 per file (MD025)
  and no skipped heading levels (MD001). Everything else is off.
- lychee requires every relative link to resolve. External 401/403 are
  accepted; internal 404s fail.
- Mermaid diagrams follow `docs/visuals/README.md`. CI validates them.
- Persona pages under `docs/personas/` route readers. Add new docs to the
  right persona and to `docs/SUMMARY.md`.
- Do not hand-edit `docs/api/python/`.

## Working in .github/workflows/

- Pin every `uses:` to a full commit SHA and add the tag as a trailing
  comment. Audit finding LTP-A-025.
- Every workflow calls `make` targets. Do not duplicate test logic in YAML.
- CODEOWNERS requires review on this path.

## Commits and PRs

Follow the same flow as human contributors in `CONTRIBUTING.md`.

- Branch from `main`. One fix or feature per PR.
- Commit messages explain the "why". No `Co-Authored-By` footer.
- Before you push, run `scripts/verify.sh` (or the lane for your surface).
- Fill in `.github/PULL_REQUEST_TEMPLATE.md`. Do not delete its sections.
- Keep diffs reviewable. Split mechanical changes from logic changes.
- Do not `@`-mention individuals in generated PR or issue text. CODEOWNERS
  assigns reviewers.
- Check for an existing PR on your branch before you open a new one.
- A merged PR is finished. Start follow-up work from `main`, not from the
  merged branch.

## Known traps

Traps that have cost time in this repo. Some were audit findings:

| Trap | What happens | Do this instead |
|---|---|---|
| Import on a stock interpreter | `import ltp` asserts on missing PQ backends | `pip install -e '.[production]'` |
| Normalizing the BLS DST | Python and Solidity signatures diverge (LTP-A-022) | Copy bytes exactly |
| Overriding `LTP_ENV` | Fail-closed paths silently open | Fix the test or the code |
| Python 3.14 + pdoc | `make docs-api` skips most submodules (ForwardRef bug) | Use 3.10 to 3.13 |
| Tag-pinned action | Audit re-finding LTP-A-025 | Pin the commit SHA |
| `git rebase` on a shared branch | Topology-sensitive tests break | `git merge` |
| Editing `docs/api/python/` or `contracts/abi/` by hand | Next regeneration overwrites it | Run `make docs-api` or `make abi` |
| Running `pytest tests/` including integration | Needs a live anvil | `make test-python` skips it; `make test-integration` runs it |
| Stale test counts in docs | Reviewers lose trust | Count with `grep -rE 'def test_' tests/ \| wc -l` |

## Reporting agent regressions

If an agent-suggested change breaks a test, reopens an audit finding, or
breaks a deploy, file a Linear issue:

| Field | Value |
|---|---|
| Workspace | `suwappu` |
| Team | Suwappu (key `GLO`) |
| Project | LTP Dev Net |
| Label | `agent-regression` |
| Include | Link to the commit and the failing check |

Open tracking issues: GLO-785 (license field), GLO-786 (GitBook).

## References

Read in this order for a non-trivial change:

1. `CONTRIBUTING.md` — prerequisites, test commands, PR workflow.
2. `docs/DEVELOPMENT.md` — devcontainer, hook list, mypy scope, tool
   versions.
3. `docs/STABILITY_PROMISES.md` — public surface and the cross-version
   compatibility matrix.
4. `docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md` — every
   finding and its status.
5. `docs/CORRIDOR_INTEGRATION.md` — wire format and on-chain ABI
   (normative).
6. `docs/OPERATOR_RUNBOOK.md` section 13 — deploy checklist.
7. `docs/visuals/README.md` — Mermaid conventions.
8. `docs/AI_AGENTS.md` — per-tool notes (Claude Code, Cursor, Copilot,
   Aider, ChatGPT).

For protocol questions: `docs/WHITEPAPER.md`, then `docs/THREAT_MODEL.md`,
then `docs/FORMAL_VERIFICATION_STATUS.md`. For operations:
`docs/DEPLOYMENT_GUIDE.md`, then `docs/OPERATOR_RUNBOOK.md`. Persona
routing starts at `docs/README.md`.
