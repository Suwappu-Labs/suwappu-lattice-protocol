# Development guide

How to set up a working environment for the Lattice Transfer Protocol
(LTP), what runs on every commit, and how to run each tool independently.

If you are auditing the repo and just need to verify a build, jump to
[Operator runbook](OPERATOR_RUNBOOK.md). This file is for **contributors**.

---

## One-command setup

Two supported paths. The devcontainer is the recommended one — it
guarantees the same Python, Node, Foundry, and solhint versions that CI
uses.

### Path A — VS Code devcontainer (recommended)

```bash
git clone <repo> && cd gsx-lattice-protocol
code .
# In VS Code, run: "Dev Containers: Reopen in Container"
# Wait ~3–5 minutes for the first build; subsequent opens are instant.
```

The container's `postCreateCommand` installs production + dev deps,
solhint, foundryup, and the pre-commit git hook, then sanity-checks
`import ltp` to confirm the real PQ crypto backends loaded.

### Path B — bare metal

```bash
git clone <repo> && cd gsx-lattice-protocol
python3.12 -m venv .venv && source .venv/bin/activate
just setup
```

`just setup` runs `pip install -e ".[production,dev]" && pre-commit
install` for you.

If `python3.12` isn't on your `PATH`, install via `pyenv install 3.12`
or `brew install python@3.12`. The project supports 3.10–3.13; CI pins
3.12, so reproducing CI locally requires 3.12.

> **Note.** `python3 -c "import ltp"` fails on a stock interpreter
> because `src/ltp/__init__.py` asserts real PQ-crypto backends. The
> `[production]` extra installs them; running anywhere else (a system
> shell, a fresh venv without `[production]`) will trip the assertion.

---

## Daily commands

The `Justfile` at the repo root is the canonical surface. Run `just`
with no arguments to see the full menu; the most common are:

| Command | What it does |
|---|---|
| `just lint` | Run every pre-commit hook on every file (ruff + ruff-format + solhint + hygiene) |
| `just fmt` | Auto-format Python (ruff) and Solidity (forge fmt) |
| `just typecheck` | Run mypy on the curated `files` list (see "Mypy scope" below) |
| `just solhint` | Run solhint on `contracts/src/**/*.sol` with `--max-warnings=0` |
| `just test-python` | Python test suite (delegates to `make test-python`) |
| `just test-contracts` | Solidity test suite via `forge test` |
| `just contracts-secaudit` | Slither + Echidna + invariants (slow; pre-merge gate for `contracts/` changes) |
| `just docs` | Regenerate the Python API reference under `docs/api/` |

The Justfile delegates test/audit/docs targets to `Makefile` so CI parity
is unbreakable — every CI workflow calls `make`, and `Makefile` is the
source of truth for what "the canonical command" does.

---

## What runs on every commit

`pre-commit install` (run automatically by `just setup` or the
devcontainer's `postCreate.sh`) wires up the following hooks. They run
against staged files; `just lint` runs them against every file.

| Hook | Source | What it catches |
|---|---|---|
| `trailing-whitespace` | `pre-commit-hooks` | trailing space at end of line (skips `.md`) |
| `end-of-file-fixer` | `pre-commit-hooks` | missing final newline |
| `check-yaml` | `pre-commit-hooks` | malformed YAML |
| `check-toml` | `pre-commit-hooks` | malformed TOML (catches `pyproject.toml` regressions) |
| `check-added-large-files` | `pre-commit-hooks` | accidental binary commits over 512 KB |
| `check-merge-conflict` | `pre-commit-hooks` | unresolved `<<<<<<< HEAD` markers |
| `mixed-line-ending` | `pre-commit-hooks` | enforces LF |
| `ruff` | `ruff-pre-commit` | Python lint (Pyflakes + pycodestyle + isort), `--fix` enabled |
| `ruff-format` | `ruff-pre-commit` | Python formatting (replaces black) |
| `solhint` | local hook | Solidity lint against `contracts/.solhint.json`, `--max-warnings=0` |

**Per LTP-A-025, every hook revision is SHA-pinned, not tagged.** Bumping
a hook requires re-resolving the SHA — see the header comment in
`.pre-commit-config.yaml`.

The CLAUDE.md hard rule **"No `--no-verify` or hook bypasses without
explicit instruction"** applies here. If a hook fails on legitimate code,
adjust the hook config (or fix the code), don't bypass.

---

## Mypy scope

Mypy is installed and runnable via `just typecheck`, but it does **not**
run in pre-commit or CI yet. Strict-mode on the full codebase surfaces
~900 errors (mostly missing return annotations and `Any` leaks from
crypto libraries without PEP-561 stubs); annotating it is a project, not
a PR.

The current scope is in `pyproject.toml` `[tool.mypy] files`:

- `src/ltp/primitives.py` — ML-KEM / ML-DSA primitives
- `src/ltp/keypair.py` — KeyPair surface

The follow-up sweep broadens `files` one submodule at a time, flips
`strict = true` once the curated set is clean, and finally adds the
mypy hook to `.pre-commit-config.yaml` + a `mypy` job to
`.github/workflows/lint.yml`.

---

## Tooling versions

| Tool | Version | Where pinned |
|---|---|---|
| Python | 3.12 | `.github/workflows/*.yml`, `pyproject.toml` `[tool.ruff] target-version` |
| Node | 20 | `.github/workflows/*.yml`, `.devcontainer/devcontainer.json` features |
| Foundry / `forge` | latest at devcontainer build | `.devcontainer/postCreate.sh` (runs `foundryup`) |
| ruff | `>=0.15,<0.16` | `pyproject.toml` `[project.optional-dependencies] dev` |
| mypy | `>=1.13,<2` | `pyproject.toml` `[project.optional-dependencies] dev` |
| pre-commit | `>=4.0,<5` | `pyproject.toml` + `.github/workflows/lint.yml` |
| solhint | `5.0.3` | `.pre-commit-config.yaml` + `.github/workflows/contracts.yml` + `.devcontainer/postCreate.sh` |
| solc | `0.8.24` | `contracts/foundry.toml` |
| pqcrypto | `>=0.4.0,<0.5` | `pyproject.toml` `[production]` extra (LTP-A-014) |
| pynacl | `>=1.5.0,<2.0` | `pyproject.toml` `[production]` extra |

---

## Onboarding checklist for a new contributor

1. Clone the repo and open in VS Code with the devcontainer extension
   (or `just setup` on bare metal with Python 3.12).
2. Verify `python -c "import ltp"` prints nothing (no assertion error).
3. Verify `just lint` returns green on a freshly-cloned `main`.
4. Verify `just test-python` returns green.
5. Read [CLAUDE.md](../CLAUDE.md) for the repo's hard rules
   (SHA-pin actions, no rebase on shared branches, no `--no-verify`).
6. Read [docs/AI_AGENTS.md](AI_AGENTS.md) if you'll be working with
   Claude Code or another AI agent on this repo.
7. Skim [docs/STABILITY_PROMISES.md](STABILITY_PROMISES.md) to learn
   which surfaces are version-locked vs. malleable.

Open a PR against `main`. The `Lint` workflow plus the existing `ETP CI`
and `Docs CI` workflows will gate the merge.
