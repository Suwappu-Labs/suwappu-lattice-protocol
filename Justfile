# LTP developer command surface. Wraps Makefile for canonical commands
# (so CI parity is unbreakable) and adds ergonomic helpers for the lint
# stack added in Track 2 of the LayerZero/Tempo benchmarking audit.
#
# Run `just` with no arguments to see the menu.

set shell := ["bash", "-uc"]
set dotenv-load := true

# Default — show the recipe list
default:
    @just --list

# --- Setup ----------------------------------------------------------------

# Install production + dev deps and the pre-commit git hook
setup:
    python -m pip install -e ".[production,dev]"
    pre-commit install

# Refresh pre-commit hook revisions (manually re-pin SHAs after running)
setup-update:
    pre-commit autoupdate
    @echo "Review .pre-commit-config.yaml — SHAs must be pinned per LTP-A-025"

# --- Lint + format --------------------------------------------------------

# Run every pre-commit hook against every file
lint:
    pre-commit run --all-files

# Format Python (ruff) and Solidity (forge fmt)
fmt:
    ruff format .
    ruff check --fix .
    cd contracts && forge fmt

# Run the type checker against the curated `files` list (advisory in this PR)
typecheck:
    mypy

# Run solhint against contracts/src/
solhint:
    cd contracts && npx -y solhint@5.0.3 'src/**/*.sol' --max-warnings=0

# --- Tests (delegated to Makefile so CI parity holds) ---------------------

# Run the canonical test target
test:
    make test

# Just the Python test suite
test-python:
    make test-python

# Just the Solidity test suite
test-contracts:
    make test-contracts

# Full suite (Python + contracts + integration)
test-all:
    make test-all

# --- Audit + docs (delegated) ---------------------------------------------

# Slither static analysis
slither:
    make slither

# Slither + Echidna + invariants (slow; pre-merge gate for contract changes)
contracts-secaudit:
    make contracts-secaudit

# Regenerate the Python API reference under docs/api/
docs:
    make docs-api

# --- Infrastructure (infra/terraform/) ------------------------------------

# Format every .tf file in infra/terraform/
tf-fmt:
    terraform -chdir=infra/terraform fmt -recursive

# Check formatting without writing — what CI runs
tf-fmt-check:
    terraform -chdir=infra/terraform fmt -check -recursive -diff

# Validate one env's composition (no AWS credentials needed)
tf-validate env="prod":
    terraform -chdir=infra/terraform/envs/{{env}} init -backend=false
    terraform -chdir=infra/terraform/envs/{{env}} validate

# --- Housekeeping ---------------------------------------------------------

# Remove generated artifacts (delegates to make clean)
clean:
    make clean
