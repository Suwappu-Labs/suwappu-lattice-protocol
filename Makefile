# ETP Development Makefile
# ========================
# Quick commands for testing, building, and deployment verification.

.PHONY: test test-python test-contracts test-integration test-all
.PHONY: build lint clean ci-integration audit abi help

# ── Python Tests ────────────────────────────────────────────────────────

test-python:
	pytest tests/ -v --ignore=tests/test_contract_integration.py

test-python-fast:
	pytest tests/ -x -q --ignore=tests/test_contract_integration.py

# ── Solidity Tests ──────────────────────────────────────────────────────

test-contracts:
	cd contracts && forge test -vvv

# ── Contract Integration (requires anvil) ───────────────────────────────

ci-integration: _anvil-start _deploy-local test-integration _anvil-stop

_anvil-start:
	@echo "Starting anvil..."
	@anvil --silent &
	@sleep 2

_deploy-local:
	@echo "Building and deploying contracts to local anvil..."
	@cd contracts && forge install foundry-rs/forge-std 2>/dev/null || true
	@cd contracts && forge build
	@cd contracts && forge script script/Deploy.s.sol \
		--rpc-url http://localhost:8545 --broadcast 2>/dev/null

test-integration:
	pytest tests/test_contract_integration.py -v

_anvil-stop:
	@echo "Stopping anvil..."
	@pkill -f anvil 2>/dev/null || true

# ── Full Suite ──────────────────────────────────────────────────────────

test-all: test-python test-contracts ci-integration
	@echo "All tests passed."

test: test-python

# ── Build & Lint ────────────────────────────────────────────────────────

build:
	pip install -e ".[dev]"

lint:
	python -m py_compile src/ltp/__init__.py
	@echo "Syntax OK"

# ── Clean ───────────────────────────────────────────────────────────────

clean:
	rm -rf __pycache__ .pytest_cache htmlcov .coverage
	rm -rf src/ltp/__pycache__ tests/__pycache__
	rm -rf contracts/out contracts/cache
	@echo "Clean."

# ── Supply-chain audit ──────────────────────────────────────────────────

audit:
	@if ! command -v pip-audit >/dev/null 2>&1; then \
		echo "pip-audit not installed; run: pip install 'pip-audit>=2.7.0,<3.0'"; \
		exit 1; \
	fi
	pip-audit --strict --vulnerability-service osv

# ── ABI export (for non-Python integrators) ─────────────────────────────

abi:
	@if [ ! -d contracts/out ]; then \
		echo "contracts/out/ missing; run 'cd contracts && forge build' first"; \
		exit 1; \
	fi
	@mkdir -p contracts/abi
	@for f in contracts/out/*.sol/*.json; do \
		name=$$(basename $$f .json); \
		jq '.abi' $$f > contracts/abi/$$name.json; \
		echo "wrote contracts/abi/$$name.json"; \
	done

# ── Help ────────────────────────────────────────────────────────────────

help:
	@echo "Common targets:"
	@echo "  make test                run the Python test suite (default)"
	@echo "  make test-python         Python only (skip live-anvil)"
	@echo "  make test-contracts      Forge / Solidity tests"
	@echo "  make test-integration    Python + Anvil contract integration"
	@echo "  make test-all            full suite + integration"
	@echo "  make audit               pip-audit against installed deps"
	@echo "  make abi                 regenerate contracts/abi/*.json"
	@echo "  make build               pip install -e .[dev]"
	@echo "  make lint                syntax check"
	@echo "  make clean               remove caches + build outputs"
