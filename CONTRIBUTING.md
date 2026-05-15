# Contributing to the Entanglement Transfer Protocol

Thank you for your interest in contributing to ETP. This document provides guidelines
for contributing to the project.

## Prerequisites

- **Python 3.10+** (3.12 recommended)
- **Git** for version control
- **Foundry** (forge, cast, anvil) — for smart contract development
- No external dependencies required for the core Python library (stdlib only)

## Getting Started

### Python Development

```bash
# Clone the repository
git clone https://github.com/GlobalSettlementNetwork/Entanglement-Transfer-Protocol.git
cd Entanglement-Transfer-Protocol

# Install in development mode (includes test deps + real PQ crypto)
pip install -e ".[dev]"

# Verify installation
pytest tests/ -v
```

### Smart Contract Development

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Build and test contracts
cd contracts
forge install
forge build
forge test -vvv
```

## Running Tests

### Python Tests (1,167 tests)

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_protocol.py -v

# Run a specific test
pytest tests/test_protocol.py::TestCommitMaterialize::test_basic_transfer -v

# Run with coverage
pytest tests/ --cov=src/ltp --cov-report=term-missing
```

### Solidity Tests (84 tests)

```bash
cd contracts

# Unit + integration tests
forge test -vvv

# Fuzz tests only (256 iterations per test)
forge test --match-contract FormalVerification -vvv

# Gas report
forge test --gas-report
```

### Integration Tests (Python ↔ Solidity)

```bash
# Terminal 1: Start Anvil
anvil

# Terminal 2: Deploy contracts and run parity tests
cd contracts && forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
cd .. && pytest tests/test_contract_integration.py -v
```

All 1,251+ tests should pass. If any fail on a clean checkout, please open an issue.

## Code Style

### Python

- **Zero external dependencies** for the core library (`src/ltp/`). Optional extras
  (pqcrypto, pynacl, blake3, web3, grpcio) are documented in `pyproject.toml`.
- **Logging, not print.** Use `logging.getLogger(__name__)` for all output.
  Never use `print()` in library code.
- **ValueError, not assert.** Use explicit `if ... raise ValueError(...)` for
  input validation at public API boundaries. Reserve `assert` for internal invariants.
- **Type annotations** on all public function signatures. Use `T | None` (Python 3.10+)
  instead of `Optional[T]`.

### Solidity

- **Solidity 0.8.24** with optimizer (200 runs, via-IR, Cancun EVM)
- **OpenZeppelin** for proxy patterns and governance (do not reinvent)
- **SHA3-256** for all on-chain/canonical hashing paths — never use BLAKE3 on-chain
- **NatSpec comments** on all public functions and events
- Use `_disableInitializers()` on implementation contracts
- Include `uint256[50] __gap` for upgrade-safe storage layouts

### Naming Conventions

- Classes: `PascalCase` (e.g., `CommitmentNetwork`, `ErasureCoder`)
- Functions/methods: `snake_case` (e.g., `commit_entity`, `fetch_encrypted_shards`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `EK_SIZE`, `DEFAULT_N`)
- Private methods: `_leading_underscore`

### Module Organization

| Directory | Purpose |
|-----------|---------|
| `src/ltp/` | Core protocol library (60+ modules) |
| `src/ltp/anchor/` | On-chain entity state machine + anchor client |
| `src/ltp/backends/` | Pluggable commitment backends (Local, Monad L1, Ethereum) |
| `src/ltp/bridge/` | Cross-chain bridge (L1Anchor, Relayer, L2Materializer) |
| `src/ltp/dual_lane/` | SHA3/BLAKE3 lane separation and enforcement |
| `src/ltp/merkle_log/` | RFC 6962 Merkle tree, signed tree heads, proofs |
| `src/ltp/network/` | gRPC client/server (7 RPCs) |
| `src/ltp/storage/` | Persistent shard stores (Memory, SQLite/WAL, Filesystem) |
| `src/ltp/verify/` | Verification SDK (pure functions, no side effects) |
| `contracts/src/` | Solidity smart contracts (LTPAnchorRegistry, LTPMultiSig) |
| `contracts/test/` | Foundry tests (unit, fuzz, invariant, cross-parity) |
| `contracts/script/` | Deployment scripts (local, testnet, mainnet, upgrade) |
| `tests/` | Python test files (prefix: `test_`) |

## Pull Request Workflow

1. **Fork** the repository and create a feature branch
2. **Write tests** for new functionality (maintain or improve coverage)
3. **Run the full test suite** before submitting: `pytest tests/ -v` and `cd contracts && forge test -vvv`
4. **Keep PRs focused** — one feature or fix per PR
5. **Write clear commit messages** describing the "why", not just the "what"

### PR Checklist

- [ ] All 1,251+ tests pass (Python + Solidity)
- [ ] New code has corresponding tests
- [ ] No external dependencies added to core library
- [ ] Type annotations on public API
- [ ] `logging` used instead of `print()`
- [ ] `ValueError` used instead of `assert` for input validation
- [ ] SHA3-256 used on all settlement/on-chain paths
- [ ] No secrets in committed code (`.env` files are gitignored)
- [ ] Solidity changes include forge tests (if applicable)

### Contract Development

When modifying `LTPAnchorRegistry.sol`:

1. Bump the `version()` return value
2. Update test assertions for the new version
3. Follow the upgrade script pattern in `contracts/script/UpgradeV4.s.sol`
4. After deployment, verify on-chain state (version, admin, paused, threshold, EIP-1967 slot)

## Architecture

- [Architecture](docs/design-decisions/ARCHITECTURE.md) — System components and data flow
- [Whitepaper](docs/WHITEPAPER.md) — Full protocol specification
- [Visuals](docs/visuals/README.md) — Inline-Mermaid diagrams of LTP, GSX DAG, GSX-DB, anchor lifecycle, trust boundary, DKG
- [Corridor Integration](docs/CORRIDOR_INTEGRATION.md) — how to interop with the 7-of-9 attestation pipeline from Python / Rust / JS
- [Stability Promises](docs/STABILITY_PROMISES.md) — semver, deprecation policy, what's public vs internal
- [Formal Verification Status](docs/FORMAL_VERIFICATION_STATUS.md) — what's symbolically verified and what isn't

## Quick Commands

```bash
make test                # Python suite (skips live-anvil integration)
make test-contracts      # Forge / Solidity tests
make test-integration    # Python + Anvil contract integration tests
make audit               # pip-audit against installed deps
make abi                 # regenerate contracts/abi/*.json from contracts/out/
make help                # full target list
```

The package ships type hints (`src/ltp/py.typed`) per PEP 561 — mypy / pyright will pick up the public API surface automatically when you `pip install -e ".[dev,chain]"`.

## Questions?

Open an issue for questions about the protocol design or implementation approach.
