# Stability Promises

What outside developers can rely on, and how breaking changes are signaled.

## Versioning

The Python package (`ltp`) and the deployed Solidity contracts follow **semantic versioning** (`MAJOR.MINOR.PATCH`):

- **MAJOR** — incompatible public-API changes (Python or Solidity). Bumped only at planned releases with at least one minor version of advance notice via the deprecation channel (see below).
- **MINOR** — new public functionality, additive, backwards-compatible.
- **PATCH** — bug fixes, performance, internals, doc improvements.

The current version is published in [`pyproject.toml`](../pyproject.toml) `project.version` and in [`CHANGELOG.md`](../CHANGELOG.md).

The on-chain `LTPAnchorRegistry` exposes its own integer `version()` view — currently `v5` on GSX Testnet and `v6` on Base Sepolia. See [`docs/DEPLOYED_CONTRACTS.md`](DEPLOYED_CONTRACTS.md) for addresses and the governance path that controls upgrades.

## Public surface

### Stable

- Every symbol re-exported from `ltp.__init__`
- Every symbol re-exported from `ltp.corridor.__init__`, `ltp.verify.__init__`, `ltp.bridge.__init__`, `ltp.backends.__init__`, `ltp.network.__init__`
- Every Solidity function in `contracts/src/interfaces/ILTPAnchorRegistry.sol`
- Every entry in `contracts/abi/LTPAnchorRegistry.json`
- Every event topic emitted by the deployed registry contracts at the addresses in [`docs/DEPLOYED_CONTRACTS.md`](DEPLOYED_CONTRACTS.md)
- The corridor JSON wire format defined by `src/ltp/corridor/wire.py` (see [`CORRIDOR_INTEGRATION.md`](CORRIDOR_INTEGRATION.md))
- The `BLS_CORRIDOR_DST` constant (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`) and the length-prefixed SHA3-256 domain digest in `src/ltp/corridor/digest.py`
- The compliance event taxonomy in `src/ltp/compliance.py::AuditEventType`

### Internal

Anything matching any of the following is private and may change in a **PATCH** release without notice:

- Any module path containing `_internal` (e.g. `ltp._internal.foo`)
- Any symbol whose name starts with `_` (single underscore)
- Anything not re-exported from a package's `__init__.py`
- Anything under `tests/`, `scripts/`, `deploy/` private subroutines
- `src/ltp/corridor/wire.py::_hex_bytes` / `_int_field` / `_dict_field` / `_list_field` validation helpers (use `WireFormatError` from the public surface to catch parse errors instead)

### Configuration

These behaviors are explicitly stable across MINOR releases:

| Knob | Where | Promise |
|---|---|---|
| `LTP_ENV=production` | env var | Causes `ltp.bls` import to assert that the `blst` backend is available |
| `ETP_DEPLOYMENT_PROFILE=fedramp-high` | env var | Causes `deploy/preflight_gateway.py` to fail closed on the FedRAMP gate list documented in `docs/compliance/fedramp-high/` |
| `--strict` in CI `pip-audit` | `.github/workflows/contracts.yml` | Reports HIGH/CRITICAL CVEs in installed deps; continue-on-error so a fresh transitive CVE doesn't stall PRs |

## Deprecation policy

Breaking changes are announced **at least one MINOR release in advance** through three channels in parallel:

1. **Code**: the deprecated symbol emits `DeprecationWarning` (Python) or is annotated `@deprecated` (Solidity NatSpec) with the target removal version.
2. **`CHANGELOG.md`**: every release records new deprecations under a `### Deprecated` heading and removals under `### Removed`.
3. **PR description on the introducing release**: the PR that introduces the deprecation calls out the migration path.

A maintainer landing a deprecation should also open a tracking issue with the milestone set to the target removal version so the cleanup PR has somewhere to point.

## Release artifacts

Each MAJOR or MINOR release publishes:

| Artifact | Path | Promise |
|---|---|---|
| Tagged git release | `git tag vX.Y.Z` | Annotated tag on `main` |
| Python sdist + wheel | (release pipeline) | Signed once the release pipeline is wired |
| Contract ABIs | `contracts/abi/*.json` | Updated whenever a contract MAJOR or MINOR bumps |
| FedRAMP evidence bundle | `docs/compliance/fedramp-high/release-evidence.md` | Template per the compliance overlay; filled in at release time |
| SBOM (CycloneDX) | (release pipeline) | Generated on each tag; format is CycloneDX 1.5 JSON |

## Filing a stability concern

If you discover a downstream-breaking change that the deprecation channel missed, open an issue with the label `stability-violation` and cite the public-surface promise above that it broke. Maintainer response target is one business day for an acknowledgment, one week for a remediation plan.

For a security-affecting break, follow [`../SECURITY.md`](../SECURITY.md) instead — those go through the private disclosure channel.
