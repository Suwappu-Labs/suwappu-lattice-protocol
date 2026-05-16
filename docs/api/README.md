# API Reference

Auto-generated HTML reference for the Python `ltp` package, rendered from
in-source docstrings via [pdoc](https://pdoc.dev/).

## Generate

```bash
make docs-api
```

Output lands in `docs/api/python/`. The HTML is **not** checked into git —
it's an artifact, regenerated on demand and built in CI by
`.github/workflows/docs.yml`.

### Python version

Use **Python 3.10–3.13**. Python 3.14 currently emits `ForwardRef` warnings
from pdoc that cause some submodules to be skipped; this is tracked
upstream in pdoc and will be resolved in a future release. CI pins 3.12.

## Source of truth

The source of truth for every public class, function, and dataclass is the
Python source under `src/ltp/`. The reference docs reflect the docstrings
that ship with the code. If a docstring is wrong, fix it in `src/` — do not
hand-edit the generated HTML.

## What's documented

Everything exported from `src/ltp/` and its subpackages:

- `ltp.anchor` — `EntityState`, `AnchorSubmission`, `AnchorClient`
- `ltp.crypto` — ML-KEM-768, ML-DSA-65, hybrid signature wrappers
- `ltp.corridor` — wire format, ABI bindings
- `ltp.dual_lane` — SHA3-256 + BLAKE3-256 domain separation
- `ltp.envelope` — sealed ML-DSA-65 envelope wrapper
- `ltp.merkle_log` — RFC 6962 Merkle tree, STH, inclusion / consistency proofs
- `ltp.network` — gRPC client and server
- `ltp.storage` — Memory, SQLite (WAL), Filesystem shard stores
- `ltp.verify` — pure verification SDK (no state, no side effects)

For the **wire format** and **on-chain ABI**, see
[CORRIDOR_INTEGRATION.md](../CORRIDOR_INTEGRATION.md) instead — those
contracts are normative and live outside the Python codebase.

## Persona shortcuts

- **dApp developer** — start with `ltp.verify` and `ltp.merkle_log`. The
  inclusion-proof verifier is in `ltp.verify.verify_inclusion_proof`.
- **Node operator** — `ltp.anchor.AnchorClient` is the submit-side entry
  point; `ltp.network` is the wire layer.
- **Cryptographer** — `ltp.crypto`, `ltp.envelope`, `ltp.dual_lane`,
  `ltp.domain`.

See [personas/README.md](../personas/README.md) for the full role map.
