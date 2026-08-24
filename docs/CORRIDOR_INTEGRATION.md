# Corridor Integration

How to participate in LTP's 7-of-9 corridor attestation pipeline from outside the Python codebase.

The corridor is the bridge layer that takes a `suwappu-db` state root, gathers BLS partial signatures from a super-node quorum, and emits an aggregated attestation that an on-chain `LTPAnchorRegistry` verifier can check. The wire format is byte-for-byte stable across Python (`src/ltp/corridor/`) and Rust (`suwappu-dag/crates/suwappu-ltp`).

## Cross-language invariants

These constants and digest constructions are part of the public surface (see [`STABILITY_PROMISES.md`](STABILITY_PROMISES.md)):

| Invariant | Where | Value |
|---|---|---|
| Corridor BLS DST | `src/ltp/corridor/constants.py::BLS_CORRIDOR_DST` and `suwappu-dag/crates/suwappu-crypto/src/bls.rs:24::BLS_DST` | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` |
| Attestation domain hash | `src/ltp/corridor/digest.py::sha3_256_domain` | `H(len(tag)||tag||data)` with `len` as `u32` big-endian |
| Quorum | `src/ltp/corridor/constants.py::LTP_ATTESTATION_QUORUM_THRESHOLD / _SIZE` | `7-of-9` |
| BLS signature size | wire format | 96 bytes |
| BLS public key size | wire format | 48 bytes (G1 compressed) |
| State root, digest, MAC size | wire format | 32 bytes |

Both implementations validate these sizes at the wire boundary. A signature shorter than 96 bytes never reaches the verifier in either language.

## Assembling the corridor

Every snippet below starts from "suppose `corridor` is the 9-member super-node
set". Getting to that object is its own problem: nine operators, nine BLS
keypairs, and no agreement yet on who is in. `src/ltp/corridor/membership.py`
is the data layer for that step — transport-agnostic, so enrollments can arrive
over gossip, a REST endpoint, or a file in a git repo.

```python
from src.ltp.corridor.membership import CorridorRegistry, build_pop_message
from src.ltp.corridor.bls import corridor_sign, keygen

# Each operator, on their own machine, once:
pk, sk = keygen()
pop = corridor_sign(sk, build_pop_message(pk))   # proves they hold sk
# ... then publishes (authority_id, corridor_id, pk, pop) however they like.

# Each node, independently, as enrollments arrive:
registry = CorridorRegistry(corridor_id=7)
for node in incoming_super_nodes:
    registry.enroll(node)       # raises on a bad, duplicate, or foreign member

print(registry.roster_digest().hex())   # compare this with your peers
corridor = registry.finalize()          # exactly 9, canonically ordered
```

`enroll` rejects, and leaves the registry untouched, when the super-node targets
a different corridor, has a wrong-length key or PoP, repeats an already-enrolled
authority id, repeats an already-enrolled **BLS public key**, or presents a PoP
that does not verify. The BLS-key check is the one with no signature-level
analogue: two authority ids sharing one key means a single operator holds two of
nine seats, so a "7-of-9" quorum can be reached by six real parties. Every
signature in that attestation is valid; the threshold is the thing that broke.

`roster_digest()` is a domain-separated SHA3-256 over `(corridor_id, count,
(authority, pubkey)*)` in canonical order. Read it aloud on a call, post it, or
diff it in CI — if two operators' digests differ, they do not have the same
corridor, and that is much cheaper to discover before anything is signed.
Members are sorted by authority id before finalization, so enrollment order
cannot make two honest nodes disagree.

## Python — verify an attestation in process

```python
from src.ltp.corridor.attestation import (
    Corridor,
    AttestationPayload,
    CorridorAttestation,
    verify_attestation,
)
from src.ltp.corridor.wire import corridor_attestation_from_dict, WireFormatError

# Suppose `corridor` is the 9-member super-node set you fetched from
# suwappu-dag, and `attestation_json` is the JSON the corridor leader gave you.
try:
    attestation: CorridorAttestation = corridor_attestation_from_dict(attestation_json)
except WireFormatError as e:
    raise SystemExit(f"malformed attestation: {e}")

# Raises if the aggregate signature doesn't verify under the quorum's
# group public key, if signers aren't in the corridor, if quorum isn't
# met, or if any per-witness signature is malformed.
verify_attestation(corridor, attestation)
print("attestation OK; safe to submit on-chain")
```

The `WireFormatError` boundary is important: never let bare `bytes.fromhex(...)` exceptions or `KeyError` propagate from network input into the cryptographic verifier — that's both a DoS surface and a schema-leak.

## Rust — produce an attestation

Use the canonical Rust crate at `suwappu-dag/crates/suwappu-ltp`. The high-level flow:

```rust
use suwappu_ltp::{Corridor, AttestationPayload, attest, verify_attestation};
use suwappu_crypto::bls::{sign, BLS_DST};

// 1. Each super-node signs the canonical digest of the payload.
let payload = AttestationPayload { /* source_chain, target_chain, source_height, state_root, timestamp_round */ };
let digest = payload.canonical_digest();        // length-prefixed SHA3-256 under "SUWAPPU-LTP-ATTEST-V1"
let partial = sign(&sk, &digest, BLS_DST, &[]); // BLS_DST is identical to BLS_CORRIDOR_DST in Python

// 2. The corridor leader gathers >=7 partials and aggregates.
let attestation = attest(&corridor, payload, partials)?;

// 3. Serialize with the hex-string wire format (matches `corridor_attestation_to_dict`).
let wire = serde_json::to_string(&attestation.to_wire())?;
```

The `suwappu-dag` README has the full sample with key management and quorum selection. The Python `attestation.py::attest` mirrors the same validation order:

1. Corridor size is 9.
2. Every signing witness is a corridor member.
3. Distinct signer count meets the 7 threshold.
4. Each individual signature verifies over `payload.canonical_digest()`.
5. Aggregate signature is computed and re-verified.

## JSON wire format

The canonical wire is hex-string-encoded bytes, sorted integer signer lists, and integer enum discriminants. Example payload:

```json
{
  "payload": {
    "source_chain": 84532,
    "target_chain": 103115120,
    "source_height": 39928377,
    "state_root": "0000...0000",
    "timestamp_round": 1234
  },
  "aggregate_signature": "<192 hex chars = 96 bytes>",
  "signers": [0, 2, 3, 4, 5, 7, 8]
}
```

If you're consuming this from a Rust serializer that defaults to byte-array JSON (lists of `u8` numbers rather than hex strings), use the `*_from_serde_default_dict` helpers in `src/ltp/corridor/wire.py` instead. They mirror serde-default behavior.

## On-chain handoff

After the corridor produces a verified `CorridorAttestation`, the natural next step is on-chain submission via the registry's `anchor(...)` function. See:

- [`docs/DEPLOYED_CONTRACTS.md`](DEPLOYED_CONTRACTS.md) for current addresses
- [`contracts/abi/LTPAnchorRegistry.json`](../contracts/abi/LTPAnchorRegistry.json) for the ABI
- [`examples/verify_anchor_from_js.mjs`](../examples/verify_anchor_from_js.mjs) for the JS read-side equivalent

The current on-chain contract does **not** re-verify the BLS aggregate; it trusts the relayer to submit valid anchors. Fraud-proof / on-chain BLS verification is tracked in `docs/plans/2026-05-11-production-roadmap.md`.

## Common gotchas

- **DST mismatch**: if you call `blst.P2.hash_to(digest)` without the explicit `BLS_DST` argument, the Rust verifier silently produces a 96-byte signature that will never cross-validate with Python. Always pass the DST. See the captured skill `bls-dst-mismatch-cross-language-interop` for the failure signature.
- **Length-prefixed digest**: the SHA3-256 helper prepends `len(tag)` as a 4-byte big-endian length before the tag bytes. A Python or Rust port that omits the length prefix produces a different digest that will fail verification with no useful error message. See `src/ltp/corridor/digest.py` for the canonical implementation.
- **Sorted signer arrays**: the `signers` JSON array MUST be sorted ascending. Both serializers emit it sorted; both verifiers reject unsorted input. Be careful if you re-emit JSON through a tool that doesn't preserve order.
- **PoP is checked at the door, not at verify time**: `Corridor.verify_pops()` exists but is opt-in, and `verify_attestation` does not call it. If you build a `Corridor` by hand rather than through `CorridorRegistry`, nothing has checked that any member actually holds the secret key for the public key it advertises — that is the rogue-key attack LTP-A-015 covers. `CorridorRegistry.enroll` verifies the PoP before admitting a member, and `finalize()` re-runs `verify_pops()` on the assembled set.
- **Hex vs serde-default**: if your Rust side uses `#[serde(with = "hex")]`, use the canonical Python helpers. If it doesn't, use the `*_to_serde_default_dict` / `*_from_serde_default_dict` mirrors.

## Reference implementations

- Python: [`src/ltp/corridor/`](../src/ltp/corridor/) — full attestation, DA SLA, DID rotation, state anchor surfaces
- Rust: `suwappu-dag/crates/suwappu-ltp` — canonical, byte-for-byte matching reference
- Solidity (read side): [`contracts/src/LTPAnchorRegistry.sol`](../contracts/src/LTPAnchorRegistry.sol)
