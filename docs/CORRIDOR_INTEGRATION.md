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
from src.ltp.corridor.bls import keygen
from src.ltp.corridor.enrollment import announce
from src.ltp.corridor.membership import CorridorRegistry

# Each operator, on their own machine, once — offline, no round trip:
pk, sk = keygen()
ann = announce(sk, pk, corridor_id=7, authority=3, epoch=0)
# ... then publishes `ann` however they like: gossip, REST, a file in a repo.

# Each node, independently, as announcements arrive:
registry = CorridorRegistry(corridor_id=7, epoch=0)
for incoming in announcements_received:
    registry.enroll_announcement(incoming)   # raises on anything not legitimate

print(registry.roster_digest().hex())   # compare this with your peers
corridor = registry.finalize()          # exactly 9, canonically ordered
```

### Why an announcement rather than a bare `SuperNode`

The PoP signs the public key **alone** — `Sign(sk, DOMAIN_TAG_CORRIDOR_POP || pk)`.
That proves the sender holds `sk`, and nothing else. It does not name a corridor,
a seat, or an epoch, because none of those are under the signature. So a PoP is
replayable in a way that costs the attacker nothing:

1. Operator A broadcasts a legitimate enrollment for corridor 7, seat 3.
2. Anyone who saw it rebroadcasts the same key and PoP as seat 8 — or corridor 12,
   or next epoch's corridor 7.
3. The registry verifies the PoP (it is genuine), admits the squatter, and then
   rejects A's real enrollment with `DuplicateBlsKey`.

A's seat is gone until somebody reconciles it by hand. `announce()` adds a second
signature from the same key over the fields that were missing:

```text
binding = Sign(sk, DOMAIN_TAG_CORRIDOR_ENROLL || corridor || epoch || authority || pk)
```

Both signatures are produced offline in one call, so this adds no key management
and no round trip, and the announcement is then safe to relay over an untrusted
transport — a relay can drop or delay it but cannot retarget it. Use
`enroll_announcement` for anything that arrived over a network and `enroll` only
for a `SuperNode` you built locally.

What this does **not** do is decide who is *entitled* to a seat. An announcement
proves "the holder of this key wants seat 3 of corridor 7 in epoch 0"; an
allowlist, stake check, or governance vote is a separate layer above this one.

### What the registry rejects

`enroll` rejects, and leaves the registry untouched, when the super-node targets
a different corridor, has a wrong-length key or PoP, repeats an already-enrolled
authority id, repeats an already-enrolled **BLS public key**, or presents a PoP
that does not verify. `enroll_announcement` additionally rejects a wrong epoch
and a binding that does not cover this corridor/epoch/seat.

The BLS-key check is the one with no signature-level analogue: two authority ids
sharing one key means a single operator holds two of nine seats, so a "7-of-9"
quorum can be reached by six real parties. Every signature in that attestation is
valid; the threshold is the thing that broke.

`roster_digest()` is a domain-separated SHA3-256 over `(corridor_id, epoch,
count, (authority, pubkey)*)` in canonical order. Read it aloud on a call, post
it, or diff it in CI — if two operators' digests differ, they do not have the
same corridor, and that is much cheaper to discover before anything is signed.
Members are sorted by authority id before finalization, so enrollment order
cannot make two honest nodes disagree.

## Running a signing round

`attest()` takes all the partial signatures at once. Real rounds do not work
that way: partials arrive one at a time, from peers, out of order, sometimes
twice, sometimes from a non-member, sometimes for a payload that is a round
stale. Handed straight to `attest()`, the whole batch fails on the first bad one
with no way to tell which peer sent it. `src/ltp/corridor/session.py` is that
missing middle — no sockets, no I/O, so a gossip loop, an HTTP handler, or a
test drives it identically.

```python
from src.ltp.corridor.session import CorridorSigner, EquivocationMonitor, SigningSession

signer = CorridorSigner(authority=3, secret_key=sk)   # this node's half
session = SigningSession(corridor, payload)
monitor = EquivocationMonitor()

session.submit(signer.sign(payload))         # our own partial
for payload_seen, ws in incoming_partials:   # from the network
    monitor.observe(payload_seen, ws)        # detection is a side effect
    session.submit_for_payload(payload_seen, ws)
    if session.has_quorum:
        break

attestation = session.finalize()             # 7-of-9, aggregated and re-verified
```

`submit` returns `False` for a duplicate rather than raising — peers legitimately
resend. It raises `UnknownWitness` for a non-member and `InvalidSignature` for a
signature that does not verify, and never partially mutates, so one hostile peer
cannot corrupt a round in progress. `session.outstanding()` names the members who
have not signed yet, which is who to chase.

Two safety properties live here that are not in `attest()`:

- **A node must not sign two conflicting payloads.** Paper §6.4 makes fast-path
  equivocation a 100%-slashing offence, and the cheapest way to lose a bond is a
  crash-restart that loses track of what was already signed. `CorridorSigner`
  keeps a per-round record and raises `DoubleSignAttempt` rather than producing
  the evidence that would slash its own operator. Re-signing the *same* payload
  is allowed and returns the identical signature, so a retry after a dropped
  response is safe. This is a local guard: it protects an honest node from an
  accident and does nothing against a node that wants to equivocate. The guard
  is only as durable as you make it — a process that restarts with an empty
  record is exactly the node that signs a conflicting payload for a height it
  already signed, so persist `signer.signed_rounds()` alongside your keys and
  hand it back with `signer.restore(...)` at startup.

- **Equivocation by someone else must be provable.** `EquivocationMonitor` emits
  `EquivocationEvidence` when one witness signs two different state roots for the
  same `(source_chain, target_chain, source_height)`. The evidence is
  self-contained — `evidence.verify(corridor)` re-checks both signatures and that
  the payloads genuinely conflict, so a recipient never has to trust whoever
  reported it. Feed the monitor every partial a node sees, including ones a
  session rejected as `WrongPayload`; that is precisely where equivocation shows
  up.

BLS signing is deterministic, so a witness cannot produce two different valid
signatures over one digest. Equivocation is always two *different payloads*,
never two signatures over one payload — which is why the monitor compares
digests rather than signature bytes.

`EquivocationMonitor` grows with the number of rounds observed; call
`forget_through(height)` once a height is finalized.

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
