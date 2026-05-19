# Streaming Protocol & Bandwidth Amortization

**Status:** Proposal
**Date:** 2026-03-13
**Authors:** LTP Core Team
**Relates to:** Whitepaper §2.1, §3.1, §3.3, Open Questions 4 & 5

---

## Context

LTP currently operates in a strictly batch-oriented mode: a sender commits
an entire entity atomically through the three-phase protocol:

```
COMMIT:       content → ErasureCoder.encode(n=8,k=4) → ShardEncryptor.encrypt → distribute
LATTICE:      seal(entity_id + CEK + commitment_ref) via ML-KEM-768 → receiver
MATERIALIZE:  unseal → fetch_encrypted_shards → decrypt → ErasureCoder.decode → verify
```

This works well for discrete objects (messages, documents, images) but
creates two problems acknowledged in the whitepaper:

1. **Open Question 4:** "Bandwidth for initial shard distribution: The commit
   phase still requires distributing n shards. Can this be amortized or
   pipelined?"
2. **Open Question 5:** "Real-time streaming: Can LTP support continuous
   entity streams (video, telemetry), or is it inherently batch-oriented?"

This document proposes a chunked streaming extension that addresses both
questions without modifying the core three-phase protocol.

---

## Why Streaming Matters

| Use Case | Data Pattern | Problem with Batch |
|----------|-------------|-------------------|
| Live video | Continuous frames, unbounded | Cannot wait for stream end to commit |
| IoT telemetry | High-frequency sensor readings | Per-reading commit overhead prohibitive |
| Large file transfer | Multi-GB payloads | Memory pressure; single-entity commit stalls network |
| Real-time collaboration | Incremental edits | Latency-to-first-byte dominates user experience |

Batch-mode LTP forces the sender to buffer the entire entity before the
first shard reaches any commitment node. For a 1 GB file with n=8, k=4:

```
Monolithic commit:
  encode time:     O(file_size × n)   — all shards produced before any distribution
  distribution:    8 × shard_size     — sequential, blocks on slowest node
  first-byte-out:  encode_time + distribution_time
  memory:          file_size + n × shard_size  ≈ 3× file_size
```

---

## Chunked Commit Model

### Core Idea

Divide the entity into fixed-size **chunks**. Each chunk is independently
committed through the existing COMMIT phase machinery (erasure encode,
encrypt, distribute). The receiver materializes chunks incrementally.

```
Entity (arbitrary size)
  │
  ├── Chunk 0  [chunk_size bytes] → COMMIT → n=8 shards → distribute
  ├── Chunk 1  [chunk_size bytes] → COMMIT → n=8 shards → distribute
  ├── Chunk 2  [chunk_size bytes] → COMMIT → n=8 shards → distribute
  │   ...
  └── Chunk N  [≤ chunk_size]     → COMMIT → n=8 shards → distribute
```

### Chunk Structure

```
ChunkHeader:
  stream_id:    str          # Unique identifier for the stream
  sequence:     int          # 0-indexed chunk position
  chunk_size:   int          # Payload bytes in this chunk
  total_chunks: int | None   # Known if sender has full entity; None for live streams
  flags:        uint8        # FIRST=0x01, LAST=0x02, KEYFRAME=0x04

Chunk:
  header:       ChunkHeader
  payload:      bytes        # Raw chunk content (pre-erasure-coding)
  chunk_id:     str          # H(stream_id || sequence || payload)
```

### Chunk Size Selection

| Chunk Size | Shard Size (k=4) | Shards (n=8) | Total Wire | Use Case |
|-----------|------------------|-------------|-----------|----------|
| 64 KB | ~16 KB | 128 KB | 128 KB | Low-latency telemetry |
| 256 KB | ~64 KB | 512 KB | 512 KB | Interactive video |
| 1 MB | ~256 KB | 2 MB | 2 MB | File transfer (default) |
| 4 MB | ~1 MB | 8 MB | 8 MB | Bulk archival |

Default: **1 MB** chunks. This balances per-chunk commit overhead against
latency-to-first-byte and memory consumption.

---

## Entity Stream

An **entity stream** is an ordered sequence of chunks bound by a shared
`stream_id`. The stream has its own lifecycle independent of any individual
chunk.

### Stream Identification

```
stream_id = H(sender_vk || receiver_ek || stream_nonce || created_at)
```

The `stream_id` is not an `entity_id` — it is a session-level identifier.
Each chunk produces its own `entity_id` through the standard COMMIT phase.
The stream manifest (below) binds them together.

### Ordering Guarantees

- **Sequence numbers** are monotonically increasing, starting at 0
- **Gaps** indicate chunk loss (detected at materialization)
- **Duplicates** are idempotent — same `(stream_id, sequence)` is ignored
- The commitment log's hash-chain provides total ordering within a stream

---

## Stream Manifest

The manifest is the metadata structure that binds all chunks to a single
logical entity. It is committed as a regular LTP entity after the stream
closes.

```
StreamManifest:
  stream_id:       str              # Stream session identifier
  sender_id:       str              # Sender label
  chunk_count:     int              # Total chunks committed
  chunk_entity_ids: list[str]       # Ordered entity_ids for each chunk
  encoding_params: dict             # Shared {n, k, algorithm, gf_poly, eval}
  aggregate_hash:  str              # H(chunk_0_content || chunk_1_content || ... )
  shape:           str              # Media type of the reassembled entity
  created_at:      float            # Stream open timestamp
  closed_at:       float            # Stream close timestamp
  total_bytes:     int              # Sum of all chunk payloads
  signature:       bytes            # ML-DSA-65 over signable fields
```

### Aggregate Entity ID

The reassembled entity gets a verifiable identity:

```
aggregate_entity_id = H(
    aggregate_hash          # H(all chunk contents concatenated)
    || shape                # Media type
    || created_at           # Stream creation timestamp
    || sender_vk            # Sender verification key
)
```

This allows the receiver to verify end-to-end integrity of the complete
stream, matching the existing EntityID verification in `LTPProtocol.materialize()`.

---

## Incremental Materialization

The receiver does not wait for the stream to close before consuming data.
Each chunk can be materialized independently as soon as its lattice key
arrives.

### Protocol Flow

```mermaid
sequenceDiagram
    participant S as Sender
    participant N as Network
    participant R as Receiver

    S->>N: COMMIT(chunk_0)
    N->>R: distribute shards
    S->>R: LATTICE(chunk_0)
    Note over R: MATERIALIZE(chunk_0)

    S->>N: COMMIT(chunk_1)
    N->>R: distribute shards
    S->>R: LATTICE(chunk_1)
    Note over R: MATERIALIZE(chunk_1)

    S->>N: COMMIT(manifest)
    S->>R: LATTICE(manifest)
    Note over R: verify aggregate
```

### Chunk Buffering at Receiver

```
StreamReceiver:
  stream_id:        str
  expected_next:    int              # Next sequence number to consume
  chunk_buffer:     dict[int, bytes] # seq → materialized content
  consumed_up_to:   int              # Highest contiguous seq delivered to app
  manifest:         StreamManifest | None

  on_chunk_materialized(seq, content):
    chunk_buffer[seq] = content
    while expected_next in chunk_buffer:
      deliver_to_application(chunk_buffer.pop(expected_next))
      consumed_up_to = expected_next
      expected_next += 1

  on_manifest_received(manifest):
    self.manifest = manifest
    verify_aggregate_hash()
```

Out-of-order chunks are buffered until the gap is filled. This handles
network reordering without requiring the sender to wait for acknowledgment
of each chunk before sending the next.

---

## Bandwidth Amortization (Open Question 4)

### Problem

Even with chunking, each chunk requires distributing n shards to the
commitment network. For n=8 and a 1 MB chunk, that is 2 MB of network
traffic per chunk.

### Pipelined Distribution

The key insight: **shard distribution for chunk C+1 overlaps with erasure
encoding of chunk C+2 and lattice sealing of chunk C**.

```mermaid
gantt
    title Pipelined vs Monolithic Distribution
    dateFormat X
    axisFormat %s

    section Pipelined
    Chunk 0 encode    :c0e, 0, 1
    Chunk 0 encrypt   :c0x, after c0e, 1
    Chunk 0 distribute:c0d, after c0x, 1
    Chunk 1 encode    :c1e, after c0e, 1
    Chunk 1 encrypt   :c1x, after c1e, 1
    Chunk 1 distribute:c1d, after c1x, 1
    Chunk 2 encode    :c2e, after c1e, 1
    Chunk 2 encrypt   :c2x, after c2e, 1
    Chunk 2 distribute:c2d, after c2x, 1

    section Monolithic
    Encode all         :me, 0, 3
    Encrypt all        :mx, after me, 3
    Distribute all     :md, after mx, 3
```

### Amortization Mechanics

| Technique | Mechanism | Bandwidth Saving |
|-----------|-----------|-----------------|
| Pipeline overlap | Encode/encrypt/distribute phases run concurrently across chunks | ~3x throughput improvement |
| Incremental shard placement | Nodes accept shards for chunk C+1 while still acknowledging chunk C | Eliminates distribution stalls |
| CEK reuse within stream | All chunks in a stream share a single CEK (sealed once in manifest) | Eliminates per-chunk LATTICE overhead |
| Delta encoding (optional) | For telemetry: encode only diff from previous chunk | 10-90% payload reduction |
| Batched commitment records | Multiple chunk records written to log in a single batch append | Reduces log write amplification |

### CEK Strategy

Two options for stream-level key management:

```
Option A: Per-chunk CEK (default, maximum isolation)
  - Each chunk gets an independent CEK
  - Chunk compromise does not leak other chunks
  - Higher LATTICE overhead: one sealed key per chunk
  - Suitable for: high-security, sparse streams

Option B: Stream CEK (amortized, lower overhead)
  - Single CEK for all chunks, sealed once in the stream manifest
  - Chunk lattice keys contain only: chunk_entity_id + stream_id + sequence
  - Stream CEK sealed to receiver once at stream open
  - Suitable for: video, bulk transfer, telemetry
```

Default: **Option B** for streams, **Option A** for standalone entities
(preserving backward compatibility with existing `LTPProtocol.commit()`).

---

## Backpressure

The receiver must be able to signal when it cannot keep up with the sender's
chunk rate. Without backpressure, the commitment network accumulates
unprocessed shards and the receiver's chunk buffer grows unboundedly.

### Backpressure Protocol

```
BackpressureSignal:
  stream_id:       str
  receiver_id:     str
  consumed_up_to:  int          # Highest contiguous sequence consumed
  buffer_depth:    int          # Number of buffered-but-unconsumed chunks
  ready_for_next:  bool         # Explicit readiness signal
  max_in_flight:   int          # Receiver's preferred window size

Sender behavior:
  in_flight = last_committed_seq - receiver.consumed_up_to
  if in_flight >= receiver.max_in_flight:
    pause chunk production until next BackpressureSignal

Default max_in_flight: 4 chunks
```

### Flow Control Window

```
Sender committed:    [0] [1] [2] [3] [4] [5]
                      ✓   ✓   ✓   ▪   ▪   ▪
Receiver consumed:   [0] [1] [2]
                                   ←─ window = 3 in flight ─→

If max_in_flight = 4: sender may commit chunk 6
If max_in_flight = 3: sender pauses until receiver consumes chunk 3
```

### Backpressure via Commitment Network

Backpressure signals are routed through the commitment network as
lightweight control messages (not full entities). They are **not**
erasure-coded or encrypted — they carry no sensitive payload.

```
Control message overhead: ~128 bytes per signal
Frequency: one per consumed chunk (piggybacks on materialization)
```

---

## Stream Lifecycle

```mermaid
stateDiagram-v2
    [*] --> OPEN: stream_open()
    OPEN --> STREAMING: First chunk committed
    STREAMING --> CLOSING: Last chunk (LAST flag)
    CLOSING --> FINALIZED: Manifest committed\nand verified
    OPEN --> ABORTED: abort()
    STREAMING --> ABORTED: abort()
    CLOSING --> ABORTED: abort()
```

**OPEN:** Generate stream_id, negotiate chunk_size and encoding params, seal stream CEK to receiver (if Option B).

**STREAMING:** Sender commits chunks sequentially (pipelined), receiver materializes and consumes incrementally, backpressure regulates flow.

**CLOSING:** Sender signals end-of-stream (LAST flag on final chunk). No more chunks accepted.

**FINALIZED:** Sender commits the StreamManifest as a regular entity. Manifest sealed to receiver via LATTICE. Receiver verifies aggregate_entity_id.

### State Transitions

| From | To | Trigger | Reversible |
|------|----|---------|-----------|
| (none) | OPEN | Sender calls stream_open() | No |
| OPEN | STREAMING | First chunk committed | No |
| STREAMING | CLOSING | Last chunk committed (LAST flag) | No |
| CLOSING | FINALIZED | Manifest committed and verified | No |
| Any | ABORTED | Sender or receiver calls abort() | No |

---

## Latency Analysis

### Monolithic vs. Chunked Commit

For an entity of size S, chunk size C, n=8, k=4:

```
Monolithic:
  T_encode     = α × S × n                  # Erasure encode entire entity
  T_encrypt    = β × S × n                  # Encrypt all shards
  T_distribute = γ × S × n / k              # Transfer all shards (shard_size = S/k + overhead)
  T_total      = T_encode + T_encrypt + T_distribute

Chunked (no pipelining):
  T_per_chunk  = α × C × n + β × C × n + γ × C × n / k
  T_total      = ceil(S / C) × T_per_chunk
  T_first_byte = T_per_chunk                # First chunk available to receiver

Chunked (pipelined, p pipeline stages):
  T_total      = T_per_chunk + (ceil(S / C) - 1) × max(T_encode_c, T_encrypt_c, T_distribute_c)
  T_first_byte = T_per_chunk                # Unchanged — pipeline doesn't help first chunk
```

### Numerical Example

| Metric | Monolithic (1 GB) | Chunked (1 MB × 1024) | Chunked + Pipelined |
|--------|------------------|----------------------|-------------------|
| First byte to receiver | ~30 s | ~30 ms | ~30 ms |
| Total transfer time | ~30 s | ~31 s | ~11 s |
| Peak sender memory | ~3 GB | ~3 MB | ~9 MB (3 chunks in flight) |
| Commitment log entries | 1 | 1024 + 1 (manifest) | 1024 + 1 |

The critical improvement is **first-byte latency**: 1000x reduction for
the 1 GB case. Total transfer time improves ~3x with pipelining due to
overlap of encode/encrypt/distribute stages across chunks.

---

## Stream Integrity

### Per-Chunk Integrity

Each chunk inherits the full integrity guarantees of a standard LTP entity:

1. **EntityID binding:** `chunk_id = H(stream_id || sequence || payload)`
2. **AEAD authentication:** Shard tampering detected at decrypt time
3. **ML-DSA signature:** Commitment record signed by sender
4. **Commitment reference:** Lattice key contains hash of commitment record

### Aggregate Integrity

The stream manifest provides end-to-end verification of the complete stream:

```
Verification steps:
  1. Materialize manifest entity
  2. Verify manifest ML-DSA signature
  3. For each chunk_entity_id in manifest.chunk_entity_ids:
     a. Verify chunk was committed (exists in log)
     b. Verify chunk's commitment record signature
  4. Concatenate all materialized chunk contents in sequence order
  5. Compute aggregate_hash = H(chunk_0 || chunk_1 || ... || chunk_N)
  6. Verify aggregate_hash matches manifest.aggregate_hash
  7. Compute aggregate_entity_id from aggregate_hash + metadata
  8. Verify aggregate_entity_id matches manifest
```

### Partial Verification

For live streams where the manifest is not yet available, the receiver
can still verify each chunk independently. Full aggregate verification
is deferred to finalization.

---

## Failure Modes

### Partial Streams

**Problem:** Sender crashes or disconnects mid-stream. Some chunks are
committed, others are not. No manifest exists.

**Handling:**

```
Detection:
  - Receiver observes no new chunks for stream_timeout (default: 60s)
  - Receiver sends a PING control message; no response triggers ABORTED state

Recovery:
  - Already-materialized chunks are valid and usable
  - Receiver can request stream resumption from sender
  - Sender resumes from last acknowledged sequence number
  - If sender is permanently gone: partial content is available up to
    the last committed chunk (graceful degradation)

Stream Resumption:
  stream_resume(stream_id, resume_from_seq):
    - Sender verifies receiver.consumed_up_to
    - Continues committing from resume_from_seq
    - Manifest updated to reflect final chunk count
```

### Chunk Loss

**Problem:** A chunk's shards become unavailable (node evictions, regional
failure) before the receiver materializes it.

**Handling:**

| Lost Shards | Impact | Recovery |
|------------|--------|----------|
| < n-k (≤ 4 of 8) | None — erasure coding reconstructs | Automatic via ErasureCoder.decode() |
| ≥ n-k (≥ 5 of 8) | Chunk irrecoverable | Gap in stream; receiver notified |
| All shards for a chunk | Chunk lost | Sender re-commits chunk if still available |

Gap handling at receiver:

```
if chunk_gap_detected(seq):
  if sender_alive:
    request_recommit(stream_id, seq)
  else:
    mark_gap(seq)  # Application decides: skip, interpolate, or fail
```

### Chunk Reordering

**Problem:** Chunks arrive at the receiver out of sequence order due to
variable distribution latency across commitment nodes.

**Handling:**

- The `StreamReceiver.chunk_buffer` absorbs reordering (see Incremental
  Materialization above)
- Chunks are delivered to the application only in sequence order
- Buffer depth is bounded by `max_in_flight` (backpressure prevents
  unbounded buffering)
- If a gap persists beyond `reorder_timeout` (default: 5s), the receiver
  requests retransmission

### Manifest Loss

**Problem:** Stream completes but the manifest entity is lost or corrupted.

**Handling:**

- Individual chunks remain independently valid and materializable
- Receiver can reconstruct the manifest locally from its chunk buffer:
  - chunk_entity_ids are known from materialized lattice keys
  - aggregate_hash is computable from chunk contents
- Reconstructed manifest lacks the sender's ML-DSA signature (cannot be
  verified as authentic), but chunk-level signatures remain valid

---

## Comparison: Batch vs. Streaming Mode

| Property | Batch (current) | Streaming (proposed) |
|----------|----------------|---------------------|
| Atomicity | Full entity | Per-chunk |
| First-byte latency | O(entity_size) | O(chunk_size) |
| Memory footprint | O(entity_size) | O(chunk_size × pipeline_depth) |
| Commitment log entries | 1 per entity | N+1 per entity (chunks + manifest) |
| Integrity verification | Single EntityID | Per-chunk + aggregate |
| Failure granularity | All-or-nothing | Per-chunk recovery |
| Bandwidth amortization | None | Pipelined distribution |
| Backward compatible | N/A | Yes — chunks are standard entities |

---

## Implementation Path

The streaming extension builds on existing abstractions without modifying
core protocol code:

```
src/ltp/
├── protocol.py          # Existing: LTPProtocol (unchanged)
├── streaming.py         # New: StreamSender, StreamReceiver, StreamManifest
├── erasure.py           # Existing: ErasureCoder (unchanged)
├── commitment.py        # Existing: CommitmentNetwork (unchanged)
├── shards.py            # Existing: ShardEncryptor (unchanged)
└── backpressure.py      # New: BackpressureController, flow control
```

Usage:

```python
from ltp.streaming import StreamSender, StreamReceiver

# Sender side
sender = StreamSender(protocol, sender_keypair, receiver_keypair,
                      chunk_size=1_048_576)  # 1 MB chunks
stream_id = sender.open()

for chunk_data in read_file_in_chunks(large_file):
    sender.commit_chunk(chunk_data)

sender.close()  # Commits manifest

# Receiver side
receiver = StreamReceiver(protocol, receiver_keypair, stream_id)

for chunk in receiver:
    process(chunk)  # Chunks delivered in order, incrementally

receiver.verify_aggregate()  # After manifest arrives
```

---

## Recommendation

**Immediate (P0):**
- Define `ChunkHeader` and `StreamManifest` data structures
- Implement `StreamSender` with sequential (non-pipelined) chunk commit
- Implement `StreamReceiver` with buffered in-order delivery

**Near-term (P1):**
- Add pipelined distribution (overlapped encode/encrypt/distribute)
- Implement backpressure controller
- Add stream resumption protocol

**Future (P2):**
- Delta encoding for telemetry streams
- Adaptive chunk sizing based on network conditions
- Multi-receiver streams (fan-out: one commit, multiple lattice keys)
