"""
Streaming Transfer — Chunked large entity transfer with backpressure.

When entities are too large for a single commit, ETP supports chunked
streaming: the entity is split into chunks, each committed independently,
then a manifest ties them together for reconstruction.

Usage:
    PYTHONPATH=. python examples/streaming.py
"""

from src.ltp import KeyPair, reset_poc_state
from src.ltp.streaming import EntityStream, StreamConfig, StreamState

reset_poc_state()

# ── Setup ────────────────────────────────────────────────────────────────
alice = KeyPair.generate("alice")

config = StreamConfig(
    chunk_size_bytes=256,  # Small chunks for demo (default: 64KB)
    max_concurrent_chunks=2,  # Parallel chunk processing
    pipeline_enabled=True,  # Pipeline distribution
)
print(f"▸ Stream Config")
print(f"  Chunk size:      {config.chunk_size_bytes} bytes")
print(f"  Max concurrent:  {config.max_concurrent_chunks}")
print(f"  Pipeline:        {config.pipeline_enabled}")

# ── Create a large entity ────────────────────────────────────────────────
large_content = b"A" * 1000 + b"B" * 500 + b"C" * 300
print(f"\n▸ Entity: {len(large_content)} bytes")

# ── Stream: open → add chunks → finalize ─────────────────────────────────
print(f"\n▸ Streaming Transfer")
stream = EntityStream(config)
stream_id = stream.open_stream(
    sender_id="alice",
    shape="application/octet-stream",
    total_size_hint=len(large_content),
)
print(f"  Stream ID: {stream_id[:48]}...")

# Add chunks
offset = 0
chunk_num = 0
while offset < len(large_content):
    end = min(offset + config.chunk_size_bytes, len(large_content))
    chunk_data = large_content[offset:end]
    chunk = stream.add_chunk(stream_id, chunk_data)
    chunk_num += 1
    print(f"  Chunk {chunk_num}: {len(chunk_data)} bytes (seq={chunk.sequence})")
    offset = end

# Close and finalize
stream.close_stream(stream_id)
manifest = stream.finalize_stream(stream_id)
print(f"\n▸ Manifest")
print(f"  Stream ID:    {manifest.stream_id[:48]}...")
print(f"  Total chunks: {manifest.total_chunks}")
print(f"  Total size:   {manifest.total_size} bytes")
print(f"  Entity ID:    {manifest.stream_entity_id[:48]}...")
print(f"  Chunk IDs:    {len(manifest.chunk_entity_ids)} entries")
print(f"  Complete:     {manifest.is_complete}")

# Retrieve chunks for verification
chunks = [stream.get_chunk(stream_id, i) for i in range(manifest.total_chunks)]
reconstructed = b"".join(c.data for c in chunks)
print(f"\n▸ Verification")
print(f"  Reconstructed: {len(reconstructed)} bytes")
print(f"  Match:         {reconstructed == large_content}")

print(f"\n✓ Streaming transfer complete — {chunk_num} chunks processed.")
