"""Tests for Streaming Entity Protocol (Open Questions 4 & 5)."""

import pytest

from src.ltp.streaming import (
    EntityStream,
    StreamChunk,
    StreamConfig,
    StreamManifest,
    StreamState,
)

# ---------------------------------------------------------------------------
# StreamConfig
# ---------------------------------------------------------------------------


class TestStreamConfig:
    def test_defaults(self):
        cfg = StreamConfig()
        assert cfg.chunk_size_bytes == 65_536
        assert cfg.max_concurrent_chunks == 4
        assert cfg.pipeline_enabled is True
        assert cfg.max_chunks_per_stream == 100_000
        assert cfg.stream_timeout_epochs == 720


# ---------------------------------------------------------------------------
# StreamChunk
# ---------------------------------------------------------------------------


class TestStreamChunk:
    def test_size_bytes(self):
        chunk = StreamChunk(stream_id="s1", sequence=0, data=b"hello", chunk_entity_id="cid")
        assert chunk.size_bytes == 5
        assert chunk.committed is False
        assert chunk.committed_epoch == -1


# ---------------------------------------------------------------------------
# StreamManifest
# ---------------------------------------------------------------------------


class TestStreamManifest:
    def test_is_complete(self):
        m = StreamManifest(
            stream_id="s1",
            stream_entity_id="eid",
            total_chunks=3,
            total_size=100,
            shape="application/json",
            chunk_entity_ids=["c0", "c1", "c2"],
        )
        assert m.is_complete is True

    def test_is_incomplete(self):
        m = StreamManifest(
            stream_id="s1",
            stream_entity_id="eid",
            total_chunks=3,
            total_size=100,
            shape="application/json",
            chunk_entity_ids=["c0", "c1"],
        )
        assert m.is_complete is False


# ---------------------------------------------------------------------------
# EntityStream — open/close lifecycle
# ---------------------------------------------------------------------------


class TestEntityStreamLifecycle:
    def setup_method(self):
        self.es = EntityStream()

    def test_open_stream(self):
        sid = self.es.open_stream("sender-1", "text/plain")
        assert isinstance(sid, str)
        assert len(sid) > 0
        assert self.es.get_stream_state(sid) == StreamState.OPEN

    def test_open_stream_appears_in_active(self):
        sid = self.es.open_stream("sender-1", "text/plain")
        assert sid in self.es.active_streams

    def test_close_stream(self):
        sid = self.es.open_stream("sender-1", "text/plain")
        assert self.es.close_stream(sid) is True
        assert self.es.get_stream_state(sid) == StreamState.CLOSED
        assert sid in self.es.active_streams  # closed but not finalized

    def test_close_already_closed(self):
        sid = self.es.open_stream("sender-1", "text/plain")
        self.es.close_stream(sid)
        assert self.es.close_stream(sid) is False

    def test_close_nonexistent(self):
        assert self.es.close_stream("no-such-stream") is False

    def test_stream_state_nonexistent(self):
        assert self.es.get_stream_state("no-such-stream") is None


# ---------------------------------------------------------------------------
# EntityStream — add_chunk
# ---------------------------------------------------------------------------


class TestEntityStreamAddChunk:
    def setup_method(self):
        self.es = EntityStream()
        self.sid = self.es.open_stream("sender-1", "text/plain")

    def test_add_chunk_auto_sequence(self):
        c0 = self.es.add_chunk(self.sid, b"chunk-0")
        c1 = self.es.add_chunk(self.sid, b"chunk-1")
        assert c0.sequence == 0
        assert c1.sequence == 1

    def test_add_chunk_explicit_sequence(self):
        c = self.es.add_chunk(self.sid, b"data", sequence=5)
        assert c.sequence == 5

    def test_add_chunk_generates_entity_id(self):
        c = self.es.add_chunk(self.sid, b"data")
        assert isinstance(c.chunk_entity_id, str)
        assert len(c.chunk_entity_id) > 0

    def test_add_chunk_to_closed_stream_fails(self):
        self.es.close_stream(self.sid)
        with pytest.raises(ValueError, match="not open"):
            self.es.add_chunk(self.sid, b"data")

    def test_add_chunk_to_nonexistent_stream_fails(self):
        with pytest.raises(ValueError, match="Unknown stream"):
            self.es.add_chunk("no-such-stream", b"data")

    def test_add_chunk_exceeds_max_fails(self):
        es = EntityStream(StreamConfig(max_chunks_per_stream=5))
        sid = es.open_stream("s", "t")
        with pytest.raises(ValueError, match="exceeds maximum"):
            es.add_chunk(sid, b"data", sequence=5)

    def test_add_chunk_at_max_minus_one_ok(self):
        es = EntityStream(StreamConfig(max_chunks_per_stream=5))
        sid = es.open_stream("s", "t")
        c = es.add_chunk(sid, b"data", sequence=4)
        assert c.sequence == 4

    def test_get_chunk(self):
        self.es.add_chunk(self.sid, b"hello")
        c = self.es.get_chunk(self.sid, 0)
        assert c is not None
        assert c.data == b"hello"

    def test_get_chunk_nonexistent_stream(self):
        assert self.es.get_chunk("no-such", 0) is None

    def test_get_chunk_out_of_range(self):
        self.es.add_chunk(self.sid, b"hello")
        assert self.es.get_chunk(self.sid, 99) is None


# ---------------------------------------------------------------------------
# EntityStream — mark_chunk_committed
# ---------------------------------------------------------------------------


class TestEntityStreamCommit:
    def setup_method(self):
        self.es = EntityStream()
        self.sid = self.es.open_stream("sender-1", "text/plain")
        self.es.add_chunk(self.sid, b"chunk-0")
        self.es.add_chunk(self.sid, b"chunk-1")

    def test_mark_committed(self):
        assert self.es.mark_chunk_committed(self.sid, 0, epoch=10) is True
        c = self.es.get_chunk(self.sid, 0)
        assert c.committed is True
        assert c.committed_epoch == 10

    def test_mark_committed_nonexistent_stream(self):
        assert self.es.mark_chunk_committed("nope", 0, 10) is False

    def test_mark_committed_out_of_range(self):
        assert self.es.mark_chunk_committed(self.sid, 99, 10) is False

    def test_get_committed_chunks(self):
        self.es.mark_chunk_committed(self.sid, 0, 10)
        committed = self.es.get_committed_chunks(self.sid)
        assert len(committed) == 1
        assert committed[0].sequence == 0

    def test_get_committed_chunks_empty(self):
        assert len(self.es.get_committed_chunks(self.sid)) == 0

    def test_get_committed_chunks_nonexistent(self):
        assert len(self.es.get_committed_chunks("nope")) == 0


# ---------------------------------------------------------------------------
# EntityStream — finalize
# ---------------------------------------------------------------------------


class TestEntityStreamFinalize:
    def setup_method(self):
        self.es = EntityStream()
        self.sid = self.es.open_stream("sender-1", "text/plain")

    def test_finalize_closed_stream(self):
        self.es.add_chunk(self.sid, b"chunk-0")
        self.es.add_chunk(self.sid, b"chunk-1")
        self.es.close_stream(self.sid)
        manifest = self.es.finalize_stream(self.sid)
        assert manifest is not None
        assert manifest.total_chunks == 2
        assert manifest.stream_id == self.sid
        assert len(manifest.chunk_entity_ids) == 2
        assert len(manifest.stream_entity_id) > 0
        assert self.es.get_stream_state(self.sid) == StreamState.FINALIZED

    def test_finalize_open_stream(self):
        self.es.add_chunk(self.sid, b"chunk-0")
        # Can finalize even while open
        manifest = self.es.finalize_stream(self.sid)
        assert manifest is not None

    def test_finalize_with_gaps_returns_none(self):
        self.es.add_chunk(self.sid, b"chunk-0", sequence=0)
        self.es.add_chunk(self.sid, b"chunk-2", sequence=2)
        # sequence=1 is missing (None placeholder)
        self.es.close_stream(self.sid)
        assert self.es.finalize_stream(self.sid) is None

    def test_finalize_empty_stream_returns_none(self):
        self.es.close_stream(self.sid)
        assert self.es.finalize_stream(self.sid) is None

    def test_finalize_nonexistent_returns_none(self):
        assert self.es.finalize_stream("nope") is None

    def test_finalize_already_finalized_returns_none(self):
        self.es.add_chunk(self.sid, b"data")
        self.es.close_stream(self.sid)
        self.es.finalize_stream(self.sid)
        assert self.es.finalize_stream(self.sid) is None

    def test_finalized_stream_in_finalized_list(self):
        self.es.add_chunk(self.sid, b"data")
        self.es.close_stream(self.sid)
        self.es.finalize_stream(self.sid)
        assert self.sid in self.es.finalized_streams
        assert self.sid not in self.es.active_streams

    def test_manifest_shape(self):
        self.es.add_chunk(self.sid, b"data")
        self.es.close_stream(self.sid)
        manifest = self.es.finalize_stream(self.sid)
        assert manifest.shape == "text/plain"

    def test_manifest_total_size(self):
        self.es.add_chunk(self.sid, b"aaaa")  # 4 bytes
        self.es.add_chunk(self.sid, b"bb")  # 2 bytes
        self.es.close_stream(self.sid)
        manifest = self.es.finalize_stream(self.sid)
        assert manifest.total_size == 6

    def test_manifest_is_complete(self):
        self.es.add_chunk(self.sid, b"data")
        self.es.close_stream(self.sid)
        manifest = self.es.finalize_stream(self.sid)
        assert manifest.is_complete is True


# ---------------------------------------------------------------------------
# EntityStream — reassemble
# ---------------------------------------------------------------------------


class TestEntityStreamReassemble:
    def setup_method(self):
        self.es = EntityStream()
        self.sid = self.es.open_stream("sender-1", "text/plain")

    def test_reassemble(self):
        self.es.add_chunk(self.sid, b"Hello, ")
        self.es.add_chunk(self.sid, b"World!")
        result = self.es.reassemble_stream(self.sid)
        assert result == b"Hello, World!"

    def test_reassemble_with_gaps(self):
        self.es.add_chunk(self.sid, b"a", sequence=0)
        self.es.add_chunk(self.sid, b"c", sequence=2)
        assert self.es.reassemble_stream(self.sid) is None

    def test_reassemble_empty(self):
        assert self.es.reassemble_stream(self.sid) is None

    def test_reassemble_nonexistent(self):
        assert self.es.reassemble_stream("nope") is None

    def test_reassemble_preserves_order(self):
        # Add out of order
        self.es.add_chunk(self.sid, b"B", sequence=1)
        self.es.add_chunk(self.sid, b"A", sequence=0)
        self.es.add_chunk(self.sid, b"C", sequence=2)
        assert self.es.reassemble_stream(self.sid) == b"ABC"


# ---------------------------------------------------------------------------
# EntityStream — pipeline schedule
# ---------------------------------------------------------------------------


class TestEntityStreamPipeline:
    def test_pipeline_schedule_small(self):
        es = EntityStream(StreamConfig(chunk_size_bytes=100, max_concurrent_chunks=4))
        schedule = es.compute_pipeline_schedule(250)
        assert schedule["total_size"] == 250
        assert schedule["chunk_size"] == 100
        assert schedule["chunk_count"] == 3
        assert schedule["pipeline_depth"] == 3

    def test_pipeline_schedule_large(self):
        es = EntityStream(StreamConfig(chunk_size_bytes=100, max_concurrent_chunks=4))
        schedule = es.compute_pipeline_schedule(1000)
        assert schedule["chunk_count"] == 10
        assert schedule["pipeline_depth"] == 4
        assert schedule["speedup_factor"] > 1.0

    def test_pipeline_schedule_single_chunk(self):
        es = EntityStream(StreamConfig(chunk_size_bytes=1000, max_concurrent_chunks=4))
        schedule = es.compute_pipeline_schedule(500)
        assert schedule["chunk_count"] == 1
        assert schedule["pipeline_depth"] == 1
        assert schedule["speedup_factor"] == 1.0

    def test_pipeline_schedule_zero_size(self):
        es = EntityStream()
        schedule = es.compute_pipeline_schedule(0)
        assert schedule["chunk_count"] == 1

    def test_pipeline_speedup_is_meaningful(self):
        es = EntityStream(StreamConfig(chunk_size_bytes=1024, max_concurrent_chunks=8))
        schedule = es.compute_pipeline_schedule(1024 * 100)
        # With 100 chunks and depth 8, should have meaningful speedup
        assert schedule["speedup_factor"] > 1.0
        assert schedule["pipelined_sequential_phases"] < schedule["chunk_count"]


# ---------------------------------------------------------------------------
# EntityStream — multiple streams
# ---------------------------------------------------------------------------


class TestEntityStreamMultiple:
    def test_independent_streams(self):
        es = EntityStream()
        s1 = es.open_stream("sender-1", "text/plain")
        s2 = es.open_stream("sender-2", "application/json")
        assert s1 != s2

        es.add_chunk(s1, b"stream-1-data")
        es.add_chunk(s2, b"stream-2-data")

        assert es.reassemble_stream(s1) == b"stream-1-data"
        assert es.reassemble_stream(s2) == b"stream-2-data"

    def test_active_streams_count(self):
        es = EntityStream()
        s1 = es.open_stream("s1", "t")
        s2 = es.open_stream("s2", "t")
        assert len(es.active_streams) == 2

        es.add_chunk(s1, b"d")
        es.close_stream(s1)
        es.finalize_stream(s1)
        assert len(es.active_streams) == 1
        assert len(es.finalized_streams) == 1
