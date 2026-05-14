"""Tests for consensus event types (Spec D1b §1)."""

import pytest

from src.ltp.consensus.events import ConsensusEvent, ConsensusEventType


class TestConsensusEventType:
    """ConsensusEventType enum tests."""

    def test_enum_has_four_values(self):
        # Extended to 6 in D1c (BATCH_EXECUTED, STATE_ROOT_ATTESTED added)
        assert len(ConsensusEventType) == 6

    def test_epoch_transition_exists(self):
        assert ConsensusEventType.EPOCH_TRANSITION.value == "epoch_transition"

    def test_validator_evicted_exists(self):
        assert ConsensusEventType.VALIDATOR_EVICTED.value == "validator_evicted"

    def test_commit_attested_exists(self):
        assert ConsensusEventType.COMMIT_ATTESTED.value == "commit_attested"

    def test_engine_rebuilt_exists(self):
        assert ConsensusEventType.ENGINE_REBUILT.value == "engine_rebuilt"


class TestConsensusEvent:
    """ConsensusEvent dataclass tests."""

    def test_event_creation_with_all_fields(self):
        event = ConsensusEvent(
            event_type=ConsensusEventType.EPOCH_TRANSITION,
            epoch=5,
            round=1000,
            timestamp_ms=1234567890,
            payload={"old_epoch": 4, "new_epoch": 5},
        )
        assert event.event_type == ConsensusEventType.EPOCH_TRANSITION
        assert event.epoch == 5
        assert event.round == 1000
        assert event.timestamp_ms == 1234567890
        assert event.payload == {"old_epoch": 4, "new_epoch": 5}

    def test_event_is_frozen(self):
        event = ConsensusEvent(
            event_type=ConsensusEventType.COMMIT_ATTESTED,
            epoch=1,
            round=10,
            timestamp_ms=0,
            payload={},
        )
        with pytest.raises(AttributeError):
            event.epoch = 2  # type: ignore[misc]

    def test_each_event_type_has_distinct_payload_keys(self):
        """Verify expected payload shapes per event type."""
        epoch_payload = {
            "old_epoch": 0, "new_epoch": 1,
            "validator_count": 4, "dkg_completed": True,
        }
        evicted_payload = {
            "writer_fp": b"\x01" * 32, "validator_index": 2,
            "reason": "crash", "remaining_active": 3,
        }
        attested_payload = {
            "round": 5, "batch_digest": b"\xab" * 32,
            "signature": b"\xcd" * 96,
        }
        rebuilt_payload = {
            "epoch": 2, "validator_count": 7,
            "quorum_threshold": 5,
        }

        for event_type, payload in [
            (ConsensusEventType.EPOCH_TRANSITION, epoch_payload),
            (ConsensusEventType.VALIDATOR_EVICTED, evicted_payload),
            (ConsensusEventType.COMMIT_ATTESTED, attested_payload),
            (ConsensusEventType.ENGINE_REBUILT, rebuilt_payload),
        ]:
            event = ConsensusEvent(
                event_type=event_type,
                epoch=1, round=0, timestamp_ms=0,
                payload=payload,
            )
            assert event.payload == payload
