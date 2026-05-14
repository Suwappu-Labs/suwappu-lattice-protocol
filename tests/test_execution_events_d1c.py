"""Tests for ExecutionEvent system and ConsensusEventType extensions (Spec D1c §1)."""

import pytest

from src.ltp.execution.execution_events import ExecutionEventType, ExecutionEvent
from src.ltp.consensus.events import ConsensusEventType
from src.ltp.execution.execution_config import ExecutionConfig


class TestExecutionEventType:

    def test_enum_has_five_values(self):
        values = list(ExecutionEventType)
        assert len(values) == 5

    def test_loop_started(self):
        assert ExecutionEventType.LOOP_STARTED.value == "loop_started"

    def test_loop_stopped(self):
        assert ExecutionEventType.LOOP_STOPPED.value == "loop_stopped"

    def test_failure_threshold_warning(self):
        assert ExecutionEventType.FAILURE_THRESHOLD_WARNING.value == "failure_threshold_warning"

    def test_execution_halted(self):
        assert ExecutionEventType.EXECUTION_HALTED.value == "execution_halted"

    def test_epoch_metrics_reset(self):
        assert ExecutionEventType.EPOCH_METRICS_RESET.value == "epoch_metrics_reset"


class TestExecutionEvent:

    def test_creation_with_all_fields(self):
        event = ExecutionEvent(
            event_type=ExecutionEventType.LOOP_STARTED,
            round=0, epoch=1, timestamp_ms=1000,
            payload={"round": 0, "epoch": 1},
        )
        assert event.event_type == ExecutionEventType.LOOP_STARTED
        assert event.round == 0
        assert event.epoch == 1
        assert event.timestamp_ms == 1000
        assert event.payload == {"round": 0, "epoch": 1}

    def test_frozen_dataclass(self):
        event = ExecutionEvent(
            event_type=ExecutionEventType.LOOP_STOPPED,
            round=5, epoch=1, timestamp_ms=5000,
            payload={"round": 5, "epoch": 1, "total_batches": 5},
        )
        with pytest.raises(AttributeError):
            event.round = 10


class TestConsensusEventTypeExtensions:

    def test_batch_executed_exists(self):
        assert ConsensusEventType.BATCH_EXECUTED.value == "batch_executed"

    def test_state_root_attested_exists(self):
        assert ConsensusEventType.STATE_ROOT_ATTESTED.value == "state_root_attested"

    def test_original_values_still_present(self):
        assert ConsensusEventType.EPOCH_TRANSITION.value == "epoch_transition"
        assert ConsensusEventType.VALIDATOR_EVICTED.value == "validator_evicted"
        assert ConsensusEventType.COMMIT_ATTESTED.value == "commit_attested"
        assert ConsensusEventType.ENGINE_REBUILT.value == "engine_rebuilt"

    def test_total_enum_count(self):
        assert len(list(ConsensusEventType)) == 6


class TestExecutionConfig:

    def test_default_values(self):
        cfg = ExecutionConfig()
        assert cfg.failure_threshold_pct == 50.0
        assert cfg.halt_on_catastrophic is True
        assert cfg.failure_window == 100
        assert cfg.attestation_mode == "dual"

    def test_custom_values(self):
        cfg = ExecutionConfig(
            failure_threshold_pct=25.0,
            halt_on_catastrophic=False,
            failure_window=50,
            attestation_mode="mldsa_only",
        )
        assert cfg.failure_threshold_pct == 25.0
        assert cfg.halt_on_catastrophic is False
        assert cfg.failure_window == 50
        assert cfg.attestation_mode == "mldsa_only"

    def test_frozen(self):
        cfg = ExecutionConfig()
        with pytest.raises(AttributeError):
            cfg.failure_window = 200
