"""Tests for WriterAuthorizer protocol (Spec C2 §7).

Covers AuthorizationResult, DispatchDecision, and the runtime-checkable
WriterAuthorizer Protocol — including a concrete implementation that
rejects DEPLOY and allows TRANSFER.
"""

import pytest
import time

from src.ltp.execution.writer_auth import (
    AuthorizationResult,
    DispatchDecision,
    WriterAuthorizer,
)
from src.ltp.execution.types import OperationType
from src.ltp.execution.writer import (
    IdentityTier,
    WriterIdentity,
    ApprovalPath,
    WriterRecord,
    WriterState,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_record() -> WriterRecord:
    """Build a WriterRecord from fabricated bytes (no real KeyPair required)."""
    identity = WriterIdentity(
        tier=IdentityTier.MLDSA,
        fingerprint=b"\xab" * 32,
        mldsa_vk=b"\xcd" * 32,
    )
    return WriterRecord(
        identity=identity,
        state=WriterState.ACTIVE,
        approval_path=ApprovalPath.ADMIN,
        enrolled_at=1_000_000,
    )


# ---------------------------------------------------------------------------
# Test 1 — AuthorizationResult allowed with defaults
# ---------------------------------------------------------------------------

class TestAuthorizationResultAllowed:
    """AuthorizationResult with allowed=True uses correct default fields."""

    def test_allowed_defaults(self):
        result = AuthorizationResult(allowed=True)
        assert result.allowed is True
        assert result.reason is None
        assert result.fee_multiplier == 1.0
        assert result.metadata is None

    def test_allowed_is_frozen(self):
        result = AuthorizationResult(allowed=True)
        with pytest.raises(Exception):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 2 — AuthorizationResult rejected with reason
# ---------------------------------------------------------------------------

class TestAuthorizationResultRejected:
    """AuthorizationResult with allowed=False carries reason and custom fields."""

    def test_rejected_with_reason(self):
        result = AuthorizationResult(
            allowed=False,
            reason="writer not active",
            fee_multiplier=0.0,
            metadata={"code": 403},
        )
        assert result.allowed is False
        assert result.reason == "writer not active"
        assert result.fee_multiplier == 0.0
        assert result.metadata == {"code": 403}

    def test_rejected_no_metadata(self):
        result = AuthorizationResult(allowed=False, reason="banned")
        assert result.metadata is None
        assert result.fee_multiplier == 1.0


# ---------------------------------------------------------------------------
# Test 3 — DispatchDecision fields
# ---------------------------------------------------------------------------

class TestDispatchDecision:
    """DispatchDecision carries allowed, optional reason, multiplier, and record."""

    def test_dispatch_allowed(self):
        record = _fake_record()
        decision = DispatchDecision(
            allowed=True,
            fee_multiplier=1.5,
            writer_record=record,
        )
        assert decision.allowed is True
        assert decision.reason is None
        assert decision.fee_multiplier == 1.5
        assert decision.writer_record is record

    def test_dispatch_denied(self):
        decision = DispatchDecision(allowed=False, reason="rate limit exceeded")
        assert decision.allowed is False
        assert decision.reason == "rate limit exceeded"
        assert decision.writer_record is None

    def test_dispatch_is_frozen(self):
        decision = DispatchDecision(allowed=True)
        with pytest.raises(Exception):
            decision.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 4 — Custom class implementing WriterAuthorizer passes isinstance check
# ---------------------------------------------------------------------------

class TestWriterAuthorizerProtocolConforming:
    """A class with both required methods satisfies the runtime-checkable Protocol."""

    def test_isinstance_passes(self):
        class NoDeployAuthorizer:
            """Rejects DEPLOY; allows everything else."""

            def authorize_writer(
                self,
                writer: WriterRecord,
                operation: OperationType,
                tx_bytes: bytes,
            ) -> AuthorizationResult:
                if operation is OperationType.DEPLOY:
                    return AuthorizationResult(
                        allowed=False,
                        reason="deploy operations are disabled on this VM",
                    )
                return AuthorizationResult(allowed=True)

            def on_writer_state_change(
                self,
                writer: WriterRecord,
                old_state: WriterState,
                new_state: WriterState,
            ) -> None:
                pass  # no-op for test

        auth = NoDeployAuthorizer()
        assert isinstance(auth, WriterAuthorizer)

    def test_rejects_deploy(self):
        class NoDeployAuthorizer:
            def authorize_writer(self, writer, operation, tx_bytes):
                if operation is OperationType.DEPLOY:
                    return AuthorizationResult(
                        allowed=False,
                        reason="deploy operations are disabled on this VM",
                    )
                return AuthorizationResult(allowed=True)

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        auth = NoDeployAuthorizer()
        record = _fake_record()
        result = auth.authorize_writer(record, OperationType.DEPLOY, b"\x00" * 8)
        assert result.allowed is False
        assert "deploy" in result.reason.lower()

    def test_allows_transfer(self):
        class NoDeployAuthorizer:
            def authorize_writer(self, writer, operation, tx_bytes):
                if operation is OperationType.DEPLOY:
                    return AuthorizationResult(
                        allowed=False,
                        reason="deploy operations are disabled on this VM",
                    )
                return AuthorizationResult(allowed=True)

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        auth = NoDeployAuthorizer()
        record = _fake_record()
        result = auth.authorize_writer(record, OperationType.TRANSFER, b"\xff" * 8)
        assert result.allowed is True
        assert result.reason is None


# ---------------------------------------------------------------------------
# Test 5 — Plain class without required methods does NOT pass isinstance check
# ---------------------------------------------------------------------------

class TestWriterAuthorizerProtocolNonConforming:
    """A class missing required methods must not satisfy the Protocol."""

    def test_empty_class_fails(self):
        class NotAnAuthorizer:
            pass

        obj = NotAnAuthorizer()
        assert not isinstance(obj, WriterAuthorizer)

    def test_partial_class_fails(self):
        """Only one of the two required methods present — must still fail."""

        class PartialAuthorizer:
            def authorize_writer(self, writer, operation, tx_bytes):
                return AuthorizationResult(allowed=True)
            # Missing: on_writer_state_change

        obj = PartialAuthorizer()
        assert not isinstance(obj, WriterAuthorizer)
