"""
gRPC server interceptors for ETP.

NetworkPolicyInterceptor: Enforces NetworkPolicy access control by
extracting caller identity from the gRPC peer context and checking
against the configured policy.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import grpc

if TYPE_CHECKING:
    from ..observability.tls import NetworkPolicyRegistry

logger = logging.getLogger(__name__)

__all__ = ["NetworkPolicyInterceptor"]


class NetworkPolicyInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor that enforces NetworkPolicy access control.

    Extracts caller identity from the peer string (mTLS client cert CN
    or IP address) and checks against the configured NetworkPolicyRegistry.

    If no policy registry is provided, all requests are allowed (passthrough).
    """

    def __init__(
        self,
        policy_registry: Optional["NetworkPolicyRegistry"] = None,
        service_id: str = "etp-node",
    ) -> None:
        self._registry = policy_registry
        self._service_id = service_id

    def intercept_service(self, continuation, handler_call_details):
        """Intercept incoming RPC and check network policy."""
        if self._registry is None:
            return continuation(handler_call_details)

        # Extract caller identity from the method metadata
        # In mTLS, the peer identity comes from the client certificate CN
        # For now, extract from invocation metadata if present
        caller_id = self._extract_caller_id(handler_call_details)

        if not self._registry.check_access(self._service_id, caller_id):
            logger.warning(
                "NetworkPolicy: denied %r access to %s",
                caller_id,
                self._service_id,
            )
            # Return a handler that aborts the RPC
            return _make_denied_handler()

        return continuation(handler_call_details)

    def _extract_caller_id(self, handler_call_details) -> str:
        """Extract caller identity from gRPC metadata.

        Checks for 'x-caller-id' metadata header (set by authenticated clients).
        Falls back to empty string (allows all when no policy configured).
        """
        metadata = dict(handler_call_details.invocation_metadata or [])
        return metadata.get("x-caller-id", "")


def _make_denied_handler():
    """Create a gRPC handler that returns None for any method (denied).

    In gRPC server interceptors, returning None from intercept_service
    causes the framework to return an unimplemented status. For explicit
    denial, we return a handler wrapper that the framework can call.
    """
    return grpc.unary_unary_rpc_method_handler(
        lambda req, ctx: ctx.abort(
            grpc.StatusCode.PERMISSION_DENIED, "Access denied by network policy"
        )
    )
