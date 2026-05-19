"""
gRPC TLS/mTLS credential loading.

Reads certificate/key/CA files from TLSConfig paths and constructs
gRPC ServerCredentials and ChannelCredentials for secure channels.

When TLS is not enabled, returns None — callers fall back to insecure ports.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import grpc

if TYPE_CHECKING:
    from ..observability.tls import TLSConfig

logger = logging.getLogger(__name__)

__all__ = ["load_server_credentials", "load_channel_credentials"]


def load_server_credentials(
    tls_config: "TLSConfig",
) -> Optional[grpc.ServerCredentials]:
    """Load gRPC server credentials from TLSConfig.

    Args:
        tls_config: TLS configuration with cert_path, key_path, ca_path.

    Returns:
        grpc.ServerCredentials for add_secure_port(), or None if TLS disabled.

    Raises:
        FileNotFoundError: If cert/key files don't exist.
        ValueError: If required paths are empty.
    """
    if not tls_config.enabled:
        return None

    if not tls_config.cert_path or not tls_config.key_path:
        raise ValueError("TLS enabled but cert_path or key_path is empty")

    cert_bytes = _read_file(tls_config.cert_path, "server certificate")
    key_bytes = _read_file(tls_config.key_path, "server private key")

    ca_bytes = None
    if tls_config.ca_path:
        ca_bytes = _read_file(tls_config.ca_path, "CA certificate")

    require_client = tls_config.require_client_cert

    credentials = grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)],
        root_certificates=ca_bytes,
        require_client_auth=require_client,
    )

    logger.info(
        "Server TLS credentials loaded (cert=%s, mTLS=%s)",
        tls_config.cert_path,
        require_client,
    )
    return credentials


def load_channel_credentials(
    tls_config: "TLSConfig",
) -> Optional[grpc.ChannelCredentials]:
    """Load gRPC channel credentials from TLSConfig.

    Args:
        tls_config: TLS configuration with cert_path, key_path, ca_path.

    Returns:
        grpc.ChannelCredentials for secure_channel(), or None if TLS disabled.
    """
    if not tls_config.enabled:
        return None

    ca_bytes = None
    if tls_config.ca_path:
        ca_bytes = _read_file(tls_config.ca_path, "CA certificate")

    cert_bytes = None
    key_bytes = None
    if tls_config.cert_path and tls_config.key_path:
        cert_bytes = _read_file(tls_config.cert_path, "client certificate")
        key_bytes = _read_file(tls_config.key_path, "client private key")

    credentials = grpc.ssl_channel_credentials(
        root_certificates=ca_bytes,
        private_key=key_bytes,
        certificate_chain=cert_bytes,
    )

    logger.info(
        "Channel TLS credentials loaded (mTLS=%s)",
        cert_bytes is not None,
    )
    return credentials


def _read_file(path: str, description: str) -> bytes:
    """Read a file and return its contents as bytes."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"{description} not found: {path}")
    except PermissionError:
        raise PermissionError(f"Cannot read {description}: {path}")
