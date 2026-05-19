"""
HTTP Federation Transport — real HTTP client for cross-network shard fetching.

Implements FederationTransport ABC using httpx for connection pooling,
configurable timeouts, and retry with ExponentialBackoff.

Auth headers:
  X-Federation-NIR-Sig      — hex-encoded NIR signature
  X-Federation-Agreement-Sig — hex-encoded agreement signatures (initiator|responder)
  X-Federation-Network-ID    — requester's network ID
"""

from __future__ import annotations

import logging
from typing import Optional

from .federation import FederationAuth, FederationTransport

logger = logging.getLogger(__name__)

__all__ = ["HTTPFederationTransport"]


class HTTPFederationTransport(FederationTransport):
    """HTTP-based federation transport using httpx.

    Sends authenticated requests to remote network REST endpoints
    for shard fetching and entity queries.
    """

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        backoff_base: float = 1.0,
        backoff_max: float = 10.0,
    ) -> None:
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._client = None

    def _get_client(self):
        """Lazy-init httpx client for connection pooling."""
        if self._client is None:
            try:
                import httpx

                self._client = httpx.Client(timeout=self._timeout)
            except ImportError:
                raise ImportError(
                    "httpx is required for HTTP federation transport: pip install httpx"
                )
        return self._client

    def _auth_headers(self, auth: FederationAuth) -> dict[str, str]:
        """Build authentication headers from FederationAuth."""
        headers = {}
        nir = auth.requester_nir
        agreement = auth.agreement

        if hasattr(nir, "signature") and nir.signature:
            headers["X-Federation-NIR-Sig"] = (
                nir.signature.hex() if isinstance(nir.signature, bytes) else str(nir.signature)
            )
        if hasattr(nir, "network_id"):
            headers["X-Federation-Network-ID"] = nir.network_id

        # Encode both agreement signatures
        if hasattr(agreement, "initiator_signature") and agreement.initiator_signature:
            init_sig = (
                agreement.initiator_signature.hex()
                if isinstance(agreement.initiator_signature, bytes)
                else str(agreement.initiator_signature)
            )
            resp_sig = ""
            if hasattr(agreement, "responder_signature") and agreement.responder_signature:
                resp_sig = (
                    agreement.responder_signature.hex()
                    if isinstance(agreement.responder_signature, bytes)
                    else str(agreement.responder_signature)
                )
            headers["X-Federation-Agreement-Sig"] = f"{init_sig}|{resp_sig}"

        return headers

    def fetch_shards(
        self,
        endpoint: str,
        entity_id: str,
        shard_indices: list[int],
        auth: FederationAuth,
    ) -> dict[int, bytes]:
        """Fetch encrypted shards from a remote network via HTTP POST."""
        if not auth.verify():
            logger.warning("HTTPFederation: auth verification failed for %s", endpoint)
            return {}

        url = f"{endpoint}/federation/v1/fetch-shards"
        headers = self._auth_headers(auth)
        payload = {
            "entity_id": entity_id,
            "shard_indices": shard_indices,
        }

        for attempt in range(self._max_retries + 1):
            try:
                client = self._get_client()
                response = client.post(url, json=payload, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    shards = {}
                    for idx_str, shard_hex in data.get("shards", {}).items():
                        shards[int(idx_str)] = bytes.fromhex(shard_hex)
                    return shards
                elif response.status_code == 403:
                    logger.warning("HTTPFederation: auth rejected by %s", endpoint)
                    return {}
                elif response.status_code == 404:
                    return {}
                else:
                    logger.warning(
                        "HTTPFederation: fetch_shards %s returned %d",
                        endpoint,
                        response.status_code,
                    )
            except Exception as e:
                logger.warning(
                    "HTTPFederation: fetch_shards attempt %d failed for %s: %s",
                    attempt + 1,
                    endpoint,
                    e,
                )
                if attempt < self._max_retries:
                    import time

                    delay = min(self._backoff_max, self._backoff_base * (2**attempt))
                    time.sleep(delay)

        return {}

    def query_entity(
        self,
        endpoint: str,
        entity_id: str,
        auth: FederationAuth,
    ) -> Optional[dict]:
        """Query if a remote network holds an entity via HTTP GET."""
        if not auth.verify():
            logger.warning("HTTPFederation: auth verification failed for %s", endpoint)
            return None

        url = f"{endpoint}/federation/v1/entity/{entity_id}"
        headers = self._auth_headers(auth)

        try:
            client = self._get_client()
            response = client.get(url, headers=headers)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                logger.warning(
                    "HTTPFederation: query_entity %s returned %d",
                    endpoint,
                    response.status_code,
                )
                return None
        except Exception as e:
            logger.warning("HTTPFederation: query_entity failed for %s: %s", endpoint, e)
            return None

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None
