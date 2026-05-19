"""
gRPC servicer for the TransferService — commit/materialize RPCs.

Maps high-level transfer operations to LTPProtocol.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from . import transfer_service_pb2 as ts_pb2
from . import transfer_service_pb2_grpc as ts_pb2_grpc

if TYPE_CHECKING:
    from ..keypair import KeyPair
    from ..protocol import LTPProtocol

logger = logging.getLogger(__name__)

__all__ = ["TransferServicer"]


class TransferServicer(ts_pb2_grpc.TransferServiceServicer):
    """Maps gRPC TransferService RPCs to LTPProtocol operations."""

    def __init__(self, protocol: "LTPProtocol", keypair: "KeyPair") -> None:
        self._protocol = protocol
        self._keypair = keypair

    def CommitEntity(self, request, context):
        """Commit an entity: encode → encrypt → distribute → seal → bundle."""
        from ..entity import Entity
        from ..keypair import KeyPair
        from ..node.transfer_bundle import TransferBundle

        try:
            entity = Entity(
                content=request.content, shape=request.shape or "application/octet-stream"
            )
            n = request.n if request.n > 0 else None
            k = request.k if request.k > 0 else None

            entity_id, record, cek = self._protocol.commit(
                entity,
                self._keypair,
                n=n,
                k=k,
            )

            # Seal to receiver if specified, else to self
            if request.receiver_ek:
                from ..primitives import MLKEM

                if len(request.receiver_ek) != MLKEM.EK_SIZE:
                    return ts_pb2.CommitResponse(
                        success=False,
                        error=(
                            f"invalid receiver_ek size: {len(request.receiver_ek)} "
                            f"(expected {MLKEM.EK_SIZE})"
                        ),
                    )
                receiver_kp = KeyPair(
                    ek=request.receiver_ek,
                    dk=b"",
                    vk=b"",
                    sk=b"",
                    label="receiver",
                )
            else:
                receiver_kp = self._keypair

            sealed_key = self._protocol.lattice(
                entity_id,
                record,
                cek,
                receiver_kp,
            )

            bundle = TransferBundle(sealed_key=sealed_key, record=record)

            return ts_pb2.CommitResponse(
                success=True,
                entity_id=entity_id,
                transfer_bundle=bundle.to_bytes(),
            )
        except Exception as e:
            logger.exception("CommitEntity failed")
            return ts_pb2.CommitResponse(
                success=False,
                error="commit failed: internal error",
            )

    def MaterializeEntity(self, request, context):
        """Materialize an entity from a transfer bundle."""
        from ..node.transfer_bundle import TransferBundle

        try:
            bundle = TransferBundle.from_bytes(request.transfer_bundle)

            content = self._protocol.materialize(
                bundle.sealed_key,
                self._keypair,
                record=bundle.record,
            )

            if content is None:
                return ts_pb2.MaterializeResponse(
                    success=False,
                    error="materialization failed",
                )

            return ts_pb2.MaterializeResponse(
                success=True,
                content=content,
                entity_id=bundle.record.entity_id,
            )
        except Exception as e:
            logger.exception("MaterializeEntity failed")
            return ts_pb2.MaterializeResponse(
                success=False,
                error="materialize failed: internal error",
            )
