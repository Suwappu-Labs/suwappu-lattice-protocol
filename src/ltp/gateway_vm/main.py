"""GatewayVM — unified entry point with lifecycle management.

Follows the ETPNode pattern: ordered startup, signal registration,
reverse-startup teardown on shutdown.

Startup order:
  1. ReplayDB (persistence layer)
  2. GatewayVMService (daemon process, depends on ReplayDB)
  3. Signal handlers (registered after service is running)

Teardown order (reverse):
  1. Service.stop() (daemon thread joins)
  2. ReplayDB.close() (persistence flushed)
"""

from __future__ import annotations

import signal
from typing import Callable, Optional

from ..keypair import KeyPair
from ..observability.logging import StructuredLogger
from .config import GatewayVMConfig
from .replay import ReplayDB
from .service import GatewayVMService
from .writer import GatewayAttestation


class GatewayVM:
    """Unified gateway VM process with lifecycle management.

    Manages startup ordering, OS signal handling, and reverse-startup
    teardown. Wraps GatewayVMService with operational concerns.
    """

    def __init__(
        self,
        config: GatewayVMConfig,
        operator_keypair: KeyPair,
        fetch_logs: Callable[[int, int], list[dict]],
        get_source_block_number: Callable[[], int],
        get_dest_block_number: Callable[[], int],
        anchor_fn: Callable[[GatewayAttestation], str],
        is_signer_authorized: Callable[[], bool],
    ) -> None:
        self._config = config
        self._log = StructuredLogger(
            f"etp.gateway-vm.{config.gateway_id}",
            default_fields={"gateway_id": config.gateway_id},
        )
        self._running = False

        # --- Startup order 1: Persistence ---
        self._replay_db = ReplayDB(config.replay_db_path)

        # --- Startup order 2: Service ---
        self._service = GatewayVMService(
            config=config,
            operator_keypair=operator_keypair,
            fetch_logs=fetch_logs,
            get_source_block_number=get_source_block_number,
            get_dest_block_number=get_dest_block_number,
            anchor_fn=anchor_fn,
            is_signer_authorized=is_signer_authorized,
        )

        self._prev_sigterm = None
        self._prev_sigint = None

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start the gateway VM in order: replay DB -> service -> signals."""
        if self._running:
            return

        self._log.info("starting gateway VM", mode=self._config.mode)

        # Step 2: Start service daemon
        self._service.start()

        # Step 3: Register signal handlers
        self._prev_sigterm = signal.getsignal(signal.SIGTERM)
        self._prev_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        self._running = True
        self._log.info(
            "gateway VM started",
            source_chain=self._config.source_chain_id,
            dest_chain=self._config.dest_chain_id,
        )

    def stop(self) -> None:
        """Stop the gateway VM in reverse startup order."""
        if not self._running:
            return

        self._log.info("stopping gateway VM", epoch=self._service.epoch)
        self._running = False

        # Reverse step 3: Restore signal handlers
        if self._prev_sigterm is not None:
            signal.signal(signal.SIGTERM, self._prev_sigterm)
            self._prev_sigterm = None
        if self._prev_sigint is not None:
            signal.signal(signal.SIGINT, self._prev_sigint)
            self._prev_sigint = None

        # Reverse step 2: Stop service
        try:
            self._service.stop()
        except Exception as exc:
            self._log.error("error stopping service", error=str(exc))

        # Reverse step 1: Close replay DB
        try:
            self._replay_db.close()
        except Exception as exc:
            self._log.error("error closing replay DB", error=str(exc))

        self._log.info("gateway VM stopped")

    def _signal_handler(self, signum, frame) -> None:
        """Handle SIGTERM/SIGINT by triggering orderly shutdown."""
        self._log.info("received signal, shutting down", signal=signum)
        self.stop()
