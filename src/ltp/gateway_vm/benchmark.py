"""GatewayBenchmark — throughput measurement harness."""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..keypair import KeyPair
from .config import GatewayVMConfig
from .service import GatewayVMService


@dataclass
class BenchmarkResult:
    """Results from a throughput benchmark run."""

    total_events: int
    total_accepted: int
    total_rejected: int
    total_anchor_failures: int
    elapsed_seconds: float
    events_per_minute: float
    ticks: int


def run_benchmark(
    keypair: KeyPair,
    event_count: int = 200,
    events_per_tick: int = 10,
    finality_depth: int = 12,
) -> BenchmarkResult:
    """Run a throughput benchmark.

    Generates event_count unique events, delivers events_per_tick
    per tick, and measures total throughput.
    """
    all_logs = []
    for i in range(event_count):
        all_logs.append(
            {
                "transactionHash": f"0xbench_{i:06d}",
                "blockNumber": 100 + (i // events_per_tick),
                "logIndex": i % events_per_tick,
                "address": "0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
                "event": "AnchorCreated",
                "args": {
                    "sender": "0xbenchsender",
                    "recipient": "0xbenchrecipient",
                    "payloadHash": f"sha3-256:bench{i:06d}",
                    "amount": 1_000_000,
                    "nonce": i,
                },
            }
        )

    cursor = [0]

    def fetch_batch(from_block, to_block):
        start = cursor[0]
        end = min(start + events_per_tick, len(all_logs))
        batch = all_logs[start:end]
        cursor[0] = end
        return batch

    config = GatewayVMConfig(
        enabled=True,
        source_chain_id=84532,
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        finality_depth=finality_depth,
        dest_chain_id=103115120,
        replay_db_path=":memory:",
        challenge_mode="disabled",
    )

    anchor_count = [0]

    def fast_anchor(attestation):
        anchor_count[0] += 1
        return f"0xbench_tx_{anchor_count[0]}"

    svc = GatewayVMService(
        config=config,
        operator_keypair=keypair,
        fetch_logs=fetch_batch,
        get_source_block_number=lambda: 10000,
        get_dest_block_number=lambda: 999,
        anchor_fn=fast_anchor,
        is_signer_authorized=lambda: True,
    )

    total_accepted = 0
    total_rejected = 0
    total_failures = 0
    ticks = 0

    start = time.monotonic()
    while cursor[0] < len(all_logs):
        result = svc.tick()
        total_accepted += result.events_accepted
        total_rejected += result.events_rejected
        total_failures += result.anchor_failures
        ticks += 1
    elapsed = time.monotonic() - start

    events_per_minute = (total_accepted / elapsed) * 60 if elapsed > 0 else 0

    return BenchmarkResult(
        total_events=event_count,
        total_accepted=total_accepted,
        total_rejected=total_rejected,
        total_anchor_failures=total_failures,
        elapsed_seconds=elapsed,
        events_per_minute=events_per_minute,
        ticks=ticks,
    )
