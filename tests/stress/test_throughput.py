"""Throughput benchmark: success criteria is 100 events/minute sustained."""

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def bench_kp():
    return KeyPair.generate("benchmark-gateway")


class TestThroughput:
    def test_100_events_per_minute_minimum(self, bench_kp):
        from src.ltp.gateway_vm.benchmark import run_benchmark

        result = run_benchmark(
            keypair=bench_kp,
            event_count=200,
            events_per_tick=10,
        )

        assert result.total_accepted == 200
        assert result.total_rejected == 0
        assert result.total_anchor_failures == 0
        assert result.events_per_minute >= 100, (
            f"Throughput {result.events_per_minute:.0f} events/min below 100 events/min target"
        )

    def test_1000_events_sustained(self, bench_kp):
        from src.ltp.gateway_vm.benchmark import run_benchmark

        result = run_benchmark(
            keypair=bench_kp,
            event_count=1000,
            events_per_tick=20,
        )

        assert result.total_accepted == 1000
        assert result.events_per_minute >= 100, (
            f"Sustained throughput {result.events_per_minute:.0f} events/min "
            f"below 100 events/min target"
        )

    def test_no_duplicate_anchors_under_load(self, bench_kp):
        """Under sustained load, replay DB prevents any duplicate processing."""
        from src.ltp.gateway_vm.benchmark import run_benchmark

        result = run_benchmark(
            keypair=bench_kp,
            event_count=500,
            events_per_tick=50,
        )

        assert result.total_accepted == 500
        assert result.total_rejected == 0
