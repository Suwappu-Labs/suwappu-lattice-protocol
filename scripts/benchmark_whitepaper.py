#!/usr/bin/env python3
"""Reproduce the measurements in docs/WHITEPAPER.md §7 (Empirical Evaluation).

Every number printed in that section comes from this script. It measures four
things against the reference implementation:

  1. Post-quantum primitive latency (ML-KEM-768, ML-DSA-65) and the throughput
     of both hash lanes.
  2. Reed-Solomon encode/decode throughput at both the implementation default
     (n=8, k=4) and the cost-model default (n=64, k=32).
  3. Wall-clock for each of the three protocol phases, end to end.
  4. Exact artifact sizes -- the sealed lattice key, the commitment record,
     and their constituent parts.

The erasure coder on the conformant path is pure Python, which dominates the
wall-clock at every size. Entity sizes are therefore kept small enough for the
run to finish in a few minutes; the throughputs, ratios, and byte counts are
the transferable results, not the absolute times at any one size.

These are single-host figures for the reference implementation. They are not a
performance claim about a deployed commitment network -- see the whitepaper
§7.5 for what they do and do not support.

Usage:  python3 scripts/benchmark_whitepaper.py [--json]
Requires the production extra:  pip install -e '.[production]'
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time

import ltp
from ltp.commitment import CommitmentNetwork
from ltp.entity import Entity
from ltp.erasure import ErasureCoder
from ltp.keypair import KeyPair
from ltp.lattice import LatticeKey
from ltp.primitives import MLDSA, MLKEM
from ltp.protocol import LTPProtocol
from ltp.shards import ShardEncryptor

# Entity sizes used for the throughput sweeps. 256 KiB is the largest size the
# pure-Python coder gets through at n=64 in reasonable time.
SWEEP = [("64KiB", 1 << 16), ("256KiB", 1 << 18)]

# (n, k) pairs: the implementation default, then the cost-model default used
# throughout §6.4 and Appendix A.
PARAM_SETS = [(8, 4), (64, 32)]

REGIONS = ("us-east", "eu-west", "ap-east", "sa-south")


def median_ms(fn, trials: int = 5, warmup: int = 1) -> float:
    """Median wall-clock of `fn` in milliseconds."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(trials):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(samples)


def build_network(nodes: int = 16) -> CommitmentNetwork:
    net = CommitmentNetwork()
    for i in range(nodes):
        net.add_node(f"node-{i}", REGIONS[i % len(REGIONS)])
    return net


def measure_primitives() -> dict:
    ek, dk = MLKEM.keygen()
    shared_secret, kem_ct = MLKEM.encaps(ek)
    vk, sk = MLDSA.keygen()
    # Sign over a payload the size of a real signable commitment record (§7.4).
    message = os.urandom(473)
    sig = MLDSA.sign(sk, message)

    one_mib = os.urandom(1 << 20)
    canonical_ms = median_ms(lambda: ltp.canonical_hash(one_mib), 30, 3)
    internal_ms = median_ms(lambda: ltp.internal_hash(one_mib), 30, 3)

    return {
        "latency_ms": {
            "mlkem768_keygen": round(median_ms(lambda: MLKEM.keygen(), 50, 3), 4),
            "mlkem768_encaps": round(median_ms(lambda: MLKEM.encaps(ek), 50, 3), 4),
            "mlkem768_decaps": round(median_ms(lambda: MLKEM.decaps(dk, kem_ct), 50, 3), 4),
            "mldsa65_keygen": round(median_ms(lambda: MLDSA.keygen(), 50, 3), 4),
            "mldsa65_sign": round(median_ms(lambda: MLDSA.sign(sk, message), 50, 3), 4),
            "mldsa65_verify": round(median_ms(lambda: MLDSA.verify(vk, message, sig), 50, 3), 4),
        },
        "hash_MiB_per_s": {
            "canonical_lane_sha3_256": round(1000.0 / canonical_ms, 1),
            "internal_lane_blake3": round(1000.0 / internal_ms, 1),
            "internal_speedup": round(canonical_ms / internal_ms, 1),
        },
        "sizes_bytes": {
            "mlkem768_ek": len(ek),
            "mlkem768_dk": len(dk),
            "mlkem768_ciphertext": len(kem_ct),
            "mlkem768_shared_secret": len(shared_secret),
            "mldsa65_vk": len(vk),
            "mldsa65_sk": len(sk),
            "mldsa65_signature": len(sig),
        },
    }


def measure_erasure() -> dict:
    out: dict = {}
    for n, k in PARAM_SETS:
        out[f"n{n}_k{k}"] = {}
        for label, size in SWEEP:
            data = os.urandom(size)
            encode_ms = median_ms(lambda: ErasureCoder.encode(data, n, k), 3, 1)
            shards = ErasureCoder.encode(data, n, k)
            subset = {i: shards[i] for i in range(k)}
            decode_ms = median_ms(lambda: ErasureCoder.decode(subset, n, k), 3, 1)
            mib = size / (1 << 20)
            out[f"n{n}_k{k}"][label] = {
                "encode_ms": round(encode_ms, 2),
                "decode_ms": round(decode_ms, 2),
                "encode_MiB_per_s": round(mib * 1000.0 / encode_ms, 3),
                "decode_MiB_per_s": round(mib * 1000.0 / decode_ms, 3),
                "shard_bytes": len(shards[0]),
            }
    return out


def measure_commit_breakdown() -> dict:
    """Split COMMIT into erasure / AEAD / shard-hash / signature components."""
    sender = KeyPair.generate("bench-sender")
    entity_id = "sha3-256:" + "ab" * 32
    out: dict = {}
    size = 1 << 18
    for n, k in PARAM_SETS:
        data = os.urandom(size)
        shards = ErasureCoder.encode(data, n, k)
        cek = ShardEncryptor.generate_cek()

        erasure_ms = median_ms(lambda: ErasureCoder.encode(data, n, k), 3, 1)
        aead_ms = median_ms(
            lambda: [
                ShardEncryptor.encrypt_shard(cek, entity_id, s, i) for i, s in enumerate(shards)
            ],
            3,
            1,
        )
        encrypted = [
            ShardEncryptor.encrypt_shard(cek, entity_id, s, i) for i, s in enumerate(shards)
        ]
        hash_ms = median_ms(lambda: [ltp.canonical_hash(s) for s in encrypted], 5, 1)
        sign_ms = median_ms(lambda: sender.sign(b"x" * 462), 20, 3)

        total = erasure_ms + aead_ms + hash_ms + sign_ms
        out[f"n{n}_k{k}"] = {
            "entity_bytes": size,
            "total_ms": round(total, 2),
            "erasure_ms": round(erasure_ms, 3),
            "aead_encrypt_ms": round(aead_ms, 3),
            "shard_hash_ms": round(hash_ms, 3),
            "mldsa_sign_ms": round(sign_ms, 3),
            "erasure_pct": round(100 * erasure_ms / total, 1),
            "cryptography_pct": round(100 * (aead_ms + hash_ms + sign_ms) / total, 1),
        }
    return out


def measure_end_to_end() -> dict:
    sender = KeyPair.generate("bench-sender")
    receiver = KeyPair.generate("bench-receiver")
    out: dict = {}
    for n, k in PARAM_SETS:
        out[f"n{n}_k{k}"] = {}
        for label, size in SWEEP:
            content = os.urandom(size)
            commits, lattices, materializes = [], [], []
            sealed = b""
            for _ in range(3):
                proto = LTPProtocol(build_network())
                entity = Entity(content=content, shape="application/octet-stream")
                t0 = time.perf_counter()
                entity_id, record, cek = proto.commit(entity, sender, n=n, k=k)
                t1 = time.perf_counter()
                sealed = proto.lattice(entity_id, record, cek, receiver)
                t2 = time.perf_counter()
                recovered = proto.materialize(sealed, receiver, record)
                t3 = time.perf_counter()
                if recovered != content:
                    raise SystemExit("materialized content does not match committed content")
                commits.append((t1 - t0) * 1000)
                lattices.append((t2 - t1) * 1000)
                materializes.append((t3 - t2) * 1000)
            out[f"n{n}_k{k}"][label] = {
                "commit_ms": round(statistics.median(commits), 2),
                "lattice_ms": round(statistics.median(lattices), 3),
                "materialize_ms": round(statistics.median(materializes), 2),
                "sealed_key_bytes": len(sealed),
            }
    return out


def measure_artifacts() -> dict:
    sender = KeyPair.generate("bench-sender")
    receiver = KeyPair.generate("bench-receiver")
    proto = LTPProtocol(build_network())

    small = Entity(content=b"x" * 1024, shape="text/plain")
    small_id, small_record, small_cek = proto.commit(small, sender, n=8, k=4)
    sealed_small = proto.lattice(small_id, small_record, small_cek, receiver)

    large = Entity(content=os.urandom(1 << 18), shape="application/octet-stream")
    large_id, large_record, large_cek = proto.commit(large, sender, n=8, k=4)
    sealed_large = proto.lattice(large_id, large_record, large_cek, receiver)

    policy = {
        "type": "time-limited",
        "not_before": 1740422400,
        "not_after": 1740508800,
        "max_materializations": 1,
    }
    sealed_policy = proto.lattice(small_id, small_record, small_cek, receiver, access_policy=policy)

    inner = LatticeKey(
        entity_id=small_id,
        cek=small_cek,
        commitment_ref=ltp.canonical_hash(small_record.to_bytes()),
        access_policy={"type": "unrestricted"},
    )

    record_bytes = len(small_record.to_bytes())
    signable = len(small_record.signable_payload())
    sig_len = len(small_record.signature)
    vk_len = len(small_record.sender_vk)

    return {
        "sealed_lattice_key": {
            "entity_1KiB": len(sealed_small),
            "entity_256KiB": len(sealed_large),
            "with_time_limited_policy": len(sealed_policy),
            "inner_payload_canonical": len(inner.canonical_bytes()),
            "constant_envelope_overhead": 1088 + 24 + 16,
        },
        "commitment_record": {
            "total_bytes": record_bytes,
            "signable_payload_bytes": signable,
            "mldsa65_signature_bytes": sig_len,
            "sender_vk_bytes": vk_len,
            "signature_plus_vk_pct": round(100 * (sig_len + vk_len) / record_bytes, 1),
        },
        "entity_id": {
            "example": small_id,
            "char_len": len(small_id),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit raw JSON only")
    args = parser.parse_args()

    ltp.assert_real_crypto()

    results = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "security_profile": str(ltp.get_security_profile()),
            "erasure_backend": os.environ.get("LTP_ERASURE_BACKEND", "pure-python (conformant)"),
        },
        "primitives": measure_primitives(),
        "erasure": measure_erasure(),
        "commit_breakdown": measure_commit_breakdown(),
        "end_to_end": measure_end_to_end(),
        "artifacts": measure_artifacts(),
    }

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    env = results["environment"]
    print(f"LTP whitepaper benchmarks -- {env['platform']}, {env['cpu_count']} CPUs")
    print(f"Profile: {env['security_profile']}")
    print(f"Erasure backend: {env['erasure_backend']}\n")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
