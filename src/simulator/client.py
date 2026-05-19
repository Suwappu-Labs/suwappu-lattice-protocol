"""
Simulation client — a sender or receiver agent located in a region.

SimClient drives the LTP protocol through all three phases while routing
operations through the simulated network. It uses the real cryptographic
primitives (Entity, ErasureCoder, ShardEncryptor, LatticeKey, KeyPair) but
routes shard storage/fetch through the NetworkSimulator's message bus,
applying realistic latency and failure modelling.
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from src.ltp.commitment import CommitmentRecord
from src.ltp.entity import Entity
from src.ltp.erasure import ErasureCoder
from src.ltp.keypair import KeyPair
from src.ltp.lattice import LatticeKey
from src.ltp.primitives import MLDSA, canonical_hash
from src.ltp.shards import ShardEncryptor

if TYPE_CHECKING:
    from .network import NetworkSimulator


class SimClient:
    """
    A participant in the LTP simulation — either sender or receiver.

    Each client has:
      - A KeyPair (ML-KEM-768 + ML-DSA-65)
      - A location (region) in the topology
      - A reference to the NetworkSimulator for routing operations

    The client executes real LTP cryptographic operations but delegates
    all network communication to the simulator, which applies latency,
    bandwidth constraints, and failure injection.
    """

    def __init__(
        self,
        label: str,
        region: str,
        keypair: KeyPair,
        simulator: "NetworkSimulator",
    ) -> None:
        self.label = label
        self.region = region
        self.keypair = keypair
        self.simulator = simulator

        # Track transfers this client is involved in
        self._committed_entities: dict[str, CommitmentRecord] = {}
        self._cek_store: dict[str, bytes] = {}

    @property
    def node_id(self) -> str:
        """Virtual node ID for this client in the topology."""
        return f"client-{self.label}"

    # ------------------------------------------------------------------
    # PHASE 1: COMMIT
    # ------------------------------------------------------------------

    def commit(
        self,
        content: bytes,
        shape: str = "application/octet-stream",
        n: int = 8,
        k: int = 4,
        replicas: int = 2,
    ) -> str:
        """
        Execute PHASE 1: COMMIT.

        1. Construct Entity and compute EntityID
        2. Erasure encode into n shards
        3. Generate CEK, encrypt each shard
        4. Distribute encrypted shards via the simulated network
        5. Build and sign CommitmentRecord
        6. Append to the simulator's commitment log

        Returns: entity_id
        """
        sim = self.simulator
        metrics = sim.metrics.new_transfer("")
        metrics.sender = self.label
        metrics.sender_region = self.region
        metrics.n_shards = n
        metrics.k_shards = k
        metrics.replicas_per_shard = replicas

        commit_start = sim.clock.now

        # 1. Construct entity and compute ID
        entity = Entity(content=content, shape=shape)
        timestamp = time.time()
        entity_id = entity.compute_id(self.keypair.vk, timestamp)

        metrics.entity_id = entity_id
        metrics.entity_size_bytes = len(content)
        metrics.commit_start_ms = commit_start

        # Update the metrics key now that we have entity_id
        sim.metrics._transfers.pop("", None)
        sim.metrics._transfers[entity_id] = metrics
        if "" in sim.metrics._transfer_order:
            idx = sim.metrics._transfer_order.index("")
            sim.metrics._transfer_order[idx] = entity_id

        # 2. Erasure encode
        encode_start = sim.clock.now
        plaintext_shards = ErasureCoder.encode(content, n, k)
        # Simulate encoding time proportional to data size
        encode_time = max(0.1, len(content) / (500 * 1024 * 1024) * 1000)  # ~500MB/s
        sim.clock.advance_to(sim.clock.now + encode_time)
        metrics.erasure_encode_ms = encode_time

        # 3. Generate CEK and encrypt shards
        encrypt_start = sim.clock.now
        cek = ShardEncryptor.generate_cek()
        encrypted_shards = [
            ShardEncryptor.encrypt_shard(cek, entity_id, shard, i)
            for i, shard in enumerate(plaintext_shards)
        ]
        # Simulate encryption time
        encrypt_time = max(0.1, len(content) / (200 * 1024 * 1024) * 1000)  # ~200MB/s
        sim.clock.advance_to(sim.clock.now + encrypt_time)
        metrics.shard_encrypt_ms = encrypt_time

        # 4. Distribute encrypted shards via the network
        dist_start = sim.clock.now
        shard_hashes = []
        max_delivery_time = 0.0

        for i, enc_shard in enumerate(encrypted_shards):
            shard_hash = canonical_hash(enc_shard + entity_id.encode() + struct.pack(">I", i))
            shard_hashes.append(shard_hash)

            target_nodes = sim.placement(entity_id, i, replicas)
            for node in target_nodes:
                latency = sim.topology.latency_between_nodes(
                    self.node_id, node.node_id, payload_bytes=len(enc_shard)
                )
                lost = False
                link = sim._get_link_for_nodes(self.node_id, node.node_id)
                if link and link.is_packet_lost():
                    lost = True

                msg = sim.bus.send(
                    msg_type=sim._msg_types.SHARD_STORE_REQUEST,
                    source=self.node_id,
                    destination=node.node_id,
                    payload_bytes=len(enc_shard),
                    send_time_ms=sim.clock.now,
                    latency_ms=latency,
                    payload={"entity_id": entity_id, "shard_index": i},
                    packet_lost=lost,
                )

                shard_metric = sim._make_shard_metric(i, node, latency, len(enc_shard), not lost)
                metrics.shard_store_metrics.append(shard_metric)

                if not lost:
                    success = node.store_shard(entity_id, i, enc_shard)
                    if latency != float("inf"):
                        max_delivery_time = max(max_delivery_time, latency)

        # Advance clock by the longest shard delivery (parallel distribution)
        if max_delivery_time > 0 and max_delivery_time != float("inf"):
            sim.clock.advance_to(sim.clock.now + max_delivery_time)
        metrics.shard_distribution_ms = sim.clock.now - dist_start

        # 5. Build and sign commitment record
        shard_map_root = canonical_hash("".join(shard_hashes).encode())
        content_hash = canonical_hash(content)
        shape_hash = canonical_hash(shape.encode())

        record = CommitmentRecord(
            entity_id=entity_id,
            sender_id=self.label,
            shard_map_root=shard_map_root,
            content_hash=content_hash,
            encoding_params={
                "n": n,
                "k": k,
                "algorithm": "reed-solomon-gf256",
                "gf_poly": "0x11d",
                "eval": "vandermonde-powers-of-0x02",
            },
            shape=shape,
            shape_hash=shape_hash,
            timestamp=timestamp,
        )

        sign_start = sim.clock.now
        record.sign(self.keypair)
        # ML-DSA-65 signing: ~1ms
        sim.clock.advance_to(sim.clock.now + 1.0)
        metrics.commit_record_sign_ms = sim.clock.now - sign_start

        sim.commitment_log.append(record)
        sim.register_sender(self.label, self.keypair)

        metrics.commit_end_ms = sim.clock.now

        self._committed_entities[entity_id] = record
        self._cek_store[entity_id] = cek

        return entity_id

    # ------------------------------------------------------------------
    # PHASE 2: LATTICE
    # ------------------------------------------------------------------

    def send_lattice_key(
        self,
        entity_id: str,
        receiver: "SimClient",
        access_policy: dict | None = None,
    ) -> bytes:
        """
        Execute PHASE 2: LATTICE.

        1. Build LatticeKey with CEK + commitment ref
        2. Seal to receiver's ML-KEM public key
        3. Simulate network transfer of sealed key

        Returns: sealed lattice key bytes
        """
        sim = self.simulator
        metrics = sim.metrics.get_transfer(entity_id)
        if metrics is None:
            raise ValueError(f"No transfer metrics for {entity_id}")

        metrics.receiver = receiver.label
        metrics.receiver_region = receiver.region
        lattice_start = sim.clock.now
        metrics.lattice_start_ms = lattice_start

        record = self._committed_entities.get(entity_id)
        if record is None:
            record = sim.commitment_log.fetch(entity_id)
        cek = self._cek_store.get(entity_id)
        if record is None or cek is None:
            raise ValueError(f"Entity {entity_id} not committed by this client")

        commitment_ref = canonical_hash(json.dumps(record.to_dict(), sort_keys=True).encode())

        key = LatticeKey(
            entity_id=entity_id,
            cek=cek,
            commitment_ref=commitment_ref,
            access_policy=access_policy or {"type": "unrestricted"},
        )

        # Seal (ML-KEM encapsulation ~0.5ms)
        seal_start = sim.clock.now
        sealed = key.seal(receiver.keypair.ek)
        sim.clock.advance_to(sim.clock.now + 0.5)
        metrics.lattice_seal_ms = sim.clock.now - seal_start
        metrics.lattice_key_bytes = len(sealed)

        # Transfer sealed key over network
        latency = sim.topology.latency_between_nodes(
            self.node_id, receiver.node_id, payload_bytes=len(sealed)
        )
        msg = sim.bus.send(
            msg_type=sim._msg_types.LATTICE_KEY_TRANSFER,
            source=self.node_id,
            destination=receiver.node_id,
            payload_bytes=len(sealed),
            send_time_ms=sim.clock.now,
            latency_ms=latency,
            payload={"entity_id": entity_id},
        )

        if latency != float("inf"):
            sim.clock.advance_to(sim.clock.now + latency)
        metrics.lattice_transfer_ms = latency
        metrics.lattice_end_ms = sim.clock.now

        return sealed

    # ------------------------------------------------------------------
    # PHASE 3: MATERIALIZE
    # ------------------------------------------------------------------

    def materialize(self, sealed_key: bytes) -> Optional[bytes]:
        """
        Execute PHASE 3: MATERIALIZE.

        1. Unseal lattice key with private key
        2. Fetch commitment record from log
        3. Verify commitment reference and signature
        4. Fetch encrypted shards from nearest nodes
        5. Decrypt shards with CEK
        6. Erasure decode to reconstruct content
        7. Verify EntityID (end-to-end integrity)

        Returns: entity content bytes, or None on failure.
        """
        sim = self.simulator
        materialize_start = sim.clock.now

        # 1. Unseal
        unseal_start = sim.clock.now
        try:
            key = LatticeKey.unseal(sealed_key, self.keypair)
        except ValueError:
            return None
        # ML-KEM decapsulation ~0.5ms
        sim.clock.advance_to(sim.clock.now + 0.5)

        metrics = sim.metrics.get_transfer(key.entity_id)
        if metrics is None:
            # Transfer initiated outside metrics tracking
            metrics = sim.metrics.new_transfer(key.entity_id)

        metrics.materialize_start_ms = materialize_start
        metrics.unseal_ms = sim.clock.now - unseal_start

        # 2. Fetch commitment record
        fetch_start = sim.clock.now
        record = sim.commitment_log.fetch(key.entity_id)
        if record is None:
            metrics.success = False
            metrics.failure_reason = "commitment_not_found"
            metrics.materialize_end_ms = sim.clock.now
            return None
        # Log fetch ~0.1ms local
        sim.clock.advance_to(sim.clock.now + 0.1)
        metrics.record_fetch_ms = sim.clock.now - fetch_start

        # 3. Verify commitment reference
        verify_start = sim.clock.now
        record_ref = canonical_hash(json.dumps(record.to_dict(), sort_keys=True).encode())
        if record_ref != key.commitment_ref:
            metrics.success = False
            metrics.failure_reason = "commitment_ref_mismatch"
            metrics.materialize_end_ms = sim.clock.now
            return None

        sender_kp = sim.get_sender_keypair(record.sender_id)
        if sender_kp is None:
            metrics.success = False
            metrics.failure_reason = "sender_not_found"
            metrics.materialize_end_ms = sim.clock.now
            return None

        if not record.verify_signature(sender_kp.vk):
            metrics.success = False
            metrics.failure_reason = "invalid_signature"
            metrics.materialize_end_ms = sim.clock.now
            return None
        # Signature verification ~0.5ms
        sim.clock.advance_to(sim.clock.now + 0.5)
        metrics.record_verify_ms = sim.clock.now - verify_start

        # 4. Fetch encrypted shards from nearest available nodes
        n = record.encoding_params["n"]
        k = record.encoding_params["k"]

        fetch_start = sim.clock.now
        try:
            encrypted_shards, shard_metrics = sim.fetch_shards_for_client(self, key.entity_id, n, k)
        except ValueError:
            metrics.success = False
            metrics.failure_reason = "no_online_nodes"
            metrics.materialize_end_ms = sim.clock.now
            return None
        metrics.shard_fetch_metrics = shard_metrics
        metrics.shards_fetched = len(encrypted_shards)
        metrics.shards_from_local_region = sum(
            1 for sm in shard_metrics if sm.success and sm.target_region == self.region
        )
        metrics.shard_fetch_ms = sim.clock.now - fetch_start

        if len(encrypted_shards) < k:
            metrics.success = False
            metrics.failure_reason = f"insufficient_shards ({len(encrypted_shards)}/{k})"
            metrics.materialize_end_ms = sim.clock.now
            return None

        # 5. Decrypt shards with CEK
        decrypt_start = sim.clock.now
        plaintext_shards: dict[int, bytes] = {}
        for i, enc_shard in encrypted_shards.items():
            try:
                plaintext_shards[i] = ShardEncryptor.decrypt_shard(
                    key.cek, key.entity_id, enc_shard, i
                )
            except ValueError:
                pass  # AEAD rejected — skip this shard

        if len(plaintext_shards) < k:
            metrics.success = False
            metrics.failure_reason = f"decryption_failed ({len(plaintext_shards)}/{k})"
            metrics.materialize_end_ms = sim.clock.now
            return None

        # Simulate decryption time
        total_shard_bytes = sum(len(s) for s in plaintext_shards.values())
        decrypt_time = max(0.1, total_shard_bytes / (200 * 1024 * 1024) * 1000)
        sim.clock.advance_to(sim.clock.now + decrypt_time)
        metrics.shard_decrypt_ms = sim.clock.now - decrypt_start

        # 6. Erasure decode
        decode_start = sim.clock.now
        entity_content = ErasureCoder.decode(plaintext_shards, n, k)
        decode_time = max(0.1, len(entity_content) / (500 * 1024 * 1024) * 1000)
        sim.clock.advance_to(sim.clock.now + decode_time)
        metrics.erasure_decode_ms = sim.clock.now - decode_start

        # 7. Verify EntityID
        verify_start = sim.clock.now
        expected_entity_id = canonical_hash(
            entity_content
            + record.shape.encode()
            + struct.pack(">d", record.timestamp)
            + sender_kp.vk
        )
        if expected_entity_id != key.entity_id:
            metrics.success = False
            metrics.failure_reason = "entity_id_mismatch"
            metrics.materialize_end_ms = sim.clock.now
            return None
        sim.clock.advance_to(sim.clock.now + 0.1)
        metrics.entity_verify_ms = sim.clock.now - verify_start

        metrics.materialize_end_ms = sim.clock.now
        metrics.success = True
        return entity_content
