"""
LTP Protocol orchestrator — the three-phase transfer protocol.

Provides:
  - LTPProtocol — COMMIT / LATTICE / MATERIALIZE phases

Post-quantum security model (Option C + ML-KEM + ML-DSA):
  COMMIT:      encrypt shards with CEK → distribute ciphertext → ML-DSA sign record
  LATTICE:     seal minimal key (entity_id + CEK + ref) via ML-KEM to receiver
  MATERIALIZE: ML-KEM unseal → derive locations → fetch ciphertext → decrypt → decode
"""

from __future__ import annotations

import logging
import struct
import threading
import time as _time_mod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .access_policy import PolicyViolation, check_policy, validate_policy
from .commitment import CommitmentNetwork, CommitmentRecord
from .dual_lane.hashing import spec_hash_hex
from .entity import Entity
from .erasure import ErasureCoder
from .keypair import KeyPair, KeyRegistry
from .lattice import LatticeKey
from .primitives import AEAD, MLDSA, MLKEM, canonical_hash
from .shards import ShardEncryptor

logger = logging.getLogger(__name__)

__all__ = ["LTPProtocol", "TransferState", "TransferSession", "ProtocolConfig"]


# ---------------------------------------------------------------------------
# Protocol State Machine (ref: WireGuard §5, FoundationDB strict serializability)
# ---------------------------------------------------------------------------


class TransferState(Enum):
    """Transfer lifecycle states. See whitepaper §2.3.3."""

    IDLE = "idle"
    COMMITTED = "committed"  # Phase 1 complete
    SEALED = "sealed"  # Phase 2 complete (lattice key sealed)
    MATERIALIZING = "materializing"  # Phase 3 in progress
    MATERIALIZED = "materialized"  # Phase 3 complete — transfer done
    FAILED = "failed"  # Unrecoverable error
    TIMED_OUT = "timed_out"  # Timeout exceeded


@dataclass
class ProtocolConfig:
    """Protocol timing constraints. See whitepaper §2.3.3."""

    commit_timeout_seconds: float = 30.0
    lattice_timeout_seconds: float = 10.0
    materialize_timeout_seconds: float = 60.0
    max_retry_attempts: int = 3
    # Maximum accepted age of a sealed lattice key, in seconds, measured
    # against its authenticated sealed_at stamp (whitepaper §3.3.8 replay
    # mitigation). None (default) preserves the protocol's asynchronous
    # design — a sealed key may sit uncollected indefinitely. When set,
    # older keys are rejected at MATERIALIZE, and a legacy key with no
    # sealed_at stamp is rejected too (fail-closed).
    max_seal_age_seconds: Optional[float] = None


@dataclass
class TransferSession:
    """Tracks state for a single transfer through all three phases.

    Created via LTPProtocol.create_session(). Not required for basic usage —
    the commit/lattice/materialize methods work without sessions for
    backward compatibility.
    """

    entity_id: str = ""
    state: TransferState = field(default=TransferState.IDLE)
    started_at: float = 0.0
    phase_started_at: float = 0.0
    retry_count: int = 0
    cek: bytes = b""
    sealed_key: bytes = b""
    error: str = ""

    def elapsed_seconds(self) -> float:
        """Seconds since current phase started."""
        if self.phase_started_at == 0.0:
            return 0.0
        return _time_mod.time() - self.phase_started_at

    def transition(self, new_state: TransferState) -> None:
        """Transition to a new state, updating phase timer."""
        self.state = new_state
        self.phase_started_at = _time_mod.time()


class LTPProtocol:
    """
    Lattice Transfer Protocol — main protocol orchestrator.

    Post-quantum security model (Option C):
      COMMIT:      encrypt shards → distribute → ML-DSA-65 sign commitment record
      LATTICE:     seal minimal key via ML-KEM-768 to receiver
      MATERIALIZE: unseal → verify → fetch → decrypt → decode → verify EntityID
    """

    def __init__(
        self,
        network: CommitmentNetwork,
        key_registry: Optional[KeyRegistry] = None,
        config: Optional[ProtocolConfig] = None,
    ) -> None:
        self.network = network
        self.default_n = 8
        self.default_k = 4
        self._entity_sizes: dict[str, int] = {}
        self.key_registry = key_registry or KeyRegistry()
        self.config = config or ProtocolConfig()
        self._sessions: dict[str, TransferSession] = {}
        self._session_lock = threading.Lock()
        self._committed_entity_ids: set[str] = set()
        # Completed materializations per sealed key (capability instance),
        # keyed by the sealed key's digest — whitepaper §2.2.1 enforcement
        # state. In-memory: bounds sealed-key replay at THIS receiver only.
        self._materialization_counts: dict[str, int] = {}
        self._policy_lock = threading.Lock()

    # --- Session Management ---

    def create_session(self) -> TransferSession:
        """Create a new transfer session for state tracking."""
        session = TransferSession(started_at=_time_mod.time())
        return session

    def get_session(self, entity_id: str) -> Optional[TransferSession]:
        """Look up a transfer session by entity_id (thread-safe)."""
        with self._session_lock:
            return self._sessions.get(entity_id)

    def list_sessions(self, state: Optional[TransferState] = None) -> list[TransferSession]:
        """List all sessions, optionally filtered by state (thread-safe)."""
        with self._session_lock:
            sessions = list(self._sessions.values())
        if state is not None:
            sessions = [s for s in sessions if s.state == state]
        return sessions

    # --- PHASE 1: COMMIT ---

    def commit(
        self,
        entity: Entity,
        sender_keypair: KeyPair,
        n: Optional[int] = None,
        k: Optional[int] = None,
    ) -> tuple[str, CommitmentRecord, bytes]:
        """
        PHASE 1: COMMIT

        1. Compute EntityID = H(content || shape || timestamp || sender_vk)
        2. Erasure encode → n plaintext shards
        3. Generate random CEK; encrypt each shard (AEAD)
        4. Distribute encrypted shards to commitment nodes
        5. Write minimal commitment record (Merkle root only, NO shard_ids)
        6. Sign record with sender's ML-DSA-65 key

        Returns: (entity_id, commitment_record, cek)
        """
        n = n or self.default_n
        k = k or self.default_k

        sender_id = sender_keypair.label
        self.key_registry.register(sender_keypair)

        timestamp = _time_mod.time()
        entity_id = entity.compute_id(sender_keypair.vk, timestamp)
        shape_hash = canonical_hash(entity.shape.encode())
        self._entity_sizes[entity_id] = len(entity.content)

        logger.info("[COMMIT] Entity ID: %s...", entity_id[:16])
        logger.info("[COMMIT] Content size: %s bytes", f"{len(entity.content):,}")

        plaintext_shards = ErasureCoder.encode(entity.content, n, k)
        logger.info("[COMMIT] Erasure encoded → %d shards (k=%d for reconstruction)", n, k)
        logger.info("[COMMIT] Plaintext shard size: %s bytes each", f"{len(plaintext_shards[0]):,}")

        # SECURITY: Each entity MUST have a unique CEK (see whitepaper §2.1.1).
        cek = ShardEncryptor.generate_cek()
        # Log a hash fingerprint, never raw key bytes — the previous
        # cek.hex()[:16] leaked 64 bits of the CEK into logs.
        key_fp = spec_hash_hex(cek)[:16]
        logger.info("[COMMIT] CEK generated: fp=%s (256-bit CSPRNG)", key_fp)

        encrypted_shards = [
            ShardEncryptor.encrypt_shard(cek, entity_id, shard, i)
            for i, shard in enumerate(plaintext_shards)
        ]

        overhead = len(encrypted_shards[0]) - len(plaintext_shards[0])
        logger.info(
            "[COMMIT] Shards encrypted (AEAD): %s bytes each (+%dB auth tag)",
            f"{len(encrypted_shards[0]):,}",
            overhead,
        )

        shard_map_root = self.network.distribute_encrypted_shards(entity_id, encrypted_shards)
        logger.info("[COMMIT] Encrypted shards → %d commitment nodes", len(self.network.nodes))
        logger.info("[COMMIT]   Nodes store CIPHERTEXT ONLY (cannot read content)")

        content_hash = canonical_hash(entity.content)
        record = CommitmentRecord(
            entity_id=entity_id,
            sender_id=sender_id,
            shard_map_root=shard_map_root,
            content_hash=content_hash,
            encoding_params={
                "n": n,
                "k": k,
                "algorithm": "reed-solomon-gf256",
                "gf_poly": "0x11d",
                "eval": "vandermonde-powers-of-0x02",
            },
            shape=entity.shape,
            shape_hash=shape_hash,
            timestamp=timestamp,
            sender_vk=sender_keypair.vk,
        )

        record.sign(sender_keypair)
        sig_size = len(record.signature)

        commitment_ref = self.network.log.append(record)
        logger.info("[COMMIT] Record written to log (ref: %s...)", commitment_ref[:16])
        logger.info("[COMMIT]   Log contains: entity_id, Merkle root, encoding params")
        logger.info("[COMMIT]   Log does NOT contain: shard_ids, shard content, CEK")
        logger.info("[COMMIT]   ML-DSA-65 signature: %s bytes (quantum-resistant)", f"{sig_size:,}")

        return entity_id, record, cek

    # --- PHASE 2: LATTICE ---

    def lattice(
        self,
        entity_id: str,
        record: CommitmentRecord,
        cek: bytes,
        receiver_keypair: KeyPair,
        access_policy: Optional[dict] = None,
    ) -> bytes:
        """
        PHASE 2: LATTICE

        Create a minimal lattice key and seal it to the receiver via ML-KEM.

        Inner payload (295 bytes with the default policy):
          entity_id + CEK (hex) + commitment_ref + policy, compact JSON

        Sealed output (1,423 bytes with the default policy):
          kem_ciphertext(1088) + nonce(24) + encrypted_payload + aead_tag(16)

        Forward secrecy: each seal() generates a fresh ML-KEM encapsulation.

        The access policy is structurally validated at seal time (fail-fast:
        a malformed or unknown-type policy would produce a key no conforming
        receiver will honor); temporal checks happen only at materialize,
        since sealing before a not_before window opens is legitimate.

        Raises: PolicyViolation on a structurally invalid access policy.
        Returns: sealed lattice key (opaque bytes)
        """
        commitment_ref = canonical_hash(record.to_bytes())

        key = LatticeKey(
            entity_id=entity_id,
            cek=cek,
            commitment_ref=commitment_ref,
            access_policy=validate_policy(access_policy or {"type": "unrestricted"}),
        )

        inner_size = key.plaintext_size
        sealed = key.seal(receiver_keypair.ek)
        entity_size = self._entity_sizes.get(entity_id, 0)

        logger.info("[LATTICE] Receiver: %s (%s)", receiver_keypair.label, receiver_keypair.pub_hex)
        logger.info("[LATTICE] Inner payload: %d bytes", inner_size)
        logger.info("[LATTICE]   Contains: entity_id + CEK + commitment_ref + policy")
        logger.info("[LATTICE]   REMOVED: shard_ids, encoding_params, sender_id")
        logger.info("[LATTICE] Sealed via ML-KEM-768: %s bytes", f"{len(sealed):,}")
        logger.info("[LATTICE]   kem_ciphertext: %d bytes (fresh encapsulation)", MLKEM.CT_SIZE)
        logger.info(
            "[LATTICE]   nonce: %d bytes | aead_tag: %d bytes", AEAD.NONCE_SIZE, AEAD._tag_size()
        )
        logger.info("[LATTICE]   Forward secrecy: shared_secret zeroized after AEAD encrypt")
        if entity_size > 0:
            logger.info(
                "[LATTICE] Entity: %sB → Key: %sB (%.1fx ratio)",
                f"{entity_size:,}",
                f"{len(sealed):,}",
                entity_size / len(sealed),
            )

        return sealed

    # --- PHASE 3: MATERIALIZE ---

    def materialize(
        self,
        sealed_key: bytes,
        receiver_keypair: KeyPair,
        record: Optional[CommitmentRecord] = None,
        now: Optional[float] = None,
    ) -> Optional[bytes]:
        """
        PHASE 3: MATERIALIZE

        1. Unseal lattice key with receiver's private key
        2. Enforce access policy — abort before any fetch (whitepaper §2.3.1)
        3. Fetch commitment record from log
        4. Verify commitment reference (hash match vs sealed ref)
        5. Verify ML-DSA-65 signature on commitment record
        6. Read encoding params (n, k) from record
        7. Derive shard locations from entity_id (no shard_ids needed)
        8. Fetch k-of-n encrypted shards; decrypt with CEK
        9. Erasure decode → original entity content
        10. Verify full EntityID: H(content || shape || ts || sender_vk)

        ``now`` overrides the policy-evaluation clock (testing/replay
        analysis); default is wall-clock time.

        Returns: entity content bytes, or None on failure.
        """
        label = receiver_keypair.label
        logger.info("[MATERIALIZE] Receiver '%s' beginning materialization...", label)
        logger.info("[MATERIALIZE] Sealed key size: %d bytes", len(sealed_key))

        # Step 1: Unseal the lattice key
        try:
            key = LatticeKey.unseal(sealed_key, receiver_keypair)
        except ValueError as e:
            logger.warning("[MATERIALIZE] UNSEAL FAILED: %s", e)
            return None

        logger.info("[MATERIALIZE] Key unsealed with private key")
        logger.info("[MATERIALIZE]   Entity ID: %s...", key.entity_id[:16])
        # Hash fingerprint only — raw CEK bytes never reach logs.
        key_fp = spec_hash_hex(key.cek)[:16]
        logger.info("[MATERIALIZE]   CEK recovered: fp=%s", key_fp)

        # Step 2: Enforce the access policy BEFORE any fetch (§2.3.1).
        # The materialization slot is reserved atomically so that two
        # concurrent attempts under a one-time key cannot both pass the
        # count check; the slot is released again if this attempt fails,
        # since the count tracks COMPLETED materializations.
        cap_id = spec_hash_hex(sealed_key)
        policy_now = _time_mod.time() if now is None else now
        with self._policy_lock:
            prior = self._materialization_counts.get(cap_id, 0)
            try:
                check_policy(key.access_policy, prior, policy_now)
            except PolicyViolation as exc:
                logger.warning("[MATERIALIZE] ACCESS POLICY DENIED: %s", exc)
                return None
            self._materialization_counts[cap_id] = prior + 1

        # Freshness bound (optional, fail-closed): bounds the window in
        # which a captured sealed key can be replayed. sealed_at is inside
        # the AEAD payload, so an attacker cannot back-date it.
        max_age = self.config.max_seal_age_seconds
        if max_age is not None:
            age = policy_now - key.sealed_at
            if key.sealed_at <= 0 or age > max_age:
                logger.warning(
                    "[MATERIALIZE] SEAL AGE REJECTED: sealed_at=%s age=%.0fs limit=%.0fs",
                    key.sealed_at,
                    age,
                    max_age,
                )
                with self._policy_lock:
                    current = self._materialization_counts.get(cap_id, 1)
                    self._materialization_counts[cap_id] = max(0, current - 1)
                return None

        logger.info(
            "[MATERIALIZE] Access policy permits (type=%s, completed=%d)",
            key.access_policy.get("type") if isinstance(key.access_policy, dict) else "?",
            prior,
        )

        result = self._materialize_unsealed(key, record, label)
        if result is None:
            # Failed attempts do not consume a materialization.
            with self._policy_lock:
                current = self._materialization_counts.get(cap_id, 1)
                self._materialization_counts[cap_id] = max(0, current - 1)
        return result

    def _materialize_unsealed(
        self,
        key: LatticeKey,
        record: Optional[CommitmentRecord],
        label: str,
    ) -> Optional[bytes]:
        """Steps 3-10 of MATERIALIZE, after unseal and policy enforcement."""
        # Step 3: Fetch commitment record (or use externally-supplied record)
        if record is None:
            record = self.network.log.fetch(key.entity_id)
        if record is None:
            logger.warning("[MATERIALIZE] Commitment not found for %s...", key.entity_id[:16])
            return None
        logger.info("[MATERIALIZE] Commitment record found")

        # Step 4: Verify commitment reference
        record_ref = canonical_hash(record.to_bytes())
        if record_ref != key.commitment_ref:
            logger.warning("[MATERIALIZE] Commitment reference MISMATCH (tampered?)")
            return None
        logger.info("[MATERIALIZE] Commitment reference verified")

        # Step 5: Verify ML-DSA-65 signature
        sender_kp = self.key_registry.get(record.sender_id)
        sender_vk: Optional[bytes] = None
        if sender_kp is not None:
            sender_vk = sender_kp.vk
        elif record.sender_vk:
            sender_vk = record.sender_vk
            logger.info("[MATERIALIZE] Using sender_vk from record (cross-node)")
        if sender_vk is None:
            logger.warning("[MATERIALIZE] Sender '%s' not found in registry", record.sender_id)
            return None
        if not record.verify_signature(sender_vk):
            logger.warning("[MATERIALIZE] ML-DSA signature INVALID — commitment record rejected")
            return None
        logger.info("[MATERIALIZE] ML-DSA-65 signature verified (sender '%s')", record.sender_id)

        # Step 6: Read encoding params from record
        n = record.encoding_params["n"]
        k = record.encoding_params["k"]
        logger.info("[MATERIALIZE] Encoding: n=%d, k=%d (from commitment record)", n, k)

        # Step 7: Fetch all n shards (so AEAD can reject bad ones; erasure fills gaps)
        logger.info("[MATERIALIZE] Deriving shard locations from entity_id + index...")
        logger.info("[MATERIALIZE] Fetching up to %d encrypted shards (need %d valid)...", n, k)

        encrypted_shards = self.network.fetch_encrypted_shards(key.entity_id, n, n)

        if len(encrypted_shards) < k:
            logger.warning("[MATERIALIZE] Only fetched %d/%d shards", len(encrypted_shards), k)
            return None
        logger.info("[MATERIALIZE] Fetched %d encrypted shards", len(encrypted_shards))

        # Step 8: Decrypt each shard with CEK (AEAD rejects tampered shards)
        plaintext_shards: dict[int, bytes] = {}
        for i, enc_shard in encrypted_shards.items():
            try:
                plaintext_shards[i] = ShardEncryptor.decrypt_shard(
                    key.cek, key.entity_id, enc_shard, i
                )
            except ValueError as e:
                logger.warning(
                    "[MATERIALIZE] Shard %d: AEAD authentication FAILED — %s (skipping)", i, e
                )

        tampered_count = len(encrypted_shards) - len(plaintext_shards)
        if len(plaintext_shards) < k:
            logger.warning(
                "[MATERIALIZE] Only %d/%d shards decrypted (%d rejected by AEAD)",
                len(plaintext_shards),
                k,
                tampered_count,
            )
            return None
        logger.info("[MATERIALIZE] %d shards decrypted with CEK", len(plaintext_shards))
        if tampered_count > 0:
            logger.warning(
                "[MATERIALIZE]   %d shard(s) REJECTED by AEAD tag verification",
                tampered_count,
            )
        else:
            logger.info("[MATERIALIZE]   AEAD tags verified — no shard tampering detected")

        # Step 9: Erasure decode
        entity_content = ErasureCoder.decode(plaintext_shards, n, k)
        logger.info("[MATERIALIZE] Entity reconstructed (%s bytes)", f"{len(entity_content):,}")

        # Step 10: Verify full EntityID (end-to-end content integrity, whitepaper §2.3.1)
        # Defends against commitment record substitution attacks.
        expected_entity_id = canonical_hash(
            entity_content + record.shape.encode() + struct.pack(">d", record.timestamp) + sender_vk
        )
        if expected_entity_id != key.entity_id:
            logger.warning("[MATERIALIZE] EntityID MISMATCH — reconstructed content differs!")
            logger.warning("[MATERIALIZE]   Expected: %s...", key.entity_id[:16])
            logger.warning("[MATERIALIZE]   Got:      %s...", expected_entity_id[:16])
            logger.warning("[MATERIALIZE]   Entity is REJECTED (immutability violation attempt)")
            return None
        logger.info(
            "[MATERIALIZE] EntityID verified: H(content||shape||ts||vk) = %s...",
            expected_entity_id[:16],
        )
        logger.info("[MATERIALIZE] MATERIALIZATION COMPLETE")

        return entity_content
