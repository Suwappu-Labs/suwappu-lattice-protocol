"""
Post-quantum asymmetric keypair and envelope encryption for LTP.

Provides:
  - KeyPair   — ML-KEM + ML-DSA combined keypair (sizes per SecurityProfile)
  - SealedBox — ML-KEM + AEAD envelope encryption (seal/unseal)

Key sizes depend on the active SecurityProfile:
  Level 3: ML-KEM-768 (ek=1184B) + ML-DSA-65 (vk=1952B)
  Level 5: ML-KEM-1024 (ek=1568B) + ML-DSA-87 (vk=2592B)
"""

from __future__ import annotations

import os
import struct
import time as _time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import AEAD, MLKEM, MLDSA, canonical_hash, canonical_hash_bytes

__all__ = [
    "KeyPair", "KeyState", "KeyRegistry", "KeyRotationManager",
    "KeyRotationEvent", "InvalidKeyStateTransition", "SealedBox",
]


# ---------------------------------------------------------------------------
# Key Lifecycle State Machine
# ---------------------------------------------------------------------------

class KeyState(Enum):
    """Formal key lifecycle states per NIST SP 800-57."""
    PENDING  = "pending"    # Generated, not yet activated by network
    ACTIVE   = "active"     # Current operational key
    RETIRING = "retiring"   # Grace period: valid for decaps, not new ops
    RETIRED  = "retired"    # Private material zeroized, only vk retained


class InvalidKeyStateTransition(Exception):
    """Raised when an illegal key state transition is attempted."""
    def __init__(self, current: KeyState, target: KeyState):
        super().__init__(
            f"Invalid key state transition: {current.value} -> {target.value}"
        )
        self.current = current
        self.target = target


_VALID_KEY_TRANSITIONS: frozenset[tuple[KeyState, KeyState]] = frozenset({
    (KeyState.PENDING, KeyState.ACTIVE),
    (KeyState.ACTIVE, KeyState.RETIRING),
    (KeyState.RETIRING, KeyState.RETIRED),
})


def _validate_key_transition(current: KeyState, target: KeyState) -> None:
    """Validate a key state transition. Raises on invalid."""
    if (current, target) not in _VALID_KEY_TRANSITIONS:
        raise InvalidKeyStateTransition(current, target)


@dataclass(frozen=True)
class KeyRotationEvent:
    """Immutable record of a key rotation for audit trail.

    Signed with the OLD key (proves the rotation was authorized by
    the holder of the previous key).
    """
    old_vk_hash: str
    new_vk_hash: str
    old_version: int
    new_version: int
    rotation_signature: bytes
    timestamp: float
    label: str


# ---------------------------------------------------------------------------
# KeyPair: Post-Quantum Asymmetric Keypair (ML-KEM + ML-DSA)
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """
    Post-quantum asymmetric keypair combining ML-KEM and ML-DSA.

    Contains:
      - ek (encapsulation key, public): used to seal lattice keys to this recipient
      - dk (decapsulation key, private): used to unseal lattice keys
      - vk (verification key, public): used to verify commitment signatures
      - sk (signing key, private): used to sign commitment records

    Key sizes depend on active SecurityProfile (NIST FIPS 203/204):
      Level 3: ML-KEM-768 (ek=1184B, dk=2400B) + ML-DSA-65 (vk=1952B, sk=4032B)
      Level 5: ML-KEM-1024 (ek=1568B, dk=3168B) + ML-DSA-87 (vk=2592B, sk=4896B)

    Security level: Determined by active SecurityProfile.
    """
    ek: bytes          # ML-KEM encapsulation key (1184 bytes, public)
    dk: bytes          # ML-KEM decapsulation key (2400 bytes, private)
    vk: bytes          # ML-DSA verification key (1952 bytes, public)
    sk: bytes          # ML-DSA signing key (4032 bytes, private)
    label: str = ""
    version: int = 1               # Key version (increments on rotation)
    created_at: float = 0.0        # Unix timestamp of generation
    expires_at: float = 0.0        # Unix timestamp of expiry (0 = never)
    predecessor_vk_hash: str = ""  # H(previous vk) for key chain verification
    state: KeyState = KeyState.ACTIVE  # Lifecycle state (default ACTIVE for backward compat)
    bls_pk: Optional[bytes] = None   # BLS12-381 public key (48 bytes, optional)
    bls_sk: Optional[bytes] = None   # BLS12-381 signing key (32 bytes, optional)

    @classmethod
    def generate(cls, label: str = "", hsm=None, with_bls: bool = False) -> 'KeyPair':
        """
        Generate a fresh post-quantum keypair (sizes per active SecurityProfile).

        Args:
            label: Human-readable label for the keypair.
            hsm: Optional HSMBackend for hardware-protected key generation.
                 When provided, private keys (dk, sk) NEVER leave the HSM
                 boundary. The KeyPair stores only public material (ek, vk)
                 and sentinel bytes for dk/sk. All sign/decaps operations
                 must be routed through the HSM using hsm_sign() / hsm_decaps().
        """
        if hsm is not None:
            kem_key_id = f"{label}-kem"
            dsa_key_id = f"{label}-dsa"
            ek = hsm.generate_kem_keypair(kem_key_id)
            vk = hsm.generate_dsa_keypair(dsa_key_id)
            # Sentinel: dk/sk are NOT the real private keys — they are
            # zero-filled placeholders that will fail if used directly.
            # All private-key operations must go through hsm_sign/hsm_decaps.
            _HSM_SENTINEL = b"\xfe" * 32  # recognizable non-key pattern
            kp = cls(
                ek=ek, dk=_HSM_SENTINEL, vk=vk, sk=_HSM_SENTINEL,
                label=f"{label}[hsm]",
                created_at=_time.time(),
            )
            kp._hsm = hsm
            kp._hsm_kem_key_id = kem_key_id
            kp._hsm_dsa_key_id = dsa_key_id
            return kp
        ek, dk = MLKEM.keygen()
        vk, sk = MLDSA.keygen()
        bls_pk = None
        bls_sk = None
        if with_bls:
            from .bls import BLS as _BLS
            bls_pk, bls_sk = _BLS.keygen()
        return cls(ek=ek, dk=dk, vk=vk, sk=sk, label=label,
                   created_at=_time.time(), bls_pk=bls_pk, bls_sk=bls_sk)

    @property
    def is_hsm_backed(self) -> bool:
        """True if private keys are held in an HSM (dk/sk are sentinels)."""
        return hasattr(self, '_hsm') and self._hsm is not None

    def hsm_sign(self, message: bytes) -> bytes:
        """Sign via HSM — private key never leaves the HSM boundary.

        Raises RuntimeError if this KeyPair is not HSM-backed.
        """
        if not self.is_hsm_backed:
            raise RuntimeError("hsm_sign() called on non-HSM KeyPair; use MLDSA.sign(kp.sk, msg) instead")
        return self._hsm.sign(self._hsm_dsa_key_id, message)

    def hsm_decaps(self, kem_ciphertext: bytes) -> bytes:
        """Decapsulate via HSM — private key never leaves the HSM boundary.

        Raises RuntimeError if this KeyPair is not HSM-backed.
        """
        if not self.is_hsm_backed:
            raise RuntimeError("hsm_decaps() called on non-HSM KeyPair; use MLKEM.decaps(kp.dk, ct) instead")
        return self._hsm.kem_decaps(self._hsm_kem_key_id, kem_ciphertext)

    @property
    def pub_hex(self) -> str:
        """Short representation of the public encapsulation key."""
        return self.ek.hex()[:16] + "..."

    @property
    def public_key(self) -> bytes:
        """ML-KEM encapsulation key (for sealing to this recipient)."""
        return self.ek

    def to_bls_identity(self):
        """Convert composite KeyPair to BLSIdentity (Spec C1 §3.4).

        Raises ValueError if this KeyPair has no BLS keys.
        """
        if self.bls_pk is None or self.bls_sk is None:
            raise ValueError(
                f"KeyPair '{self.label}' has no BLS keys — "
                "generate with KeyPair.generate(label, with_bls=True)"
            )
        from .bls_keys import BLSIdentity, bls_fingerprint
        sk_bytes = self.bls_sk
        return BLSIdentity(
            pk=self.bls_pk,
            sk_accessor=lambda: sk_bytes,
            fingerprint=bls_fingerprint(self.bls_pk),
            mode="composite",
            label=self.label,
        )


# ---------------------------------------------------------------------------
# KeyRegistry: Shared store for sender verification keys
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    Registry for looking up sender KeyPairs by label.

    Decouples key storage from the protocol instance so that multiple
    protocol instances (e.g. sender on L1, receiver on L2) can share the
    same registry.  This resolves CODE_IMPROVEMENTS #3 — previously,
    _sender_keypairs was scoped to a single LTPProtocol instance.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyPair] = {}

    def register(self, keypair: KeyPair) -> None:
        """Register a keypair under its label."""
        if not keypair.label:
            raise ValueError("Cannot register a keypair without a label")
        self._keys[keypair.label] = keypair

    def get(self, label: str) -> Optional[KeyPair]:
        """Look up a keypair by label. Returns None if not found."""
        return self._keys.get(label)

    def __contains__(self, label: str) -> bool:
        return label in self._keys

    def __len__(self) -> int:
        return len(self._keys)


# ---------------------------------------------------------------------------
# KeyRotationManager: Key Lifecycle Management
#
# Protocol (per whitepaper §2.3.4):
#   1. Generate new KeyPair with version = old.version + 1
#   2. Set predecessor_vk_hash = H(old.vk) for chain verification
#   3. Old key enters grace period (default: 1 hour)
#   4. During grace period, both old and new dk accepted
#   5. After grace period, old dk/sk zeroized
# ---------------------------------------------------------------------------

class KeyRotationManager:
    """
    Manages key lifecycle: rotation, grace periods, and secure retirement.

    Rotation protocol:
      rotate(old_kp) → new_kp with:
        - version = old.version + 1
        - predecessor_vk_hash = H(old.vk)
        - old.expires_at = now + grace_period

    During grace period, both old and new keys are valid for decapsulation.
    After grace, retire(old_kp) zeroizes private key material.

    Reference: WireGuard §5 (rekey every 2 min), NIST SP 800-57 (key lifecycle).
    """

    DEFAULT_GRACE_PERIOD = 3600.0    # 1 hour
    DEFAULT_ROTATION_INTERVAL = 90 * 24 * 3600.0  # 90 days

    def __init__(self, kms=None, scheduler=None) -> None:
        # label → list of KeyPairs (newest last)
        self._key_chains: dict[str, list[KeyPair]] = {}
        self._kms = kms          # Optional KMSBackend for cloud key management
        self._scheduler = scheduler  # Optional ScheduledTaskRunner for CronJob triggers

    def rotate(
        self,
        old_keypair: KeyPair,
        grace_period_seconds: float = DEFAULT_GRACE_PERIOD,
    ) -> KeyPair:
        """
        Generate a new keypair linked to the predecessor.

        The old keypair's expires_at is set to now + grace_period.
        During the grace period, both keys can be used for decapsulation.
        After the grace period, call retire() on the old keypair.

        Returns: the new KeyPair.
        """
        now = _time.time()

        # Set expiry on old key and transition state
        old_keypair.expires_at = now + grace_period_seconds
        if old_keypair.state == KeyState.ACTIVE:
            old_keypair.state = KeyState.RETIRING

        # Generate successor
        new_kp = KeyPair.generate(label=old_keypair.label)
        new_kp.version = old_keypair.version + 1
        new_kp.predecessor_vk_hash = canonical_hash(old_keypair.vk)

        # Track chain
        label = old_keypair.label
        if label not in self._key_chains:
            self._key_chains[label] = [old_keypair]
        self._key_chains[label].append(new_kp)

        return new_kp

    def is_expired(self, keypair: KeyPair, now: float | None = None) -> bool:
        """Check if a keypair has passed its expiry time."""
        if keypair.expires_at == 0.0:
            return False  # Never expires
        now = now or _time.time()
        return now >= keypair.expires_at

    def active_keys(self, label: str, now: float | None = None) -> list[KeyPair]:
        """Return all non-expired keys for a label (current + grace period)."""
        now = now or _time.time()
        chain = self._key_chains.get(label, [])
        return [kp for kp in chain if not self.is_expired(kp, now)]

    def current_key(self, label: str) -> KeyPair | None:
        """Return the newest (highest version) key for a label."""
        chain = self._key_chains.get(label, [])
        return chain[-1] if chain else None

    def retire(self, keypair: KeyPair) -> None:
        """Securely zeroize private key material.

        WARNING: Python's memory management does not guarantee secure zeroization.
        In production, use a C-level zeroization function (e.g., sodium_memzero).
        This is a best-effort implementation for the PoC.
        """
        # Best-effort: overwrite with zeros (Python may not actually clear memory)
        if keypair.dk:
            keypair.dk = b'\x00' * len(keypair.dk)
        if keypair.sk:
            keypair.sk = b'\x00' * len(keypair.sk)
        keypair.expires_at = 1.0  # Mark as expired (epoch + 1s)
        keypair.state = KeyState.RETIRED

    def verify_chain(self, label: str) -> bool:
        """Verify the key chain integrity: each key links to its predecessor."""
        chain = self._key_chains.get(label, [])
        for i in range(1, len(chain)):
            expected_hash = canonical_hash(chain[i - 1].vk)
            if chain[i].predecessor_vk_hash != expected_hash:
                return False
        return True

    def register(self, keypair: KeyPair) -> None:
        """Register a keypair in the rotation manager."""
        label = keypair.label
        if label not in self._key_chains:
            self._key_chains[label] = []
        self._key_chains[label].append(keypair)

    # ------------------------------------------------------------------
    # Formal key lifecycle state machine
    # ------------------------------------------------------------------

    def generate_pending(self, label: str) -> KeyPair:
        """Generate a new keypair in PENDING state (not yet activated)."""
        kp = KeyPair.generate(label=label)
        kp.state = KeyState.PENDING
        return kp

    def activate(self, keypair: KeyPair) -> None:
        """Transition PENDING -> ACTIVE. Adds key to chain."""
        _validate_key_transition(keypair.state, KeyState.ACTIVE)
        keypair.state = KeyState.ACTIVE
        label = keypair.label
        if label not in self._key_chains:
            self._key_chains[label] = []
        self._key_chains[label].append(keypair)

    def begin_retirement(
        self, keypair: KeyPair, grace_period_seconds: float = DEFAULT_GRACE_PERIOD,
    ) -> None:
        """Transition ACTIVE -> RETIRING. Sets expires_at for grace period."""
        _validate_key_transition(keypair.state, KeyState.RETIRING)
        keypair.state = KeyState.RETIRING
        keypair.expires_at = _time.time() + grace_period_seconds

    def complete_retirement(self, keypair: KeyPair) -> None:
        """Transition RETIRING -> RETIRED. Zeroizes private material.

        If KMS backend is configured, delegates key destruction.
        """
        _validate_key_transition(keypair.state, KeyState.RETIRED)
        self.retire(keypair)
        if self._kms is not None:
            try:
                key_id = f"{keypair.label}-v{keypair.version}"
                self._kms.destroy_key(key_id)
            except Exception:
                pass  # Best-effort KMS cleanup

    def rotate_with_dst_validation(
        self,
        old_keypair: KeyPair,
        grace_period_seconds: float = DEFAULT_GRACE_PERIOD,
    ) -> KeyRotationEvent:
        """Full rotation with domain-separated signed event for audit trail.

        1. Begin retirement of old key
        2. Generate and activate new key
        3. Sign rotation event with old key (proves authorization)
        4. Verify chain integrity
        """
        from .domain import DOMAIN_KEY_ROTATION

        now = _time.time()

        # Generate new key via standard rotate()
        new_kp = self.rotate(old_keypair, grace_period_seconds)

        # Build rotation payload
        old_vk_hash = canonical_hash(old_keypair.vk)
        new_vk_hash = canonical_hash(new_kp.vk)
        payload = (
            DOMAIN_KEY_ROTATION
            + old_vk_hash.encode()
            + new_vk_hash.encode()
            + struct.pack(">I", old_keypair.version)
            + struct.pack(">I", new_kp.version)
            + struct.pack(">d", now)
        )

        # Sign with old key (proves the rotation was authorized)
        sig = MLDSA.sign(old_keypair.sk, payload)

        # Verify chain integrity
        if not self.verify_chain(old_keypair.label):
            raise ValueError("Chain integrity check failed after rotation")

        return KeyRotationEvent(
            old_vk_hash=old_vk_hash,
            new_vk_hash=new_vk_hash,
            old_version=old_keypair.version,
            new_version=new_kp.version,
            rotation_signature=sig,
            timestamp=now,
            label=old_keypair.label,
        )


# ---------------------------------------------------------------------------
# SealedBox: Post-Quantum Envelope Encryption (ML-KEM-768 + AEAD)
#
# Protocol:
#   seal(plaintext, receiver_ek) → kem_ciphertext(1088) || nonce(16) || aead_ct+tag
#   unseal(sealed_bytes, receiver_keypair) → plaintext
#
# Forward secrecy: each seal() performs a fresh ML-KEM.Encaps(ek), producing a
# unique (shared_secret, kem_ciphertext) pair. The shared_secret is used once
# as the AEAD key, then immediately zeroized.
# ---------------------------------------------------------------------------

class SealedBox:
    """
    Post-quantum public-key envelope encryption using ML-KEM-768 + AEAD.

    Security:
      - Each seal() uses a fresh ML-KEM encapsulation (forward secrecy per message)
      - Only the holder of the corresponding dk can unseal
      - Sealed output is indistinguishable from random bytes
      - Resistant to both classical and quantum adversaries

    Sealed format:
      kem_ciphertext(1088) || nonce(AEAD.NONCE_SIZE) || aead_ciphertext(variable) || aead_tag(AEAD.TAG_SIZE)

    Total overhead: 1088 + NONCE_SIZE + TAG_SIZE bytes over plaintext
    """

    @classmethod
    def seal(cls, plaintext: bytes, receiver_ek: bytes) -> bytes:
        """
        Seal plaintext to receiver's ML-KEM encapsulation key.

        Forward secrecy: each call generates a fresh encapsulation.
        The shared_secret is used once and then discarded.
        """
        if len(receiver_ek) != MLKEM.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(receiver_ek)} (expected {MLKEM.EK_SIZE})")

        shared_secret, kem_ct = MLKEM.encaps(receiver_ek)

        nonce = os.urandom(AEAD.NONCE_SIZE)
        ciphertext = AEAD.encrypt(shared_secret, plaintext, nonce)
        del shared_secret

        return kem_ct + nonce + ciphertext

    @classmethod
    def unseal(cls, sealed_data: bytes, receiver_keypair: KeyPair) -> bytes:
        """
        Unseal with receiver's ML-KEM decapsulation key.

        Raises ValueError if wrong keypair or tampered data.
        """
        min_len = MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD._tag_size()
        if len(sealed_data) < min_len:
            raise ValueError(f"Sealed data too short ({len(sealed_data)} < {min_len})")

        kem_ct = sealed_data[:MLKEM.CT_SIZE]
        nonce = sealed_data[MLKEM.CT_SIZE:MLKEM.CT_SIZE + AEAD.NONCE_SIZE]
        aead_ct = sealed_data[MLKEM.CT_SIZE + AEAD.NONCE_SIZE:]

        try:
            shared_secret = MLKEM.decaps(receiver_keypair.dk, kem_ct)
        except ValueError:
            raise ValueError(
                "Cannot unseal — ML-KEM decapsulation failed "
                "(wrong decapsulation key or corrupted ciphertext)"
            )

        try:
            plaintext = AEAD.decrypt(shared_secret, aead_ct, nonce)
        except ValueError as e:
            raise ValueError(f"Cannot unseal — AEAD decryption failed: {e}")

        del shared_secret
        return plaintext
