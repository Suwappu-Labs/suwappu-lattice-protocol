"""
Domain separation registry for the Lattice Transfer Protocol.

Centralizes all domain separation tags and provides domain_hash() and
domain_sign() wrappers that prepend the domain tag before hashing/signing.

Architecture:
  - domain.py is Tier 2 (imports from primitives.py, which is Tier 1)
  - primitives.py MUST NEVER import from domain.py (one-way dependency)
  - Domain tags are bytes literals — no cross-module dependency needed

All tags follow the format: b"GSX-LTP:<name>:v<N>\\x00"
The trailing null byte acts as a separator to prevent prefix collisions.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.2
"""

from __future__ import annotations

from .primitives import MLDSA, canonical_hash, canonical_hash_bytes

__all__ = [
    # Domain tags
    "DOMAIN_ENTITY_ID",
    "DOMAIN_COMMIT_SIGN",
    "DOMAIN_COMMIT_RECORD",
    "DOMAIN_STH_SIGN",
    "DOMAIN_SHARD_NONCE",
    "DOMAIN_APPROVAL_RECEIPT",
    "DOMAIN_ANCHOR_DIGEST",
    "DOMAIN_SIGNED_ENVELOPE",
    "DOMAIN_SIGNER_POLICY",
    "DOMAIN_LATTICE_KEY",
    "DOMAIN_BRIDGE_MSG",
    "DOMAIN_NODE_HANDSHAKE",
    "DOMAIN_JWT_TOKEN",
    "DOMAIN_PEER_GOSSIP",
    "DOMAIN_GATEWAY_ATTEST",
    "DOMAIN_EXTERNAL_EVENT",
    "DOMAIN_MULTI_VM_STATE_ROOT",
    "DOMAIN_MULTI_VM_ATTEST",
    "DOMAIN_BLS_SIGN",
    "DOMAIN_BLS_ATTEST",
    # Functions
    "domain_hash",
    "domain_hash_bytes",
    "domain_sign",
    "domain_verify",
    "signer_fingerprint",
    "bls_domain_sign",
    "bls_domain_verify",
    "bls_aggregate_sigs",
    "bls_aggregate_verify",
]

# ---------------------------------------------------------------------------
# Canonical trust boundary tags
# ---------------------------------------------------------------------------

DOMAIN_ENTITY_ID        = b"GSX-LTP:entity-id:v1\x00"
DOMAIN_COMMIT_SIGN      = b"GSX-LTP:commit-sign:v1\x00"
DOMAIN_COMMIT_RECORD    = b"GSX-LTP:commit-record:v1\x00"
DOMAIN_STH_SIGN         = b"GSX-LTP:sth-sign:v1\x00"
DOMAIN_SHARD_NONCE      = b"GSX-LTP:shard-nonce:v1\x00"
DOMAIN_APPROVAL_RECEIPT = b"GSX-LTP:approval-receipt:v1\x00"
DOMAIN_ANCHOR_DIGEST    = b"GSX-LTP:anchor-digest:v1\x00"
DOMAIN_SIGNED_ENVELOPE  = b"GSX-LTP:signed-envelope:v1\x00"
DOMAIN_SIGNER_POLICY    = b"GSX-LTP:signer-policy:v1\x00"
DOMAIN_LATTICE_KEY      = b"GSX-LTP:lattice-key:v1\x00"
DOMAIN_BRIDGE_MSG       = b"GSX-LTP:bridge-msg:v1\x00"
DOMAIN_NODE_HANDSHAKE   = b"GSX-LTP:node-handshake:v1\x00"
DOMAIN_FRAUD_PROOF      = b"GSX-LTP:fraud-proof:v1\x00"
DOMAIN_CHALLENGE        = b"GSX-LTP:challenge:v1\x00"
DOMAIN_WATCHER          = b"GSX-LTP:watcher:v1\x00"
DOMAIN_ZK_BRIDGE        = b"GSX-LTP:zk-bridge:v1\x00"
DOMAIN_KEY_ROTATION     = b"GSX-LTP:key-rotation:v1\x00"
DOMAIN_KEY_ADMISSION    = b"GSX-LTP:key-admission:v1\x00"
DOMAIN_NODE_ENDORSEMENT = b"GSX-LTP:node-endorsement:v1\x00"
DOMAIN_GOVERNANCE_VOTE  = b"GSX-LTP:governance-vote:v1\x00"
DOMAIN_NIR              = b"GSX-LTP:nir:v1\x00"
DOMAIN_FED_AGREEMENT    = b"GSX-LTP:fed-agreement:v1\x00"
DOMAIN_JWT_TOKEN        = b"GSX-LTP:jwt-token:v1\x00"
DOMAIN_PEER_GOSSIP      = b"GSX-LTP:peer-gossip:v1\x00"
DOMAIN_ZK_TRANSFER      = b"GSX-LTP:zk-transfer:v1\x00"
DOMAIN_GATEWAY_ATTEST   = b"GSX-LTP:gateway-attest:v1\x00"
DOMAIN_EXTERNAL_EVENT   = b"GSX-LTP:external-event:v1\x00"
DOMAIN_MULTI_VM_STATE_ROOT = b"GSX-LTP:multi-vm-state-root:v1\x00"
DOMAIN_MULTI_VM_ATTEST     = b"GSX-LTP:multi-vm-attest:v1\x00"
DOMAIN_BLS_SIGN            = b"GSX-LTP:bls-sign:v1\x00"
DOMAIN_BLS_ATTEST          = b"GSX-LTP:bls-attest:v1\x00"


# ---------------------------------------------------------------------------
# Collision-checked registry
# ---------------------------------------------------------------------------

_ALL_TAGS: dict[str, bytes] = {
    "DOMAIN_ENTITY_ID": DOMAIN_ENTITY_ID,
    "DOMAIN_COMMIT_SIGN": DOMAIN_COMMIT_SIGN,
    "DOMAIN_COMMIT_RECORD": DOMAIN_COMMIT_RECORD,
    "DOMAIN_STH_SIGN": DOMAIN_STH_SIGN,
    "DOMAIN_SHARD_NONCE": DOMAIN_SHARD_NONCE,
    "DOMAIN_APPROVAL_RECEIPT": DOMAIN_APPROVAL_RECEIPT,
    "DOMAIN_ANCHOR_DIGEST": DOMAIN_ANCHOR_DIGEST,
    "DOMAIN_SIGNED_ENVELOPE": DOMAIN_SIGNED_ENVELOPE,
    "DOMAIN_SIGNER_POLICY": DOMAIN_SIGNER_POLICY,
    "DOMAIN_LATTICE_KEY": DOMAIN_LATTICE_KEY,
    "DOMAIN_BRIDGE_MSG": DOMAIN_BRIDGE_MSG,
    "DOMAIN_NODE_HANDSHAKE": DOMAIN_NODE_HANDSHAKE,
    "DOMAIN_FRAUD_PROOF": DOMAIN_FRAUD_PROOF,
    "DOMAIN_CHALLENGE": DOMAIN_CHALLENGE,
    "DOMAIN_WATCHER": DOMAIN_WATCHER,
    "DOMAIN_ZK_BRIDGE": DOMAIN_ZK_BRIDGE,
    "DOMAIN_KEY_ROTATION": DOMAIN_KEY_ROTATION,
    "DOMAIN_KEY_ADMISSION": DOMAIN_KEY_ADMISSION,
    "DOMAIN_NODE_ENDORSEMENT": DOMAIN_NODE_ENDORSEMENT,
    "DOMAIN_GOVERNANCE_VOTE": DOMAIN_GOVERNANCE_VOTE,
    "DOMAIN_NIR": DOMAIN_NIR,
    "DOMAIN_FED_AGREEMENT": DOMAIN_FED_AGREEMENT,
    "DOMAIN_JWT_TOKEN": DOMAIN_JWT_TOKEN,
    "DOMAIN_PEER_GOSSIP": DOMAIN_PEER_GOSSIP,
    "DOMAIN_ZK_TRANSFER": DOMAIN_ZK_TRANSFER,
    "DOMAIN_GATEWAY_ATTEST": DOMAIN_GATEWAY_ATTEST,
    "DOMAIN_EXTERNAL_EVENT": DOMAIN_EXTERNAL_EVENT,
    "DOMAIN_MULTI_VM_STATE_ROOT": DOMAIN_MULTI_VM_STATE_ROOT,
    "DOMAIN_MULTI_VM_ATTEST": DOMAIN_MULTI_VM_ATTEST,
    "DOMAIN_BLS_SIGN": DOMAIN_BLS_SIGN,
    "DOMAIN_BLS_ATTEST": DOMAIN_BLS_ATTEST,
}

# Verify no byte-level collisions at import time
_seen_bytes: set[bytes] = set()
for _name, _tag in _ALL_TAGS.items():
    if _tag in _seen_bytes:
        raise RuntimeError(f"Domain tag collision detected for {_name}: {_tag!r}")
    _seen_bytes.add(_tag)
del _seen_bytes


# ---------------------------------------------------------------------------
# Domain-separated hash functions
# ---------------------------------------------------------------------------

def domain_hash(domain: bytes, data: bytes) -> str:
    """Compute canonical_hash(domain || data).

    Returns the hash as an algo-prefixed hex string (e.g. 'sha3-256:abcd...').
    """
    return canonical_hash(domain + data)


def domain_hash_bytes(domain: bytes, data: bytes) -> bytes:
    """Compute canonical_hash_bytes(domain || data).

    Returns raw 32-byte hash.
    """
    return canonical_hash_bytes(domain + data)


# ---------------------------------------------------------------------------
# Domain-separated signing
# ---------------------------------------------------------------------------

def domain_sign(domain: bytes, signer, data: bytes) -> bytes:
    """Sign domain-separated data: MLDSA.sign(sk, domain || data).

    LTP-A-032 (Phase 4d): `signer` may now be either raw `sk` bytes
    (legacy callers) OR a `KeyPair` (HSM-friendly path). For a KeyPair
    we route through `keypair.sign(...)` so HSM-backed kps stay
    sentinel-only and software-mode kps still produce identical
    signatures.

    Note: Python pqcrypto backend doesn't expose ML-DSA's native context
    parameter. Domain separation via byte-prefix concatenation is the
    correct approach for our backend. If the backend is upgraded to expose
    ctx, this function's internals can change without affecting the API.
    """
    # Avoid an import cycle: `keypair.py` imports from this module.
    from .keypair import KeyPair as _KeyPair
    if isinstance(signer, _KeyPair):
        return signer.sign(domain + data)
    return MLDSA.sign(signer, domain + data)


def domain_verify(domain: bytes, vk: bytes, data: bytes, sig: bytes) -> bool:
    """Verify domain-separated signature: MLDSA.verify(vk, domain || data, sig)."""
    return MLDSA.verify(vk, domain + data, sig)


# ---------------------------------------------------------------------------
# Key fingerprint
# ---------------------------------------------------------------------------

def signer_fingerprint(vk: bytes) -> bytes:
    """Compute a 32-byte signer fingerprint from a verification key.

    Uses SHA3-256 (via canonical_hash_bytes), NOT SHA256.
    Follows the crypto-rs fingerprint pattern but uses LTP's canonical hash
    for consistency with the rest of the codebase.

    Used for:
      - On-chain signer identification in AnchorSubmission
      - Envelope routing without transmitting full 1952B VK
      - COSE kid-equivalent field in SignedEnvelope
    """
    return canonical_hash_bytes(vk)


# ---------------------------------------------------------------------------
# Domain-separated BLS signing (Spec C1 §4)
# ---------------------------------------------------------------------------

def bls_domain_sign(domain: bytes, sk: bytes, data: bytes) -> bytes:
    """Sign domain-separated data with BLS: BLS.sign(sk, domain || data)."""
    from .bls import BLS
    return BLS.sign(sk, domain + data)


def bls_domain_verify(domain: bytes, pk: bytes, data: bytes, sig: bytes) -> bool:
    """Verify domain-separated BLS signature: BLS.verify(pk, domain || data, sig)."""
    from .bls import BLS
    return BLS.verify(pk, domain + data, sig)


def bls_aggregate_sigs(sigs: list[bytes]) -> bytes:
    """Aggregate multiple BLS signatures into one 96-byte signature."""
    from .bls import BLS
    return BLS.aggregate_signatures(sigs)


def bls_aggregate_verify(domain: bytes, pks: list[bytes], data: bytes, agg_sig: bytes) -> bool:
    """Verify aggregate BLS signature (same-message fast path).

    All signers must have signed domain || data.
    """
    from .bls import BLS
    return BLS.aggregate_verify_same_message(pks, domain + data, agg_sig)
