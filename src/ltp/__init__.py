"""
Lattice Transfer Protocol (LTP) — Proof of Concept v3 (Post-Quantum Security)

Implements the three core phases of LTP with post-quantum cryptographic primitives:

  1. COMMIT      — Entity → Erasure Encode → Encrypt Shards with CEK → Distribute Ciphertext
  2. LATTICE     — Generate minimal sealed key (~160B inner, ~1300B sealed) with CEK
  3. MATERIALIZE — Unseal key → Derive shard locations → Fetch ciphertext → Decrypt → Reconstruct

Cryptographic primitives:
  - ML-KEM-768 (FIPS 203 / Kyber) for key encapsulation (sealing lattice keys)
  - ML-DSA-65 (FIPS 204 / Dilithium) for digital signatures (commitment records)
  - BLAKE2b-256 for content-addressing (production: BLAKE3)
  - AEAD (symmetric) for shard encryption and envelope payload encryption

Security properties (Option C + Post-Quantum):
  - Shards encrypted at rest with random Content Encryption Key (CEK)
  - Lattice key sealed via ML-KEM encapsulation (quantum-resistant)
  - Commitment records signed with ML-DSA (quantum-resistant signatures)
  - Shard IDs removed from lattice key (locations derived from entity_id)
  - Commitment log stores only Merkle root (no individual shard metadata)
  - Forward secrecy: each seal() generates a fresh ML-KEM encapsulation
  - Three-leak kill chain CLOSED: key sealed, shards encrypted, log minimal
  - Full post-quantum security: no X25519/Ed25519 dependency

Production dependencies: liboqs or pqcrypto (ML-KEM-768 + ML-DSA-65)
PoC: simulates ML-KEM/ML-DSA API with correct key/ciphertext sizes using
     stdlib BLAKE2b + HMAC. The PoC enforces API semantics and size constraints;
     production replaces simulation with FIPS 203/204 implementations.

Run demo:
  python -m ltp
"""

from .primitives import (
    AEAD, MLKEM, MLDSA,
    SecurityProfile, HashFunction, CryptoLane,
    canonical_hash, canonical_hash_bytes,
    internal_hash, internal_hash_bytes,
    get_security_profile, set_security_profile,
    set_crypto_provider, get_crypto_provider,
    set_compliance_strict, get_compliance_strict,
    assert_real_crypto,
)
from .keypair import KeyPair, KeyRegistry, SealedBox
from .keyvault import KeyVault, KeyVaultError
from .erasure import ErasureCoder
from .shards import ShardEncryptor
from .entity import Entity, canonicalize_shape
from .commitment import (
    AuditResult,
    StakeEscrow,
    StorageEndowment,
    CommitmentNode,
    CommitmentRecord,
    CommitmentLog,
    CommitmentNetwork,
    MIN_STAKE_LTP,
    STAKE_LOCKUP_SECONDS,
    EVICTION_COOLDOWN_SECONDS,
    CORRELATION_PENALTY_MAX,
    WITHHOLDING_SCHEDULE,
)
from .lattice import LatticeKey
from .protocol import LTPProtocol
from .enforcement import (
    StorageProofStrategy,
    PDPChallenge,
    PDPProof,
    PDPVerifier,
    SlashingConditionRegistry,
    AuditFailureCondition,
    DataWithholdingCondition,
    LatencyDegradationCondition,
    ProofFailureCondition,
    EnforcementInvariants,
    DecentralizationMetrics,
    GovernanceTransition,
)
from .economics import (
    EconomicsConfig,
    EconomicsEngine,
    NodeEconomics,
    NetworkPhase,
    SlashingTier,
    RewardBreakdown,
    EpochSnapshot,
)
from .enforcement_pipeline import (
    EnforcementPipeline,
    EnforcementPipelineConfig,
)
from .compliance import (
    CryptoProviderMode,
    FIPSCryptoProvider,
    ComplianceRole,
    Permission,
    RBACPolicy,
    RBACManager,
    Jurisdiction,
    GeoFencePolicy,
    AuditEventType,
    AuditEvent,
    ComplianceAuditLogger,
    KeyVersion,
    KeyRotationPolicy,
    KeyRotationManager,
    DeletionRequest,
    DeletionProof,
    GDPRDeletionManager,
    SIEMFormat,
    SIEMExporter,
    HSMConfig,
    HSMInterface,
    SoftwareHSM as ComplianceSoftwareHSM,
    ComplianceConfig,
    ComplianceFramework,
)
from .hsm import HSMBackend, SoftwareHSM

# GSX Pre-Blockchain Trust Packaging Layer
from .encoding import CanonicalEncoder
from .domain import (
    DOMAIN_ENTITY_ID, DOMAIN_COMMIT_SIGN, DOMAIN_COMMIT_RECORD,
    DOMAIN_STH_SIGN, DOMAIN_SHARD_NONCE, DOMAIN_APPROVAL_RECEIPT,
    DOMAIN_ANCHOR_DIGEST, DOMAIN_SIGNED_ENVELOPE, DOMAIN_SIGNER_POLICY,
    DOMAIN_LATTICE_KEY, DOMAIN_BRIDGE_MSG, DOMAIN_NODE_HANDSHAKE,
    DOMAIN_BLS_SIGN, DOMAIN_BLS_ATTEST,
    domain_hash, domain_hash_bytes, domain_sign, domain_verify,
    signer_fingerprint,
    bls_domain_sign, bls_domain_verify, bls_aggregate_sigs, bls_aggregate_verify,
)
from .envelope import SignedEnvelope
from .receipt import ReceiptType, ApprovalReceipt
from .sequencing import SequenceTracker
from .governance import SignerEntry, ApprovalRule, SignerPolicy
from .evidence import EvidenceBundle
from .hybrid import (
    AlgorithmId, CompositeSignature, AlgorithmRegistry,
    composite_signing_message, split_signing_message,
)


def reset_poc_state() -> None:
    """Reset all PoC simulation state across modules.

    Call this between tests or when you need fresh state. Clears:
      - MLKEM encapsulation lookup tables
      - MLDSA signature lookup tables
      - ShardEncryptor issued CEK tracking set
    """
    MLKEM.reset_poc_state()
    MLDSA.reset_poc_state()
    ShardEncryptor.reset_poc_state()


__all__ = [
    # Security profiles
    "SecurityProfile",
    "HashFunction",
    "CryptoLane",
    "get_security_profile",
    "set_security_profile",
    # Dual-lane hash API
    "canonical_hash",
    "canonical_hash_bytes",
    "internal_hash",
    "internal_hash_bytes",
    # Compliance
    "set_compliance_strict",
    "get_compliance_strict",
    # Primitives
    "AEAD",
    "MLKEM",
    "MLDSA",
    # HSM
    "HSMBackend",
    "SoftwareHSM",
    # Keypair
    "KeyPair",
    "KeyRegistry",
    "SealedBox",
    # KeyVault — at-rest / in-memory key wrapping
    "KeyVault",
    "KeyVaultError",
    # Erasure coding
    "ErasureCoder",
    # Shard encryption
    "ShardEncryptor",
    # Entity
    "Entity",
    "canonicalize_shape",
    # Commitment layer
    "AuditResult",
    "StakeEscrow",
    "CommitmentNode",
    "CommitmentRecord",
    "CommitmentLog",
    "CommitmentNetwork",
    "StorageEndowment",
    "MIN_STAKE_LTP",
    "STAKE_LOCKUP_SECONDS",
    "EVICTION_COOLDOWN_SECONDS",
    "CORRELATION_PENALTY_MAX",
    "WITHHOLDING_SCHEDULE",
    # Lattice key
    "LatticeKey",
    # Protocol
    "LTPProtocol",
    # Merkle log (CT-style commitment log, §5.1.4)
    "MerkleTree",
    "SignedTreeHead",
    "InclusionProof",
    "MerkleLog",
    # Economics
    "EconomicsConfig",
    "EconomicsEngine",
    "NodeEconomics",
    "NetworkPhase",
    "SlashingTier",
    "RewardBreakdown",
    "EpochSnapshot",
    # Enforcement
    "StorageProofStrategy",
    "PDPChallenge",
    "PDPProof",
    "PDPVerifier",
    "SlashingConditionRegistry",
    "AuditFailureCondition",
    "DataWithholdingCondition",
    "LatencyDegradationCondition",
    "ProofFailureCondition",
    "EnforcementInvariants",
    "DecentralizationMetrics",
    "GovernanceTransition",
    # Enforcement pipeline
    "EnforcementPipeline",
    "EnforcementPipelineConfig",
    # Compliance (institutional standards)
    "CryptoProviderMode",
    "FIPSCryptoProvider",
    "ComplianceRole",
    "Permission",
    "RBACPolicy",
    "RBACManager",
    "Jurisdiction",
    "GeoFencePolicy",
    "AuditEventType",
    "AuditEvent",
    "ComplianceAuditLogger",
    "KeyVersion",
    "KeyRotationPolicy",
    "KeyRotationManager",
    "DeletionRequest",
    "DeletionProof",
    "GDPRDeletionManager",
    "SIEMFormat",
    "SIEMExporter",
    "HSMConfig",
    "HSMInterface",
    "ComplianceSoftwareHSM",
    "ComplianceConfig",
    "ComplianceFramework",
    "set_crypto_provider",
    "get_crypto_provider",
    # GSX Pre-Blockchain Trust Packaging Layer
    "CanonicalEncoder",
    "DOMAIN_ENTITY_ID", "DOMAIN_COMMIT_SIGN", "DOMAIN_COMMIT_RECORD",
    "DOMAIN_STH_SIGN", "DOMAIN_SHARD_NONCE", "DOMAIN_APPROVAL_RECEIPT",
    "DOMAIN_ANCHOR_DIGEST", "DOMAIN_SIGNED_ENVELOPE", "DOMAIN_SIGNER_POLICY",
    "DOMAIN_LATTICE_KEY", "DOMAIN_BRIDGE_MSG", "DOMAIN_NODE_HANDSHAKE",
    "DOMAIN_BLS_SIGN", "DOMAIN_BLS_ATTEST",
    "domain_hash", "domain_hash_bytes", "domain_sign", "domain_verify",
    "signer_fingerprint",
    "bls_domain_sign", "bls_domain_verify", "bls_aggregate_sigs", "bls_aggregate_verify",
    "SignedEnvelope",
    "ReceiptType", "ApprovalReceipt",
    "SequenceTracker",
    "SignerEntry", "ApprovalRule", "SignerPolicy",
    "EvidenceBundle",
    "AlgorithmId", "CompositeSignature", "AlgorithmRegistry",
    "composite_signing_message", "split_signing_message",
    # Production assertions
    "assert_real_crypto",
    # Utilities
    "reset_poc_state",
    # Cross-repo wire surface with gsx-dag (paper §10)
    "corridor",
]


# Sub-namespace import — re-exported so callers can `from ltp import corridor`
# and reach the wire-compatible mirror of `gsx-dag/crates/gsx-ltp`.
from . import corridor  # noqa: E402


# Lazy imports to avoid circular dependency (merkle_log → ltp.primitives → ltp)
_MERKLE_LOG_NAMES = {"MerkleTree", "SignedTreeHead", "InclusionProof", "MerkleLog"}
_ANCHOR_NAMES = {"EntityState", "VALID_TRANSITIONS", "validate_transition", "AnchorSubmission"}
_VERIFY_NAMES = {"VerificationResult", "verify_envelope", "verify_receipt",
                 "verify_merkle_proof", "verify_sth", "verify_commitment_chain"}
_PORTABLE_PROOF_NAMES = {"TreeType", "PortableMerkleProof"}


def __getattr__(name: str):
    if name in _MERKLE_LOG_NAMES:
        from .merkle_log import MerkleTree, SignedTreeHead, InclusionProof, MerkleLog
        _map = {
            "MerkleTree": MerkleTree,
            "SignedTreeHead": SignedTreeHead,
            "InclusionProof": InclusionProof,
            "MerkleLog": MerkleLog,
        }
        return _map[name]
    if name in _ANCHOR_NAMES:
        from .anchor import EntityState, VALID_TRANSITIONS, validate_transition, AnchorSubmission
        _map = {
            "EntityState": EntityState,
            "VALID_TRANSITIONS": VALID_TRANSITIONS,
            "validate_transition": validate_transition,
            "AnchorSubmission": AnchorSubmission,
        }
        return _map[name]
    if name in _VERIFY_NAMES:
        from .verify import (
            VerificationResult, verify_envelope, verify_receipt,
            verify_merkle_proof, verify_sth, verify_commitment_chain,
        )
        _map = {
            "VerificationResult": VerificationResult,
            "verify_envelope": verify_envelope,
            "verify_receipt": verify_receipt,
            "verify_merkle_proof": verify_merkle_proof,
            "verify_sth": verify_sth,
            "verify_commitment_chain": verify_commitment_chain,
        }
        return _map[name]
    if name in _PORTABLE_PROOF_NAMES:
        from .merkle_log.portable_proof import TreeType, PortableMerkleProof
        _map = {
            "TreeType": TreeType,
            "PortableMerkleProof": PortableMerkleProof,
        }
        return _map[name]
    raise AttributeError(f"module 'ltp' has no attribute {name!r}")
