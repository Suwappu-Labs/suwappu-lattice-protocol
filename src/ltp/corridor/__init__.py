"""LTP corridor surface — wire-compatible with `gsx-dag/crates/gsx-ltp`.

This package mirrors the Rust crate byte-for-byte so a Python LTP corridor
witness can interoperate with the GSX DAG L1 7-of-9 attestation pipeline,
Commitment-Node DA SLA, and cross-chain DID rotation proof surface.

See `docs/design-decisions/GSX_DAG_DB_INTEGRATION.md` for the cross-repo
boundary and `gsx_dag_l1_academic_v7.pdf` §10 for the protocol spec.
"""

from .attestation import (
    AggregateVerificationFailed,
    AttestationPayload,
    AuthorityId,
    BadCorridorSize,
    BelowQuorum,
    ChainId,
    Corridor,
    CorridorAttestation,
    CorridorId,
    InvalidSignature,
    LtpError,
    SuperNode,
    UnknownWitness,
    WitnessSignature,
    attest,
    verify_attestation,
)
from .bls import (
    CorridorBlsBackendMissing,
    corridor_aggregate_signatures,
    corridor_aggregate_verify,
    corridor_sign,
    corridor_verify,
    keygen,
)
from .constants import (
    BLS_CORRIDOR_DST,
    DOMAIN_TAG_ATTEST,
    DOMAIN_TAG_CID,
    DOMAIN_TAG_DID_STARK,
    LTP_ATTESTATION_QUORUM_SIZE,
    LTP_ATTESTATION_QUORUM_THRESHOLD,
    ON_CHAIN_COMMITMENT_BYTES,
)
from .da import (
    DA_SLA_DEFAULT,
    Cid,
    Commitment,
    CommitmentNetwork,
    CommitmentNotFound,
    DaError,
    DaSla,
    LatencyExceeded,
    PayloadMismatch,
    RetentionExpired,
    verify_sla,
)
from .did_doc import (
    DidDocument,
    DidError,
    KeyAlgorithm,
    Service,
    VerificationMethod,
    VerificationMethodId,
    VerificationRelationship,
)
from .did_stark import (
    DidRotationStatement,
    DidStarkError,
    DidStarkProof,
    InvalidSignature as DidStarkInvalidSignature,
    OldDocHashMismatch,
    UnauthorizedMethod,
    UnknownMethod,
    prove_rotation,
    prove_rotation_with_doc,
    verify_rotation_proof,
    verify_rotation_proof_with_doc,
)
from .envelope import (
    BLS_G2_COMPRESSED_BYTES,
    ML_KEM_768_CT_BYTES,
    ML_KEM_1024_CT_BYTES,
    SHA3_256_BYTES,
    EnvelopeSizeError,
    OnChainCommitment,
)
from .digest import sha3_256_domain
from .state_anchor import (
    GENESIS_PARENT,
    AuthScheme,
    StateAnchor,
    compute_mac_blake3,
    compute_mac_keccak256,
    hash_anchor_blake3,
    hash_anchor_keccak256,
)
from .submission import (
    CorridorAnchorBuild,
    CorridorAnchorError,
    build_state_anchor_blake3,
    build_state_anchor_keccak256,
)

__all__ = [
    # constants
    "ON_CHAIN_COMMITMENT_BYTES",
    "LTP_ATTESTATION_QUORUM_SIZE",
    "LTP_ATTESTATION_QUORUM_THRESHOLD",
    "DOMAIN_TAG_ATTEST",
    "DOMAIN_TAG_CID",
    "DOMAIN_TAG_DID_STARK",
    "BLS_CORRIDOR_DST",
    # digest
    "sha3_256_domain",
    # attestation
    "AttestationPayload",
    "WitnessSignature",
    "CorridorAttestation",
    "Corridor",
    "SuperNode",
    "AuthorityId",
    "ChainId",
    "CorridorId",
    "attest",
    "verify_attestation",
    "LtpError",
    "BadCorridorSize",
    "BelowQuorum",
    "UnknownWitness",
    "InvalidSignature",
    "AggregateVerificationFailed",
    # bls
    "keygen",
    "corridor_sign",
    "corridor_verify",
    "corridor_aggregate_signatures",
    "corridor_aggregate_verify",
    "CorridorBlsBackendMissing",
    # da
    "Cid",
    "DaSla",
    "DA_SLA_DEFAULT",
    "Commitment",
    "CommitmentNetwork",
    "verify_sla",
    "DaError",
    "CommitmentNotFound",
    "PayloadMismatch",
    "RetentionExpired",
    "LatencyExceeded",
    # did stark
    "DidRotationStatement",
    "DidStarkProof",
    "prove_rotation",
    "verify_rotation_proof",
    "DidStarkError",
    "OldDocHashMismatch",
    "DidStarkInvalidSignature",
    # gsx-db state anchor
    "StateAnchor",
    "AuthScheme",
    "GENESIS_PARENT",
    "compute_mac_blake3",
    "compute_mac_keccak256",
    "hash_anchor_blake3",
    "hash_anchor_keccak256",
    # DID document
    "DidDocument",
    "VerificationMethod",
    "VerificationMethodId",
    "VerificationRelationship",
    "KeyAlgorithm",
    "Service",
    "DidError",
    "UnknownMethod",
    "UnauthorizedMethod",
    "prove_rotation_with_doc",
    "verify_rotation_proof_with_doc",
    # Constant-size commitment envelope
    "OnChainCommitment",
    "EnvelopeSizeError",
    "ML_KEM_768_CT_BYTES",
    "ML_KEM_1024_CT_BYTES",
    "BLS_G2_COMPRESSED_BYTES",
    "SHA3_256_BYTES",
    # Corridor → gsx-db submission bridge
    "build_state_anchor_blake3",
    "build_state_anchor_keccak256",
    "CorridorAnchorBuild",
    "CorridorAnchorError",
]
