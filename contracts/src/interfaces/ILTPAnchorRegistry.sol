// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ILTPAnchorRegistry
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice Interface for the LTP on-chain anchor registry.
/// @dev Stores anchor digests, enforces state machine transitions,
///      tracks per-signer sequences, and manages signer authorization.
interface ILTPAnchorRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct AnchorRecord {
        bytes32 merkleRoot;
        bytes32 policyHash;
        bytes32 signerVkHash;
        bytes32 entityIdHash;
        uint64  sequence;
        uint64  validUntil;
        uint64  targetChainId;
        uint8   receiptType;
        uint8   entityState;
        uint64  anchoredAt;
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Anchored(
        bytes32 indexed anchorDigest,
        bytes32 indexed entityIdHash,
        bytes32 indexed signerVkHash,
        uint64 sequence
    );

    event BatchAnchored(
        uint256 count,
        bytes32 indexed firstDigest
    );

    event SignerRegistered(bytes32 indexed vkHash);
    event SignerRevoked(bytes32 indexed vkHash);

    event StateTransition(
        bytes32 indexed entityIdHash,
        uint8 fromState,
        uint8 toState
    );

    event StateTransitioned(
        bytes32 indexed entityIdHash,
        bytes32 indexed signerVkHash,
        uint8 fromState,
        uint8 toState,
        uint64 sequence
    );

    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // v6 — entity-signer binding
    event EntitySignerBound(bytes32 indexed entityIdHash, bytes32 indexed signerVkHash);

    // v6 — signer rotation
    event SignerRotated(bytes32 indexed oldVkHash, bytes32 indexed newVkHash);

    // v7 — signer rotation grace period (LTP-A-030)
    event SignerExpiryScheduled(bytes32 indexed vkHash, uint64 expiresAt);

    // v7 — owner-signed binding statement (LTP-A-005 Option C-3)
    event BindingStatementRecorded(
        bytes32 indexed entityIdHash,
        bytes32 indexed signerVkHash,
        bytes32 statementHash,
        bytes32 signatureHash
    );
    event BindingDisputed(
        bytes32 indexed entityIdHash,
        bytes32 indexed disputedSignerVkHash,
        bytes32 fraudProofHash
    );
    event BindingDisputeVerifierUpdated(address indexed previous, address indexed next);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error AlreadyAnchored(bytes32 anchorDigest);
    error SequenceTooLow(bytes32 signerVkHash, uint64 provided, uint64 current);
    error Expired(uint64 validUntil, uint64 blockTimestamp);
    error UnauthorizedSigner(bytes32 signerVkHash);
    error InvalidStateTransition(uint8 fromState, uint8 toState);
    error NotAdmin(address caller);
    error EmptyBatch();
    error BatchTooLarge(uint256 provided, uint256 max);
    error ArrayLengthMismatch();
    error ContractPaused();

    // v6 — zero-value guards
    error ZeroDigest();
    error ZeroMerkleRoot();
    error ZeroEntityId();
    error ZeroSignerVk();

    // v6 — entity-signer binding
    error NotEntitySigner(bytes32 entityIdHash, bytes32 signerVkHash);

    // v7 — binding-statement dispute (LTP-A-005 Option C-3)
    error NotBindingDisputeVerifier(address caller);
    error BindingAlreadyDisputed(bytes32 entityIdHash);
    error NoBindingRecorded(bytes32 entityIdHash);

    // v6 — signer rotation
    error SignerNotRegistered(bytes32 vkHash);
    error SignerAlreadyRegistered(bytes32 vkHash);

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @notice Anchor a single trust artifact on-chain.
    function anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external;

    /// @notice Anchor multiple trust artifacts in a single transaction.
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata entityIdHashes,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external;

    /// @notice Transition an entity's state without a new anchor record.
    function transitionState(
        bytes32 entityIdHash,
        uint8   newState,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil
    ) external;

    /// @notice Register an authorized signer by VK hash. Admin only.
    function registerSigner(bytes32 vkHash) external;

    /// @notice Revoke an authorized signer. Admin only.
    function revokeSigner(bytes32 vkHash) external;

    /// @notice Atomically rotate a signer key. Admin only.
    function rotateSigner(bytes32 oldVkHash, bytes32 newVkHash) external;

    /// @notice Reassign an entity's bound signer. Admin only.
    function reassignEntitySigner(bytes32 entityIdHash, bytes32 newSignerVkHash) external;

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @notice Check if an anchor digest has been recorded.
    function isAnchored(bytes32 anchorDigest) external view returns (bool);

    /// @notice Get the entity state for an entity ID hash.
    function getEntityState(bytes32 entityIdHash) external view returns (uint8);

    /// @notice Get the current sequence for a signer VK hash.
    function getSignerSequence(bytes32 vkHash) external view returns (uint64);

    /// @notice Get the full anchor record for a digest.
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory);

    /// @notice Batch check if anchor digests have been recorded.
    function areAnchored(bytes32[] calldata anchorDigests) external view returns (bool[] memory);

    /// @notice Batch get entity states.
    function getEntityStates(
        bytes32[] calldata entityIdHashes
    ) external view returns (uint8[] memory);

    /// @notice Batch get anchor records.
    function getAnchorRecords(
        bytes32[] calldata anchorDigests
    ) external view returns (AnchorRecord[] memory);
}
