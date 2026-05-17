// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPAnchorRegistry} from "./interfaces/ILTPAnchorRegistry.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title LTPAnchorRegistry
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice On-chain registry for LTP anchor digests with state machine,
///         per-signer sequencing, signer authorization, and emergency pause.
/// @dev Upgradeable via UUPS proxy pattern. Admin is expected to be a multi-sig.
///      Thin on-chain, thick off-chain — no PQ signature verification on-chain.
contract LTPAnchorRegistry is ILTPAnchorRegistry, Initializable, UUPSUpgradeable {
    // -----------------------------------------------------------------------
    // Constants — EntityState enum mirrors Python src/ltp/anchor/state.py
    // -----------------------------------------------------------------------

    uint8 public constant STATE_UNKNOWN       = 0;
    uint8 public constant STATE_COMMITTED     = 1;
    uint8 public constant STATE_ANCHORED      = 2;
    uint8 public constant STATE_MATERIALIZED  = 3;
    uint8 public constant STATE_DISPUTED      = 4;
    uint8 public constant STATE_DELETED       = 5;

    /// @notice Maximum items per batchAnchor call (gas DoS protection).
    uint256 public constant MAX_BATCH_SIZE = 100;

    // -----------------------------------------------------------------------
    // Storage (must be append-only for upgrade safety)
    // -----------------------------------------------------------------------

    address public admin;
    bool public paused;

    /// @notice anchorDigest => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    /// @notice signerVkHash => highest accepted sequence number
    mapping(bytes32 => uint64) public signerSequences;

    /// @notice entityIdHash => EntityState (uint8)
    mapping(bytes32 => uint8) public entityStates;

    /// @notice signerVkHash => authorized flag
    mapping(bytes32 => bool) public authorizedSigners;

    /// @notice signerVkHash => expiry timestamp for grace-period rotations.
    ///         Zero means "no scheduled expiry"; nonzero means the key is
    ///         authorized only while block.timestamp <= signerExpiresAt[vk].
    ///         LTP-A-030 in docs/SECURITY_AUDIT_2026-05-15.md.
    mapping(bytes32 => uint64) public signerExpiresAt;

    /// @notice entityIdHash => bound signerVkHash (v6: entity-signer binding)
    mapping(bytes32 => bytes32) public entitySigners;

    // -----------------------------------------------------------------------
    // LTP-A-005 Option C-3 storage — owner-signed binding statement +
    // on-chain dispute path (docs/SECURITY_AUDIT_2026-05-15.md).
    //
    // Off-chain: the relayer verifies the entity owner's ML-DSA signature
    //   over (entityIdHash || signerVkHash) before submitting the first
    //   anchor. The signature itself stays off-chain (ML-DSA verify is
    //   too expensive on-chain today); the registry stores hashes of the
    //   statement and signature so any future dispute can reference
    //   them.
    // On-chain: an authorized binding-dispute verifier (set by admin,
    //   distinct from the OptimisticBridgeChallenge zkVerifier) can call
    //   disputeBinding after verifying a SNARK that the stored signature
    //   was forged. Successful dispute clears the entitySigners binding
    //   so the legitimate owner can re-anchor with a fresh statement.

    struct BindingStatement {
        bytes32 signerVkHash;       // bound signer at first anchor
        bytes32 statementHash;      // hash of off-chain signed statement bytes
        bytes32 signatureHash;      // hash of the ML-DSA signature bytes
        uint64 bindingTimestamp;    // block.timestamp at first binding
        bool disputed;              // true if disputeBinding has been called
    }

    /// @notice entityIdHash => recorded binding statement evidence.
    mapping(bytes32 => BindingStatement) public bindingStatements;

    /// @notice Authorized address that may call disputeBinding. Distinct
    ///         from `admin` so admin compromise alone cannot dismiss a
    ///         legitimate binding-dispute claim. Admin sets via
    ///         setBindingDisputeVerifier — production v7 routes that
    ///         setter through the governance Timelock.
    address public bindingDisputeVerifier;

    // -----------------------------------------------------------------------
    // Constructor — disables initializers on the implementation contract
    // -----------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // -----------------------------------------------------------------------
    // Initializer (replaces constructor for proxy deployments)
    // -----------------------------------------------------------------------

    function initialize(address _admin) external initializer {
        if (_admin == address(0)) revert NotAdmin(address(0));
        admin = _admin;
        paused = false;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // -----------------------------------------------------------------------
    // Admin functions
    // -----------------------------------------------------------------------

    /// @notice Transfer admin role. Admin only.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert NotAdmin(address(0));
        address oldAdmin = admin;
        admin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    /// @notice Pause all anchoring operations. Admin only.
    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause anchoring operations. Admin only.
    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -----------------------------------------------------------------------
    // UUPS upgrade authorization
    // -----------------------------------------------------------------------

    /// @dev Only admin can authorize upgrades.
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external whenNotPaused {
        _anchor(
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            signerVkHash,
            sequence,
            validUntil,
            receiptType
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata entityIdHashes,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external whenNotPaused {
        uint256 len = anchorDigests.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (
            entityIdHashes.length != len ||
            merkleRoots.length != len ||
            policyHashes.length != len ||
            signerVkHashes.length != len ||
            sequences.length != len ||
            validUntils.length != len ||
            receiptTypes.length != len
        ) revert ArrayLengthMismatch();
        for (uint256 i = 0; i < len; ++i) {
            _anchor(
                anchorDigests[i],
                entityIdHashes[i],
                merkleRoots[i],
                policyHashes[i],
                signerVkHashes[i],
                sequences[i],
                validUntils[i],
                receiptTypes[i]
            );
        }

        emit BatchAnchored(len, anchorDigests[0]);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function transitionState(
        bytes32 entityIdHash,
        uint8   newState,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil
    ) external whenNotPaused {
        // 0. Zero-value guards (v6)
        if (entityIdHash == bytes32(0)) revert ZeroEntityId();
        if (signerVkHash == bytes32(0)) revert ZeroSignerVk();

        // 1. Signer authorization. A signer with a scheduled expiry
        //    (LTP-A-030 grace-period rotation) remains valid until
        //    block.timestamp passes signerExpiresAt.
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }
        uint64 expiresAt = signerExpiresAt[signerVkHash];
        if (expiresAt != 0 && block.timestamp > expiresAt) {
            revert UnauthorizedSigner(signerVkHash);
        }

        // 1b. Entity-signer binding (v6)
        bytes32 boundSigner = entitySigners[entityIdHash];
        if (boundSigner == bytes32(0)) {
            entitySigners[entityIdHash] = signerVkHash;
            emit EntitySignerBound(entityIdHash, signerVkHash);
        } else if (boundSigner != signerVkHash) {
            revert NotEntitySigner(entityIdHash, signerVkHash);
        }

        // 2. Sequence monotonicity
        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        // 3. Temporal expiry
        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        // 4. State transition validation
        uint8 currentState = entityStates[entityIdHash];
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 5. Update state
        entityStates[entityIdHash] = newState;

        // 6. Update signer sequence HWM
        signerSequences[signerVkHash] = sequence;

        emit StateTransitioned(entityIdHash, signerVkHash, currentState, newState, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function registerSigner(bytes32 vkHash) external onlyAdmin {
        if (vkHash == bytes32(0)) revert ZeroSignerVk();
        if (authorizedSigners[vkHash]) revert SignerAlreadyRegistered(vkHash);
        authorizedSigners[vkHash] = true;
        emit SignerRegistered(vkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function revokeSigner(bytes32 vkHash) external onlyAdmin {
        if (!authorizedSigners[vkHash]) revert SignerNotRegistered(vkHash);
        authorizedSigners[vkHash] = false;
        emit SignerRevoked(vkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function rotateSigner(bytes32 oldVkHash, bytes32 newVkHash) external onlyAdmin {
        _rotateSignerWithGrace(oldVkHash, newVkHash, 0);
    }

    /// @notice Rotate a signer with a grace period during which the old
    ///         key remains valid for already-signed in-flight anchors.
    ///         LTP-A-030 in docs/SECURITY_AUDIT_2026-05-15.md.
    /// @dev    The old key is NOT revoked at this call; instead its
    ///         expiry is recorded at `block.timestamp + gracePeriod`.
    ///         `_anchor()` rejects the old key once expiry elapses.
    ///         `gracePeriod` is capped at 7 days to bound ambiguity.
    function rotateSignerWithGrace(
        bytes32 oldVkHash,
        bytes32 newVkHash,
        uint64 gracePeriod
    ) external onlyAdmin {
        require(gracePeriod <= 7 days, "grace > 7d");
        _rotateSignerWithGrace(oldVkHash, newVkHash, gracePeriod);
    }

    function _rotateSignerWithGrace(
        bytes32 oldVkHash,
        bytes32 newVkHash,
        uint64 gracePeriod
    ) internal {
        if (oldVkHash == bytes32(0) || newVkHash == bytes32(0)) revert ZeroSignerVk();
        if (!authorizedSigners[oldVkHash]) revert SignerNotRegistered(oldVkHash);
        if (authorizedSigners[newVkHash]) revert SignerAlreadyRegistered(newVkHash);
        signerSequences[newVkHash] = signerSequences[oldVkHash];
        authorizedSigners[newVkHash] = true;
        if (gracePeriod == 0) {
            // Atomic rotation: old key revoked immediately.
            authorizedSigners[oldVkHash] = false;
            emit SignerRevoked(oldVkHash);
        } else {
            // Grace-period rotation: old key stays authorized; _anchor
            // additionally checks signerExpiresAt to gate in-flight use.
            signerExpiresAt[oldVkHash] = uint64(block.timestamp) + gracePeriod;
            emit SignerExpiryScheduled(oldVkHash, signerExpiresAt[oldVkHash]);
        }
        emit SignerRegistered(newVkHash);
        emit SignerRotated(oldVkHash, newVkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function reassignEntitySigner(bytes32 entityIdHash, bytes32 newSignerVkHash) external onlyAdmin {
        if (entityIdHash == bytes32(0)) revert ZeroEntityId();
        if (newSignerVkHash == bytes32(0)) revert ZeroSignerVk();
        if (!authorizedSigners[newSignerVkHash]) revert UnauthorizedSigner(newSignerVkHash);
        entitySigners[entityIdHash] = newSignerVkHash;
        emit EntitySignerBound(entityIdHash, newSignerVkHash);
    }

    // -----------------------------------------------------------------------
    // LTP-A-005 Option C-3 — owner-signed binding statement + dispute
    // -----------------------------------------------------------------------

    /// @notice Anchor and simultaneously record an owner-signed binding
    ///         statement as on-chain evidence. The relayer MUST have
    ///         verified the owner's ML-DSA signature off-chain before
    ///         calling this; the registry stores hashes for any future
    ///         dispute.
    /// @dev    On the FIRST anchor for an entity, this binds the entity
    ///         to `signerVkHash` AND records the statement evidence.
    ///         On subsequent anchors with the same signerVkHash, the
    ///         evidence parameters are ignored (binding is already
    ///         recorded). Pass zero for `bindingStatementHash` and
    ///         `bindingSignatureHash` if you don't want to record
    ///         evidence — equivalent to legacy `anchor()`.
    function anchorWithBinding(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType,
        bytes32 bindingStatementHash,
        bytes32 bindingSignatureHash
    ) external whenNotPaused {
        bool isFirstBinding = entitySigners[entityIdHash] == bytes32(0);

        _anchor(
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            signerVkHash,
            sequence,
            validUntil,
            receiptType
        );

        if (isFirstBinding && bindingStatementHash != bytes32(0)) {
            bindingStatements[entityIdHash] = BindingStatement({
                signerVkHash: signerVkHash,
                statementHash: bindingStatementHash,
                signatureHash: bindingSignatureHash,
                bindingTimestamp: uint64(block.timestamp),
                disputed: false
            });
            emit BindingStatementRecorded(
                entityIdHash, signerVkHash, bindingStatementHash, bindingSignatureHash
            );
        }
    }

    /// @notice Dispute a previously recorded binding by submitting a
    ///         cryptographic fraud proof. Callable only by the
    ///         authorized binding-dispute verifier (set by admin via
    ///         setBindingDisputeVerifier). The verifier is expected to
    ///         have validated a SNARK proving the recorded
    ///         `bindingSignatureHash` does NOT correspond to a valid
    ///         ML-DSA signature by the legitimate entity owner.
    /// @dev    On success: marks the binding as `disputed`, clears
    ///         `entitySigners[entityIdHash]` so the legitimate owner
    ///         can re-anchor with a fresh statement, and emits
    ///         BindingDisputed. The dispute is one-shot per binding —
    ///         once disputed, no further dispute call is accepted.
    function disputeBinding(bytes32 entityIdHash, bytes32 fraudProofHash) external {
        if (msg.sender != bindingDisputeVerifier || bindingDisputeVerifier == address(0)) {
            revert NotBindingDisputeVerifier(msg.sender);
        }
        BindingStatement storage b = bindingStatements[entityIdHash];
        if (b.bindingTimestamp == 0) revert NoBindingRecorded(entityIdHash);
        if (b.disputed) revert BindingAlreadyDisputed(entityIdHash);

        bytes32 disputedVk = b.signerVkHash;
        b.disputed = true;
        // Clear the binding so the legitimate owner can re-anchor.
        delete entitySigners[entityIdHash];
        // Reset the per-entity state machine to UNKNOWN so the legitimate
        // owner can transition back through UNKNOWN → ANCHORED (line ~597
        // in _isValidTransition). Without this reset, the attacker's
        // ANCHORED state persists and re-anchoring trips
        // InvalidStateTransition(ANCHORED, ANCHORED). The audit trail is
        // still preserved via `b.disputed = true` above and the
        // BindingDisputed event below.
        delete entityStates[entityIdHash];
        emit BindingDisputed(entityIdHash, disputedVk, fraudProofHash);
    }

    /// @notice Admin function — set the dispute verifier address.
    /// @dev    Production v7 deployments route this setter through the
    ///         governance Timelock; same reasoning as the
    ///         OptimisticBridgeChallenge arbiter wiring (LTP-A-006).
    function setBindingDisputeVerifier(address verifier) external onlyAdmin {
        emit BindingDisputeVerifierUpdated(bindingDisputeVerifier, verifier);
        bindingDisputeVerifier = verifier;
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function isAnchored(bytes32 anchorDigest) external view returns (bool) {
        return _anchors[anchorDigest].anchoredAt != 0;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityState(bytes32 entityIdHash) external view returns (uint8) {
        return entityStates[entityIdHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getSignerSequence(bytes32 vkHash) external view returns (uint64) {
        return signerSequences[vkHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory) {
        return _anchors[anchorDigest];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function areAnchored(bytes32[] calldata anchorDigests) external view returns (bool[] memory) {
        bool[] memory results = new bool[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]].anchoredAt != 0;
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityStates(
        bytes32[] calldata entityIdHashes
    ) external view returns (uint8[] memory) {
        uint8[] memory results = new uint8[](entityIdHashes.length);
        for (uint256 i = 0; i < entityIdHashes.length; ++i) {
            results[i] = entityStates[entityIdHashes[i]];
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecords(
        bytes32[] calldata anchorDigests
    ) external view returns (AnchorRecord[] memory) {
        AnchorRecord[] memory results = new AnchorRecord[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]];
        }
        return results;
    }

    /// @notice Returns the implementation version for upgrade tracking.
    function version() external pure returns (uint256) {
        return 6;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Core anchoring logic shared by anchor() and batchAnchor().
    function _anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) internal {
        // 0. Zero-value guards (v6)
        if (anchorDigest == bytes32(0)) revert ZeroDigest();
        if (entityIdHash == bytes32(0)) revert ZeroEntityId();
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        if (signerVkHash == bytes32(0)) revert ZeroSignerVk();
        // policyHash may be bytes32(0) — sentinel for "no policy enforced on-chain"

        // 1. Replay rejection
        if (_anchors[anchorDigest].anchoredAt != 0) {
            revert AlreadyAnchored(anchorDigest);
        }

        // 2. Signer authorization (mirrors governance.py:143-173 and
        //    transitionState's LTP-A-030 grace-period check). A signer
        //    with a scheduled expiry (`rotateSignerWithGrace`) remains
        //    valid only until block.timestamp passes signerExpiresAt;
        //    omitting this check would let a rotated-out key keep
        //    anchoring indefinitely. See LTP-A-031 + SCN-015.
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }
        {
            uint64 expiresAt = signerExpiresAt[signerVkHash];
            if (expiresAt != 0 && block.timestamp > expiresAt) {
                revert UnauthorizedSigner(signerVkHash);
            }
        }

        // 2b. Entity-signer binding (v6: first write wins, then enforced)
        {
            bytes32 boundSigner = entitySigners[entityIdHash];
            if (boundSigner == bytes32(0)) {
                entitySigners[entityIdHash] = signerVkHash;
                emit EntitySignerBound(entityIdHash, signerVkHash);
            } else if (boundSigner != signerVkHash) {
                revert NotEntitySigner(entityIdHash, signerVkHash);
            }
        }

        // 3. Sequence monotonicity (mirrors sequencing.py:68-74)
        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        // 4. Temporal expiry (mirrors sequencing.py:65-66)
        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        // 5. State transition: entity state → ANCHORED
        uint8 currentState = entityStates[entityIdHash];
        uint8 newState = STATE_ANCHORED;
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 6. Store the anchor record
        _anchors[anchorDigest] = AnchorRecord({
            merkleRoot:    merkleRoot,
            policyHash:    policyHash,
            signerVkHash:  signerVkHash,
            entityIdHash:  entityIdHash,
            sequence:      sequence,
            validUntil:    validUntil,
            targetChainId: uint64(block.chainid), // stamped from block.chainid, not caller-supplied (cross-chain replay prevention)
            receiptType:   receiptType,
            entityState:   newState,
            anchoredAt:    uint64(block.timestamp)
        });

        // 7. Update signer sequence HWM
        signerSequences[signerVkHash] = sequence;

        // 8. Update entity state
        entityStates[entityIdHash] = newState;

        emit Anchored(anchorDigest, entityIdHash, signerVkHash, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
    }

    /// @dev Validate entity state transitions. Mirrors Python state.py:37-51.
    function _isValidTransition(uint8 from_, uint8 to_) internal pure returns (bool) {
        if (from_ == STATE_UNKNOWN   && to_ == STATE_COMMITTED)    return true;
        if (from_ == STATE_COMMITTED && to_ == STATE_ANCHORED)     return true;
        if (from_ == STATE_ANCHORED  && to_ == STATE_MATERIALIZED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DELETED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DELETED) return true;
        if (from_ == STATE_DISPUTED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_UNKNOWN && to_ == STATE_ANCHORED) return true;
        return false;
    }

    // -----------------------------------------------------------------------
    // Storage gap — reserves slots for future upgrades without colliding
    // with derived contract storage. Standard OpenZeppelin pattern.
    // -----------------------------------------------------------------------

    uint256[49] private __gap;
}
