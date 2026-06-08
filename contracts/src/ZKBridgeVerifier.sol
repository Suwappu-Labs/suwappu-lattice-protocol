// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OptimisticBridgeChallenge} from "./OptimisticBridgeChallenge.sol";

/// @title ZKBridgeVerifier
/// @author Javier Calderon Jr, CTO of Suwappu
/// @notice On-chain ZK proof verification for instant bridge finality.
///         Accepts proof bytes + public inputs, verifies the proof, and calls
///         finalizeWithZKProof on the challenge contract.
/// @dev Simulated backend: keccak256 hash check matching Python PoC.
///      Production: delegates to SP1Verifier or RiscZeroVerifier contracts.
contract ZKBridgeVerifier {
    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct PublicInputs {
        bytes32 sthRootHash;
        bytes32 operatorVkHash;
        uint64 treeSize;
        uint64 sthSequence;
    }

    // Verification mode
    uint8 public constant MODE_SIMULATED = 0;
    uint8 public constant MODE_SP1 = 1;
    uint8 public constant MODE_RISC_ZERO = 2;
    uint8 public constant MODE_STARK = 3;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;
    OptimisticBridgeChallenge public challengeContract;
    uint8 public verificationMode;
    /// @notice When true, MODE_SIMULATED is rejected at verify time and
    ///         the flag itself becomes irreversibly locked.
    ///         LTP-A-007 (docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md).
    bool public productionMode;

    // Track verified proofs to prevent double-finalization
    mapping(bytes32 => bool) public verifiedProofs;

    // SP1 verifier integration
    address public sp1Verifier; // Succinct's on-chain SP1 verifier (or simulated)
    bytes32 public sp1ProgramVKey; // Verification key for the SP1 ML-DSA circuit ELF

    /// @notice Authorized operator verification-key hashes (C3 / P3-1). A proof
    ///         is only accepted if its `operatorVkHash` is registered here — a
    ///         self-signed/unauthorized key cannot finalize anything.
    mapping(bytes32 => bool) public authorizedOperatorVk;

    /// @notice Addresses permitted to submit verifyAndFinalize (C3 access
    ///         control). Defense-in-depth on top of operator authorization.
    mapping(address => bool) public isProver;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event ProofVerified(
        bytes32 indexed anchorDigest,
        bytes32 sthRootHash,
        bytes32 operatorVkHash,
        uint64 sthSequence
    );
    event ProofRejected(bytes32 indexed anchorDigest, string reason);
    event SP1VerifierUpdated(address indexed verifier, bytes32 indexed vkey);
    event OperatorVkSet(bytes32 indexed operatorVkHash, bool authorized);
    event ProverSet(address indexed prover, bool authorized);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error InvalidProof();
    error InvalidPublicInputs();
    error ProofAlreadyUsed();
    error Unauthorized();
    error UnauthorizedOperator(bytes32 operatorVkHash);
    error UnauthorizedProver(address caller);
    error SimulatedModeNotAllowedInProduction();
    error SP1VerifierNotConfigured();
    error STARKModeDisabled();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address _admin, address _challengeContract, uint8 _mode) {
        admin = _admin;
        challengeContract = OptimisticBridgeChallenge(_challengeContract);
        verificationMode = _mode;
        // productionMode defaults false; production deploys call
        // `lockProduction()` post-deploy to refuse MODE_SIMULATED.
    }

    event ProductionModeLocked();

    /// @notice Irreversibly lock the contract into production mode.
    ///         After this call:
    ///           - MODE_SIMULATED is rejected at verify time
    ///           - This function reverts on every subsequent call
    ///           - setVerificationMode rejects any future switch to
    ///             MODE_SIMULATED
    ///         Admin only. LTP-A-007.
    function lockProduction() external {
        if (msg.sender != admin) revert Unauthorized();
        if (verificationMode == MODE_SIMULATED) revert SimulatedModeNotAllowedInProduction();
        if (verificationMode == MODE_STARK) revert STARKModeDisabled();
        if (verificationMode == MODE_SP1 && sp1Verifier == address(0)) {
            revert SP1VerifierNotConfigured();
        }
        productionMode = true;
        emit ProductionModeLocked();
    }

    // -----------------------------------------------------------------------
    // Core function
    // -----------------------------------------------------------------------

    /// @notice Verify a ZK proof and finalize the entity on the challenge contract.
    /// @param anchorDigest The anchor digest to finalize
    /// @param proofBytes Raw proof bytes from the prover (64B for simulated)
    /// @param inputs Public inputs attesting to the STH being verified
    function verifyAndFinalize(
        bytes32 anchorDigest,
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) external {
        // C3 access control: only an authorized prover may submit.
        if (!isProver[msg.sender]) revert UnauthorizedProver(msg.sender);

        // Validate public inputs
        if (
            inputs.sthRootHash == bytes32(0) || inputs.operatorVkHash == bytes32(0)
                || anchorDigest == bytes32(0)
        ) {
            revert InvalidPublicInputs();
        }

        // C3 / P3-1: the attesting operator key must be authorized — a
        // self-signed/unregistered key cannot finalize anything.
        if (!authorizedOperatorVk[inputs.operatorVkHash]) {
            revert UnauthorizedOperator(inputs.operatorVkHash);
        }

        // Compute proof ID for dedup. C3: bind anchorDigest so a proof cannot be
        // replayed to finalize a DIFFERENT digest (and bind chainid+address so it
        // cannot be replayed onto another deployment).
        bytes32 proofId = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                anchorDigest,
                proofBytes,
                inputs.sthRootHash,
                inputs.operatorVkHash,
                inputs.treeSize,
                inputs.sthSequence
            )
        );
        if (verifiedProofs[proofId]) revert ProofAlreadyUsed();

        // LTP-A-007: refuse simulated proofs when locked into production.
        if (productionMode && verificationMode == MODE_SIMULATED) {
            revert SimulatedModeNotAllowedInProduction();
        }
        // Dispatch to verification backend. anchorDigest is threaded in so the
        // proof's public values commit to the exact digest being finalized (C3).
        bool valid;
        if (verificationMode == MODE_SIMULATED) {
            valid = _verifySimulated(anchorDigest, proofBytes, inputs);
        } else if (verificationMode == MODE_SP1) {
            valid = _verifySP1(anchorDigest, proofBytes, inputs);
        } else if (verificationMode == MODE_STARK) {
            // C5: STARK mode permanently disabled. _verifySTARK was a keccak256
            // tag check, not a cryptographic STARK verifier. Reverts to prevent
            // any accidental use.
            revert STARKModeDisabled();
        } else {
            // RISC Zero — future backend
            revert InvalidProof();
        }

        if (!valid) {
            emit ProofRejected(anchorDigest, "verification failed");
            revert InvalidProof();
        }

        // Mark proof as used
        verifiedProofs[proofId] = true;

        // Finalize on the challenge contract
        challengeContract.finalizeWithZKProof(anchorDigest);

        emit ProofVerified(
            anchorDigest, inputs.sthRootHash, inputs.operatorVkHash, inputs.sthSequence
        );
    }

    // -----------------------------------------------------------------------
    // Verification backends
    // -----------------------------------------------------------------------

    /// @dev Simulated verification: check keccak256-based proof structure.
    ///      Proof layout: [0:32] proof_hash, [32:64] verification_tag.
    ///      verify_tag must equal keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || proof_hash || "sim-verify")
    function _verifySimulated(
        bytes32 anchorDigest,
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) internal pure returns (bool) {
        if (proofBytes.length != 64) return false;

        bytes32 proofHash = bytes32(proofBytes[:32]);
        bytes32 claimedTag = bytes32(proofBytes[32:64]);

        // C3: bind anchorDigest into the tag so the proof commits to the exact
        // digest being finalized.
        bytes32 expectedTag = keccak256(
            abi.encodePacked(
                anchorDigest,
                inputs.sthRootHash,
                inputs.operatorVkHash,
                inputs.treeSize,
                inputs.sthSequence,
                proofHash,
                "sim-verify"
            )
        );

        return claimedTag == expectedTag;
    }

    /// @dev STARK verification: supports legacy (128B) and real FRI-based (v3) proofs.
    ///
    ///      Legacy (128B): [0:96] layers, [96:128] verify_tag
    ///        verify_tag = keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || layers || "stark-verify")
    ///
    ///      V3 FRI-based: header(8B) + pi_hash(32B) + witness_hash(32B) + roots(N*32B) + verify_tag(32B)
    ///        verify_tag = keccak256(header || pi_hash || witness_hash || roots || "stark-verify")
    ///        pi_hash must match keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || "stark-public")
    function _verifySTARK(bytes calldata proofBytes, PublicInputs calldata inputs)
        internal
        pure
        returns (bool)
    {
        // Legacy 128B proof (v1)
        if (proofBytes.length == 128) {
            bytes32 claimedTag = bytes32(proofBytes[96:128]);
            bytes32 expectedTag = keccak256(
                abi.encodePacked(
                    inputs.sthRootHash,
                    inputs.operatorVkHash,
                    inputs.treeSize,
                    inputs.sthSequence,
                    proofBytes[:96],
                    "stark-verify"
                )
            );
            return claimedTag == expectedTag;
        }

        // V3 FRI-based STARK proof
        if (proofBytes.length < 8) return false;

        uint8 version = uint8(proofBytes[0]);
        if (version < 3) return false;

        uint8 numRoots = uint8(proofBytes[1]);
        // Expected: 8 + 32 + 32 + (numRoots * 32) + 32
        uint256 expectedLen = 104 + (uint256(numRoots) * 32);
        if (proofBytes.length != expectedLen) return false;

        // Extract public_inputs_hash (bytes 8..40)
        bytes32 piHash = bytes32(proofBytes[8:40]);

        // Verify public_inputs_hash matches declared inputs
        bytes32 expectedPiHash = keccak256(
            abi.encodePacked(
                inputs.sthRootHash,
                inputs.operatorVkHash,
                inputs.treeSize,
                inputs.sthSequence,
                "stark-public"
            )
        );
        if (piHash != expectedPiHash) return false;

        // Verify tag: keccak256(everything_before_tag || "stark-verify")
        uint256 tagOffset = expectedLen - 32;
        bytes32 claimedTag = bytes32(proofBytes[tagOffset:tagOffset + 32]);
        bytes32 expectedTag = keccak256(abi.encodePacked(proofBytes[:tagOffset], "stark-verify"));

        return claimedTag == expectedTag;
    }

    /// @dev SP1 verification: delegates to Succinct's on-chain SP1 verifier.
    ///      Requires sp1Verifier to be set — no fallback to mock proofs.
    ///      Production: calls sp1Verifier.verifyProof(vkey, publicValues, proofBytes).
    function _verifySP1(
        bytes32 anchorDigest,
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) internal view returns (bool) {
        // C1: Never accept unverified input. sp1Verifier must be configured
        // before MODE_SP1 is used. Call setSP1Verifier() first.
        if (sp1Verifier == address(0)) revert SP1VerifierNotConfigured();
        // C4 fix: a staticcall to a code-less address returns (success=true,"")
        // which the tail used to treat as "verified". Reject a verifier with no
        // contract code so a misconfigured/not-yet-deployed verifier cannot
        // silently accept every proof.
        if (sp1Verifier.code.length == 0) revert SP1VerifierNotConfigured();

        // Encode public values matching circuit commit order. C3: anchorDigest is
        // prepended so the proof cryptographically commits to the exact digest it
        // finalizes. P9: block.chainid + address(this) are appended so the proof
        // also commits to the destination chain + verifier instance (previously
        // these were only in the dedup proofId, not the SNARK commitment, so a
        // genuine proof was portable across deployments). The SP1 circuit ELF MUST
        // commit these seven values IN THIS ORDER.
        // anchor_digest(32B) || sth_root_hash(32B) || operator_vk_hash(32B)
        //   || tree_size(8B BE) || sth_sequence(8B BE)
        //   || chain_id(32B) || verifier_addr(20B)
        bytes memory publicValues = abi.encodePacked(
            anchorDigest, // 32 bytes (C3 binding)
            inputs.sthRootHash, // 32 bytes
            inputs.operatorVkHash, // 32 bytes
            inputs.treeSize, // 8 bytes (uint64 in encodePacked = 8B)
            inputs.sthSequence, // 8 bytes (uint64 in encodePacked = 8B)
            uint256(block.chainid), // 32 bytes (P9: bind destination chain)
            address(this) // 20 bytes (P9: bind this verifier instance)
        );
        // Total: 164 bytes. A new ELF => a new vkey => deploying this change
        // requires rotating it via setSP1Verifier(newVerifier, newVkey).

        // Call SP1 verifier contract: verifyProof(bytes32 vkey, bytes publicValues, bytes proof)
        (bool success, bytes memory returnData) = sp1Verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes32,bytes,bytes)", sp1ProgramVKey, publicValues, proofBytes
            )
        );
        if (!success) return false;
        // C4 fix: a real SP1 verifier returns an ABI-encoded bool. Empty
        // returndata (e.g. from an EOA/code-less target) must NOT be treated as
        // a passing proof — reject it.
        if (returnData.length == 0) return false;
        return abi.decode(returnData, (bool));
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    function isProofUsed(bytes32 proofId) external view returns (bool) {
        return verifiedProofs[proofId];
    }

    // -----------------------------------------------------------------------
    // Admin
    // -----------------------------------------------------------------------

    function setVerificationMode(uint8 _mode) external {
        if (msg.sender != admin) revert Unauthorized();
        if (productionMode && _mode == MODE_SIMULATED) {
            revert SimulatedModeNotAllowedInProduction();
        }
        // STARK mode is permanently disabled — it used a keccak256 tag check,
        // not a cryptographic STARK proof. Use MODE_SP1 for production.
        if (_mode == MODE_STARK) revert STARKModeDisabled();
        verificationMode = _mode;
    }

    /// @notice Register/deregister an authorized operator verification-key hash (C3/P3-1).
    function setAuthorizedOperatorVk(bytes32 operatorVkHash, bool authorized) external {
        if (msg.sender != admin) revert Unauthorized();
        authorizedOperatorVk[operatorVkHash] = authorized;
        emit OperatorVkSet(operatorVkHash, authorized);
    }

    /// @notice Register/deregister an address permitted to submit verifyAndFinalize (C3).
    function setProver(address prover, bool authorized) external {
        if (msg.sender != admin) revert Unauthorized();
        isProver[prover] = authorized;
        emit ProverSet(prover, authorized);
    }

    function transferAdmin(address newAdmin) external {
        if (msg.sender != admin) revert Unauthorized();
        admin = newAdmin;
    }

    /// @notice Set the SP1 on-chain verifier contract and program verification key.
    function setSP1Verifier(address _verifier, bytes32 _vkey) external {
        if (msg.sender != admin) revert Unauthorized();
        sp1Verifier = _verifier;
        sp1ProgramVKey = _vkey;
        emit SP1VerifierUpdated(_verifier, _vkey);
    }
}
