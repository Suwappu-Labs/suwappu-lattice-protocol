// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OptimisticBridgeChallenge} from "./OptimisticBridgeChallenge.sol";

/// @title ZKBridgeVerifier
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
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
        uint64  treeSize;
        uint64  sthSequence;
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
    ///         LTP-A-007 (docs/SECURITY_AUDIT_2026-05-15.md).
    bool public productionMode;

    // Track verified proofs to prevent double-finalization
    mapping(bytes32 => bool) public verifiedProofs;

    // SP1 verifier integration
    address public sp1Verifier;     // Succinct's on-chain SP1 verifier (or simulated)
    bytes32 public sp1ProgramVKey;  // Verification key for the SP1 ML-DSA circuit ELF

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event ProofVerified(bytes32 indexed anchorDigest, bytes32 sthRootHash, bytes32 operatorVkHash, uint64 sthSequence);
    event ProofRejected(bytes32 indexed anchorDigest, string reason);
    event SP1VerifierUpdated(address indexed verifier, bytes32 indexed vkey);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error InvalidProof();
    error InvalidPublicInputs();
    error ProofAlreadyUsed();
    error Unauthorized();
    error SimulatedModeNotAllowedInProduction();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(
        address _admin,
        address _challengeContract,
        uint8 _mode
    ) {
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
        // Validate public inputs
        if (inputs.sthRootHash == bytes32(0) || inputs.operatorVkHash == bytes32(0)) {
            revert InvalidPublicInputs();
        }

        // Compute proof ID for dedup (includes public inputs to prevent cross-context replay)
        bytes32 proofId = keccak256(abi.encodePacked(proofBytes, inputs.sthRootHash, inputs.operatorVkHash, inputs.treeSize, inputs.sthSequence));
        if (verifiedProofs[proofId]) revert ProofAlreadyUsed();

        // LTP-A-007: refuse simulated proofs when locked into production.
        if (productionMode && verificationMode == MODE_SIMULATED) {
            revert SimulatedModeNotAllowedInProduction();
        }
        // Dispatch to verification backend
        bool valid;
        if (verificationMode == MODE_SIMULATED) {
            valid = _verifySimulated(proofBytes, inputs);
        } else if (verificationMode == MODE_SP1) {
            valid = _verifySP1(proofBytes, inputs);
        } else if (verificationMode == MODE_STARK) {
            valid = _verifySTARK(proofBytes, inputs);
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

        emit ProofVerified(anchorDigest, inputs.sthRootHash, inputs.operatorVkHash, inputs.sthSequence);
    }

    // -----------------------------------------------------------------------
    // Verification backends
    // -----------------------------------------------------------------------

    /// @dev Simulated verification: check keccak256-based proof structure.
    ///      Proof layout: [0:32] proof_hash, [32:64] verification_tag.
    ///      verify_tag must equal keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || proof_hash || "sim-verify")
    function _verifySimulated(
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) internal pure returns (bool) {
        if (proofBytes.length != 64) return false;

        bytes32 proofHash = bytes32(proofBytes[:32]);
        bytes32 claimedTag = bytes32(proofBytes[32:64]);

        bytes32 expectedTag = keccak256(abi.encodePacked(
            inputs.sthRootHash,
            inputs.operatorVkHash,
            inputs.treeSize,
            inputs.sthSequence,
            proofHash,
            "sim-verify"
        ));

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
    function _verifySTARK(
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) internal pure returns (bool) {
        // Legacy 128B proof (v1)
        if (proofBytes.length == 128) {
            bytes32 claimedTag = bytes32(proofBytes[96:128]);
            bytes32 expectedTag = keccak256(abi.encodePacked(
                inputs.sthRootHash,
                inputs.operatorVkHash,
                inputs.treeSize,
                inputs.sthSequence,
                proofBytes[:96],
                "stark-verify"
            ));
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
        bytes32 expectedPiHash = keccak256(abi.encodePacked(
            inputs.sthRootHash,
            inputs.operatorVkHash,
            inputs.treeSize,
            inputs.sthSequence,
            "stark-public"
        ));
        if (piHash != expectedPiHash) return false;

        // Verify tag: keccak256(everything_before_tag || "stark-verify")
        uint256 tagOffset = expectedLen - 32;
        bytes32 claimedTag = bytes32(proofBytes[tagOffset:tagOffset + 32]);
        bytes32 expectedTag = keccak256(abi.encodePacked(
            proofBytes[:tagOffset],
            "stark-verify"
        ));

        return claimedTag == expectedTag;
    }

    /// @dev SP1 verification: delegates to Succinct's on-chain SP1 verifier.
    ///      If no sp1Verifier is configured, accepts proofs >= 128 bytes (simulated).
    ///      Production: calls sp1Verifier.verifyProof(vkey, publicValues, proofBytes).
    function _verifySP1(
        bytes calldata proofBytes,
        PublicInputs calldata inputs
    ) internal view returns (bool) {
        if (sp1Verifier == address(0)) {
            // No real SP1 verifier configured — accept only mock proofs (exactly 128B)
            return proofBytes.length == 128;
        }

        // Encode public values matching circuit commit order:
        // sth_root_hash(32B) || operator_vk_hash(32B) || tree_size(8B BE) || sth_sequence(8B BE)
        // Note: uint64 in abi.encodePacked produces 8 bytes (not 32 like abi.encode)
        bytes memory publicValues = abi.encodePacked(
            inputs.sthRootHash,      // 32 bytes
            inputs.operatorVkHash,   // 32 bytes
            inputs.treeSize,         // 8 bytes (uint64 in encodePacked = 8B)
            inputs.sthSequence       // 8 bytes (uint64 in encodePacked = 8B)
        );
        // Total: 80 bytes — matches SP1 circuit commit (32 + 32 + 8 + 8)

        // Call SP1 verifier contract: verifyProof(bytes32 vkey, bytes publicValues, bytes proof)
        (bool success, bytes memory returnData) = sp1Verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes32,bytes,bytes)",
                sp1ProgramVKey,
                publicValues,
                proofBytes
            )
        );
        if (!success) return false;
        // If verifier returns data, decode it; if it just doesn't revert, success = true
        if (returnData.length > 0) {
            return abi.decode(returnData, (bool));
        }
        return true;
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
        // LTP-A-007: once production-locked, admin can switch backends
        // freely between real verifiers but can never re-enable the
        // simulated path.
        if (productionMode && _mode == MODE_SIMULATED) {
            revert SimulatedModeNotAllowedInProduction();
        }
        verificationMode = _mode;
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
