// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GsxDagValidatorRegistry} from "./GsxDagValidatorRegistry.sol";

/// @notice Minimal interface for the Succinct SP1 on-chain verifier.
///         verifyProof reverts on failure (void return), matching the real ISP1Verifier.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @title Sp1QuorumVerifier
/// @notice Finalizes a GSX-DAG block's EVM state root once an SP1 Groth16 proof
///         of a >2/3-stake ML-DSA-65 validator quorum is verified on-chain.
///
/// @dev HONEST FRAMING — read this:
///   - The SP1 proof circuit (sp1-quorum-verifier) verifies ML-DSA-65 signatures
///     from >2/3 of the tracked validator set over a header attestation
///     blake3(HEADER_DOMAIN || networkId || oracle || blockNumber || stateRoot).
///   - The SNARK wrapping those ML-DSA verifications is classical BN254 (Groth16) —
///     NOT post-quantum. A quantum adversary that can break BN254 discrete-log can
///     forge the SNARK. The ML-DSA-65 verifications are proved inside the circuit,
///     not on-chain; the on-chain verifier only checks the Groth16 proof.
///   - The native-precompile path (GsxDagQuorumHeaderOracle with 0x0101) is the
///     actual post-quantum path; this contract is the SNARK-wrapped equivalent for
///     chains that lack the 0x0101 precompile.
///   - Trust model: trust an honest >2/3-stake quorum of the tracked set
///     (sync-committee style). This is NOT consensus light-client verification.
///   - The public values bind networkId, blockNumber, stateRoot, and validatorSetRoot.
///     They do NOT bind the oracle address — oracle is in the header_digest signed by
///     validators, so it is enforced implicitly via the ML-DSA signatures rather than
///     via the on-chain public-values check.
///
/// @dev Public-values layout (128 bytes, abi.encodePacked):
///   [0..32]   networkId          (bytes32, = registry.networkId())
///   [32..64]  blockNumber        (uint256 BE)
///   [64..96]  stateRoot          (bytes32)
///   [96..128] validatorSetRoot   (bytes32, = registry.currentValidatorSetRoot())
contract Sp1QuorumVerifier {
    // -----------------------------------------------------------------------
    // Immutables
    // -----------------------------------------------------------------------

    /// @notice The SP1 on-chain verifier (Succinct's deployed ISP1Verifier, or a mock in tests).
    ISP1Verifier public immutable sp1Verifier;

    /// @notice The SP1 program verification key for the sp1-quorum-verifier ELF.
    bytes32 public immutable vkey;

    /// @notice The GSX-DAG validator registry — provides networkId, currentValidatorSetRoot.
    GsxDagValidatorRegistry public immutable registry;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice blockNumber => finalized EVM state root.
    ///         Non-zero means finalized. Idempotent for the same root.
    mapping(uint256 => bytes32) private _stateRoots;

    // -----------------------------------------------------------------------
    // Events & Errors
    // -----------------------------------------------------------------------

    event HeaderFinalized(uint256 indexed blockNumber, bytes32 stateRoot, bytes32 validatorSetRoot);

    error ZeroStateRoot();
    error HeaderConflict(uint256 blockNumber);
    error SP1VerifierNotDeployed();
    error PublicValuesMismatch();
    error ValidatorSetRootMismatch(bytes32 fromProof, bytes32 fromRegistry);

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address sp1Verifier_, bytes32 vkey_, address registry_) {
        require(sp1Verifier_ != address(0), "Sp1QuorumVerifier: zero sp1Verifier");
        require(registry_ != address(0), "Sp1QuorumVerifier: zero registry");
        sp1Verifier = ISP1Verifier(sp1Verifier_);
        vkey = vkey_;
        registry = GsxDagValidatorRegistry(registry_);
    }

    // -----------------------------------------------------------------------
    // Core function
    // -----------------------------------------------------------------------

    /// @notice Submit an SP1 proof of >2/3-stake ML-DSA quorum over a header.
    ///         Finalizes `stateRoot` for `blockNumber` if the proof is valid.
    ///         Idempotent: a second call with the same root is a no-op.
    ///
    /// @param blockNumber    The GSX-DAG block number being finalized.
    /// @param stateRoot      The EVM state root attested by the quorum.
    /// @param validatorSetRoot  The keccak256 root of the validator set that signed.
    ///                       Must equal registry.currentValidatorSetRoot() and the
    ///                       value committed by the circuit.
    /// @param publicValues   The 128-byte public values committed by the SP1 circuit.
    ///                       Must equal abi.encodePacked(registry.networkId(),
    ///                       uint256(blockNumber), stateRoot, validatorSetRoot).
    /// @param proofBytes     The raw SP1 proof (Groth16 bytes).
    function submitProvenHeader(
        uint256 blockNumber,
        bytes32 stateRoot,
        bytes32 validatorSetRoot,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        if (stateRoot == bytes32(0)) revert ZeroStateRoot();

        // Idempotency: if the same root is already final, no-op.
        bytes32 existing = _stateRoots[blockNumber];
        if (existing != bytes32(0)) {
            if (existing != stateRoot) revert HeaderConflict(blockNumber);
            return;
        }

        // C4: reject a verifier with no contract code — a code-less address
        // returns (success=true,"") from staticcall, which must not be treated
        // as a valid proof.
        if (address(sp1Verifier).code.length == 0) revert SP1VerifierNotDeployed();

        // Reconstruct expected public values:
        //   networkId(32) || uint256(blockNumber)(32) || stateRoot(32) || validatorSetRoot(32)
        // This MUST be byte-identical to what the guest commits.
        bytes memory expectedPV = abi.encodePacked(
            bytes32(registry.networkId()), // [0..32] networkId as bytes32
            uint256(blockNumber), // [32..64] blockNumber as uint256
            stateRoot, // [64..96]
            validatorSetRoot // [96..128]
        );
        if (keccak256(publicValues) != keccak256(expectedPV)) revert PublicValuesMismatch();

        // Binding: the submitted validatorSetRoot must match the registry's current epoch.
        // This prevents a valid quorum proof over a stale/different set from finalizing.
        bytes32 registryRoot = registry.currentValidatorSetRoot();
        if (validatorSetRoot != registryRoot) {
            revert ValidatorSetRootMismatch(validatorSetRoot, registryRoot);
        }

        // SP1 proof verification — reverts if the proof is invalid.
        // The verifier checks the circuit's VKey, the committed public values, and the proof.
        sp1Verifier.verifyProof(vkey, publicValues, proofBytes);

        // Finalize
        _stateRoots[blockNumber] = stateRoot;
        emit HeaderFinalized(blockNumber, stateRoot, validatorSetRoot);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @notice The finalized state root for `blockNumber`, or bytes32(0) if not finalized.
    function finalizedStateRoot(uint256 blockNumber) external view returns (bytes32) {
        return _stateRoots[blockNumber];
    }
}
