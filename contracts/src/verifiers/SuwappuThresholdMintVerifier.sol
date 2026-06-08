// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMintAttestationVerifier} from "../interfaces/IMintAttestationVerifier.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SuwappuThresholdMintVerifier
/// @notice k-of-N ECDSA threshold attestation verifier — the bridge's new
///         trust root. A mint (or refund) is authorized only when at least
///         `threshold` (K) DISTINCT authorized operators each sign the bound
///         digest. This removes the single-operator failure mode of
///         SuwappuEcdsaMintVerifier: compromising one key no longer mints.
///
/// @dev Drop-in for IMintAttestationVerifier — callers only use
///      verifyMintAttestation(bytes32,bytes). The operator set and threshold
///      are governance-managed (Timelock in production) with the same two-step
///      admin handoff as the sibling verifiers.
///
///      Attestation encoding: abi.encode(bytes[] sigs), where each element is a
///      65-byte ECDSA signature over MessageHashUtils.toEthSignedMessageHash
///      (digest). Signatures MUST be ordered by STRICTLY INCREASING signer
///      address — this simultaneously de-duplicates signers and bounds the
///      verification gas (single pass, no membership set in memory).
///
///      Malformed input NEVER reverts the caller: a bad outer encoding returns
///      false via the self-staticcall try/catch (ML-DSA verifier parity), and a
///      bad inner element (wrong length / unrecoverable / out of order) returns
///      false inside the loop.
contract SuwappuThresholdMintVerifier is IMintAttestationVerifier {
    using ECDSA for bytes32;

    address public admin;
    address public pendingAdmin;

    /// @notice Authorized operator set.
    mapping(address => bool) public isOperator;

    /// @notice Number of authorized operators (N). Kept exact by setOperator.
    uint256 public operatorCount;

    /// @notice Quorum size (K): minimum DISTINCT authorized signatures required.
    uint256 public threshold;

    event OperatorSet(address indexed operator, bool authorized);
    event ThresholdSet(uint256 oldThreshold, uint256 newThreshold);
    event AdminTransferStarted(address indexed current, address indexed pending);
    event AdminTransferCompleted(address indexed previous, address indexed next);

    error Unauthorized();
    error ZeroAddress();
    /// @param threshold_     The threshold that would be left dangling.
    /// @param operatorCount_ The operator count it cannot exceed / drop below.
    error InvalidThreshold(uint256 threshold_, uint256 operatorCount_);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    /// @param admin_     Initial admin (Gnosis Safe / Timelock).
    /// @param threshold_ Initial quorum size K. Must be non-zero. Operators are
    ///                   added afterwards via setOperator; the K <= N invariant
    ///                   is enforced by setOperator/setThreshold from then on.
    constructor(address admin_, uint256 threshold_) {
        if (admin_ == address(0)) revert ZeroAddress();
        if (threshold_ == 0) revert InvalidThreshold(threshold_, operatorCount);
        admin = admin_;
        threshold = threshold_;
    }

    /// @inheritdoc IMintAttestationVerifier
    /// @dev attestation = abi.encode(bytes[] sigs). Each sig is a 65-byte ECDSA
    ///      signature over the EIP-191 hash of digest. Signers must appear in
    ///      strictly increasing address order.
    function verifyMintAttestation(bytes32 digest, bytes calldata attestation)
        external
        view
        override
        returns (bool)
    {
        uint256 k = threshold;
        if (k == 0) return false;

        // Decode defensively: a malformed/truncated encoding returns false for
        // parity with the ECDSA/ML-DSA verifiers, rather than reverting the
        // caller's tx.
        (bool decoded, bytes[] memory sigs) = _tryDecode(attestation);
        if (!decoded) return false;
        if (sigs.length < k) return false;

        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);

        address last = address(0);
        uint256 count = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            bytes memory sig = sigs[i];
            if (sig.length != 65) return false;

            (address signer, ECDSA.RecoverError err,) = ethHash.tryRecover(sig);
            if (err != ECDSA.RecoverError.NoError) return false;

            // Strictly increasing signer order: rejects duplicates and any
            // unordered element, and bounds gas to a single pass.
            if (signer <= last) return false;
            last = signer;

            if (isOperator[signer]) {
                count++;
                if (count >= k) return true;
            }
        }
        return count >= k;
    }

    /// @dev abi.decode reverts on malformed input; wrap it in an external
    ///      try/catch (self-staticcall, safe in a view) so the verifier returns
    ///      false instead of reverting. `this.decodeAttestation` is external pure.
    function _tryDecode(bytes calldata attestation)
        private
        view
        returns (bool ok, bytes[] memory sigs)
    {
        try this.decodeAttestation(attestation) returns (bytes[] memory s) {
            return (true, s);
        } catch {
            return (false, new bytes[](0));
        }
    }

    /// @dev External so it can be try/caught. Pure: only decodes calldata.
    function decodeAttestation(bytes calldata attestation)
        external
        pure
        returns (bytes[] memory sigs)
    {
        return abi.decode(attestation, (bytes[]));
    }

    // ---- governance ----

    /// @notice Add or remove an authorized operator. Idempotent: a no-op when
    ///         the operator is already in the requested state (operatorCount is
    ///         unchanged). Removing an operator that would drop operatorCount
    ///         below the current threshold REVERTS (fail-closed): governance must
    ///         lower the threshold first.
    function setOperator(address operator, bool authorized) external onlyAdmin {
        if (operator == address(0)) revert ZeroAddress();
        bool current = isOperator[operator];
        if (current == authorized) return; // idempotent no-op, count exact

        if (authorized) {
            isOperator[operator] = true;
            operatorCount += 1;
        } else {
            // Fail-closed: never let the operator set shrink below the quorum.
            if (operatorCount - 1 < threshold) {
                revert InvalidThreshold(threshold, operatorCount - 1);
            }
            isOperator[operator] = false;
            operatorCount -= 1;
        }
        emit OperatorSet(operator, authorized);
    }

    /// @notice Set the quorum size K. Must be non-zero and not exceed the
    ///         current operator count N.
    function setThreshold(uint256 newThreshold) external onlyAdmin {
        if (newThreshold == 0 || newThreshold > operatorCount) {
            revert InvalidThreshold(newThreshold, operatorCount);
        }
        emit ThresholdSet(threshold, newThreshold);
        threshold = newThreshold;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert Unauthorized();
        emit AdminTransferCompleted(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }
}
