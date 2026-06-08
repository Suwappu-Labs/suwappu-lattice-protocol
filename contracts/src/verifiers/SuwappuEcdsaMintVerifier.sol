// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMintAttestationVerifier} from "../interfaces/IMintAttestationVerifier.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SuwappuEcdsaMintVerifier
/// @notice EVM-interim attestation verifier: an authorized operator's ECDSA
///         signature over the adapter's mint digest. Used on destination EVM
///         chains where on-chain ML-DSA verification is gas-prohibitive
///         (~5-12M gas — see docs/security/audits/suwappu/P5b_ONCHAIN_PQ.md).
///         The Suwappu DAG home chain uses SuwappuMlDsaMintVerifier (real PQ).
///
/// @dev Operator set is governance-managed (Timelock). The signature is over
///      the EIP-191 personal-sign hash of the digest, so off-chain operators
///      can produce it with a standard signer.
contract SuwappuEcdsaMintVerifier is IMintAttestationVerifier {
    using ECDSA for bytes32;

    address public admin;
    address public pendingAdmin;
    mapping(address => bool) public isOperator;

    event OperatorSet(address indexed operator, bool authorized);
    event AdminTransferStarted(address indexed current, address indexed pending);
    event AdminTransferCompleted(address indexed previous, address indexed next);

    error Unauthorized();
    error ZeroAddress();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    constructor(address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    /// @inheritdoc IMintAttestationVerifier
    function verifyMintAttestation(bytes32 digest, bytes calldata attestation)
        external
        view
        override
        returns (bool)
    {
        // attestation is a 65-byte ECDSA signature over the EIP-191 hash of digest.
        if (attestation.length != 65) return false;
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (address signer, ECDSA.RecoverError err,) = ethHash.tryRecover(attestation);
        if (err != ECDSA.RecoverError.NoError) return false;
        return isOperator[signer];
    }

    // ---- governance ----
    function setOperator(address operator, bool authorized) external onlyAdmin {
        if (operator == address(0)) revert ZeroAddress();
        isOperator[operator] = authorized;
        emit OperatorSet(operator, authorized);
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
