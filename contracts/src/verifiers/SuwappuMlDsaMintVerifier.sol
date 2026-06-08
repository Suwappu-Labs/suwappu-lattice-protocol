// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMintAttestationVerifier} from "../interfaces/IMintAttestationVerifier.sol";

/// @title SuwappuMlDsaMintVerifier
/// @notice POST-QUANTUM attestation verifier for the Suwappu DAG home chain.
///         Verifies an ML-DSA-65 (FIPS 204) operator signature over the mint
///         digest by calling the native ML-DSA verification precompile.
///
/// @dev This is the on-chain PQ wiring. The precompile at MLDSA_PRECOMPILE
///      implements `suwappu-mldsa-precompile::verify` (crate in suwappu-dag):
///      input  = pubkey(1952) || signature(3309) || message
///      output = 32-byte word, 1 iff the ML-DSA-65 signature is valid.
///      No SNARK wrapper, no scheme substitution — genuinely FIPS-204 sound
///      (contrast the SP1->Groth16/BN254 path, which is Shor-broken).
///
///      EVM destination chains cannot host this precompile affordably
///      (direct ML-DSA verify ~5-12M gas), so they use the ECDSA interim
///      verifier and inherit PQ transitively via a Suwappu DAG attestation —
///      see docs/security/audits/suwappu/P5b_ONCHAIN_PQ.md.
contract SuwappuMlDsaMintVerifier is IMintAttestationVerifier {
    /// @notice Native ML-DSA-65 verification precompile address on Suwappu DAG.
    address public constant MLDSA_PRECOMPILE = address(0x0101);

    /// @notice FIPS 204 ML-DSA-65 fixed sizes.
    uint256 public constant PK_LEN = 1952;
    uint256 public constant SIG_LEN = 3309;

    address public admin;
    address public pendingAdmin;

    /// @notice Authorized operators keyed by keccak256(ml-dsa pubkey).
    mapping(bytes32 => bool) public isOperatorKey;

    event OperatorKeySet(bytes32 indexed pubkeyHash, bool authorized);
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
    /// @dev attestation = abi.encode(bytes pubkey, bytes mldsaSig). The signed
    ///      message is the 32-byte `digest` itself.
    function verifyMintAttestation(bytes32 digest, bytes calldata attestation)
        external
        view
        override
        returns (bool)
    {
        (bytes memory pubkey, bytes memory sig) = abi.decode(attestation, (bytes, bytes));
        if (pubkey.length != PK_LEN || sig.length != SIG_LEN) return false;

        // Operator authorization (P3-1): the signing key must be authorized.
        if (!isOperatorKey[keccak256(pubkey)]) return false;

        // Precompile input: pubkey || sig || message(=digest).
        bytes memory input = abi.encodePacked(pubkey, sig, digest);
        (bool ok, bytes memory out) = MLDSA_PRECOMPILE.staticcall(input);
        // Reject if the precompile is absent/code-less or returned anything
        // other than a single word equal to 1 (mirrors the C4 fix discipline).
        if (!ok || out.length != 32) return false;
        return abi.decode(out, (uint256)) == 1;
    }

    // ---- governance ----
    function setOperatorKey(bytes32 pubkeyHash, bool authorized) external onlyAdmin {
        isOperatorKey[pubkeyHash] = authorized;
        emit OperatorKeySet(pubkeyHash, authorized);
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
