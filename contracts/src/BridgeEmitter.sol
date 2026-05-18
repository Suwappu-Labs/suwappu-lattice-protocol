// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BridgeEmitter
/// @notice Minimal contract that emits bridge events for gateway VM testing.
///         Deployed on the source chain (Base Sepolia) so the gateway can
///         detect, validate, attest, and anchor events to GSX devnet.
/// @dev    Event fields match the gateway's BridgeEvent dataclass:
///         sender, recipient, payloadHash, amount, nonce.
///
///         LTP-A-017 (docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md): the v6
///         contract gates `emitBridgeTransfer` behind an admin-managed
///         allowlist so an arbitrary EOA can't spoof bridge-transfer
///         events that downstream indexers consume. Existing v5/v6
///         deployments stay permissionless; future deployments (v7+)
///         should pass a real admin and call `setAuthorized` for each
///         legitimate sender.
contract BridgeEmitter {
    event BridgeTransfer(
        address indexed sender,
        address indexed recipient,
        string payloadHash,
        uint256 amount,
        uint256 nonce
    );

    event AuthorizedSenderUpdated(address indexed sender, bool allowed);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error NotAuthorized(address sender);
    error NotAdmin(address caller);
    error ZeroAdmin();

    address public admin;
    mapping(address => bool) public authorizedSenders;
    bool public immutable permissionless;

    uint256 public nextNonce;

    /// @notice Construct with an admin and a permissionless flag.
    /// @dev    Pass `permissionless_=true` to preserve the existing v5/v6
    ///         "anyone can emit" semantics. Production v7+ deployments
    ///         should set it to false and call `setAuthorized` for each
    ///         legitimate caller.
    constructor(address admin_, bool permissionless_) {
        if (admin_ == address(0) && !permissionless_) revert ZeroAdmin();
        admin = admin_;
        permissionless = permissionless_;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    /// @notice Emit a bridge transfer event for gateway testing.
    /// @param recipient  Destination address on the target chain.
    /// @param payloadHash  Algo-prefixed hash (e.g. "sha3:0xabc...").
    /// @param amount  Transfer amount in wei.
    function emitBridgeTransfer(
        address recipient,
        string calldata payloadHash,
        uint256 amount
    ) external {
        if (!permissionless && !authorizedSenders[msg.sender]) {
            revert NotAuthorized(msg.sender);
        }
        uint256 nonce = nextNonce++;
        emit BridgeTransfer(msg.sender, recipient, payloadHash, amount, nonce);
    }

    /// @notice Allow or revoke a sender. Admin only. No-op in permissionless mode.
    function setAuthorized(address sender, bool allowed) external onlyAdmin {
        authorizedSenders[sender] = allowed;
        emit AuthorizedSenderUpdated(sender, allowed);
    }

    /// @notice Transfer admin to a new address. Admin only.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0) && !permissionless) revert ZeroAdmin();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }
}
