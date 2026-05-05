// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BridgeEmitter
/// @notice Minimal contract that emits bridge events for gateway VM testing.
///         Deployed on the source chain (Base Sepolia) so the gateway can
///         detect, validate, attest, and anchor events to GSX devnet.
/// @dev    Event fields match the gateway's BridgeEvent dataclass:
///         sender, recipient, payloadHash, amount, nonce.
contract BridgeEmitter {
    event BridgeTransfer(
        address indexed sender,
        address indexed recipient,
        string payloadHash,
        uint256 amount,
        uint256 nonce
    );

    uint256 public nextNonce;

    /// @notice Emit a bridge transfer event for gateway testing.
    /// @param recipient  Destination address on the target chain.
    /// @param payloadHash  Algo-prefixed hash (e.g. "sha3:0xabc...").
    /// @param amount  Transfer amount in wei.
    function emitBridgeTransfer(
        address recipient,
        string calldata payloadHash,
        uint256 amount
    ) external {
        uint256 nonce = nextNonce++;
        emit BridgeTransfer(msg.sender, recipient, payloadHash, amount, nonce);
    }
}
