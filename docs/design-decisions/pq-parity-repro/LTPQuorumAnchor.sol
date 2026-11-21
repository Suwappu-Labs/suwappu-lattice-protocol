// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ZKNOX_dilithium65} from "./ZKNOX_dilithium65.sol";
import {SSTORE2} from "sstore2/SSTORE2.sol";

/// @title LTPQuorumAnchor (testnet prototype, unreviewed)
/// @notice Records a 32-byte state root once 7 of 9 registered ML-DSA-65 keys
///         have signed it. Keys are stored once as contract code so the
///         per-root transaction carries only signatures.
contract LTPQuorumAnchor {
    uint256 public constant N = 9;
    uint256 public constant T = 7;
    uint256 internal constant KEY_BYTES = 38112;
    uint256 internal constant SPLIT = 24000;

    ZKNOX_dilithium65 public immutable verifier;
    address public immutable admin;
    bool public sealedKeys;
    address[2][N] internal keyChunks;
    bytes32[N] public keyHash;
    mapping(bytes32 => uint256) public anchoredBitmap;

    event KeyRegistered(uint256 indexed index, bytes32 keyHash);
    event QuorumAnchored(bytes32 indexed root, uint256 bitmap, uint256 signers);

    error NotAdmin();
    error KeysSealed();
    error BadKey();
    error BadBitmap();
    error BelowThreshold();
    error BadSignature(uint256 signer);

    constructor(ZKNOX_dilithium65 v) {
        verifier = v;
        admin = msg.sender;
    }

    /// @dev The expanded key exceeds the 24,576-byte code limit, so it is
    ///      stored as two data contracts.
    function registerKey(uint256 i, bytes calldata blob) external {
        if (msg.sender != admin) revert NotAdmin();
        if (sealedKeys) revert KeysSealed();
        if (i >= N || blob.length != KEY_BYTES) revert BadKey();
        keyChunks[i][0] = SSTORE2.write(blob[:SPLIT]);
        keyChunks[i][1] = SSTORE2.write(blob[SPLIT:]);
        keyHash[i] = keccak256(blob);
        emit KeyRegistered(i, keyHash[i]);
    }

    function sealKeys() external {
        if (msg.sender != admin) revert NotAdmin();
        sealedKeys = true;
    }

    function _key(uint256 i) internal view returns (bytes memory) {
        return bytes.concat(SSTORE2.read(keyChunks[i][0]), SSTORE2.read(keyChunks[i][1]));
    }

    /// @param sigs one 3,309-byte ML-DSA-65 signature over `root` (empty
    ///        context) per set bit of `bitmap`, in ascending signer order.
    function anchorQuorum(bytes32 root, uint256 bitmap, bytes[] calldata sigs) external {
        if (bitmap >= (1 << N)) revert BadBitmap();
        bytes memory m = abi.encodePacked(root);
        uint256 used;
        for (uint256 i = 0; i < N; i++) {
            if (bitmap & (1 << i) == 0) continue;
            if (used >= sigs.length) revert BelowThreshold();
            if (!verifier.verify(_key(i), m, sigs[used], "")) revert BadSignature(i);
            used++;
        }
        if (used < T || used != sigs.length) revert BelowThreshold();
        anchoredBitmap[root] = bitmap;
        emit QuorumAnchored(root, bitmap, used);
    }
}
