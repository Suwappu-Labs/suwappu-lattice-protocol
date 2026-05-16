// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_001_Wormhole_AnchorRegistry.invariant
/// @notice Stateful invariant suite for SCN-001 (Wormhole-class
///         pattern). See
///         docs/security/campaigns/SCN-001-wormhole-signature-skip/.
///
/// Properties pinned across any reachable handler call sequence:
///
///   I1 (no-unauthorized-anchor):
///     For every accepted anchor digest the handler observed, the
///     `signerVkHash` was in `authorizedSigners` at the moment of write.
///
///   I2 (chain-id-stamp):
///     Every stored anchor has `targetChainId == block.chainid`. The
///     contract never stores a caller-supplied chain ID.
///
///   I3 (sequence-monotonicity):
///     For every signer, the on-chain `signerSequences[vk]` is
///     non-decreasing across the test campaign.
contract SCN001_Invariant is Test {
    LTPAnchorRegistry internal reg;
    SCN001_Handler internal handler;

    address internal constant ADMIN = address(0xA11CE);

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        handler = new SCN001_Handler(reg, ADMIN);
        targetContract(address(handler));
    }

    /// I1: every accepted anchor's signer was authorized at write-time.
    function invariant_no_unauthorized_anchor() public view {
        for (uint256 i = 0; i < handler.observedAnchorCount(); ++i) {
            bytes32 digest = handler.observedAnchors(i);
            LTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(digest);
            // At write-time the handler recorded the vk as authorized;
            // we mirror that into `handler.wasAuthorizedAtWrite`.
            assertTrue(
                handler.wasAuthorizedAtWrite(rec.signerVkHash),
                "anchor stored with vk never authorized"
            );
        }
    }

    /// I2: targetChainId on every stored anchor equals block.chainid.
    function invariant_chain_id_stamp() public view {
        for (uint256 i = 0; i < handler.observedAnchorCount(); ++i) {
            bytes32 digest = handler.observedAnchors(i);
            LTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(digest);
            assertEq(uint256(rec.targetChainId), block.chainid);
        }
    }

    /// I3: signer sequence HWM is monotonic across the campaign.
    function invariant_sequence_monotone() public view {
        for (uint256 i = 0; i < handler.observedSignerCount(); ++i) {
            bytes32 vk = handler.observedSigners(i);
            uint64 onChainHwm = reg.signerSequences(vk);
            uint64 observed = handler.lastSeenSequence(vk);
            assertGe(uint256(onChainHwm), uint256(observed));
        }
    }
}

/// @notice Handler bounds the fuzzer's call set to legal entrypoints
///         and tracks invariant-relevant accumulated state.
contract SCN001_Handler is Test {
    LTPAnchorRegistry public reg;
    address public immutable admin;

    bytes32[] public observedAnchors;
    mapping(bytes32 => bool) public seenAnchor;

    bytes32[] public observedSigners;
    mapping(bytes32 => bool) public seenSigner;
    mapping(bytes32 => bool) public wasAuthorizedAtWrite;
    mapping(bytes32 => uint64) public lastSeenSequence;

    constructor(LTPAnchorRegistry _reg, address _admin) {
        reg = _reg;
        admin = _admin;
    }

    function observedAnchorCount() external view returns (uint256) {
        return observedAnchors.length;
    }

    function observedSignerCount() external view returns (uint256) {
        return observedSigners.length;
    }

    // ----- Register a signer (admin only) -----
    function registerSigner(bytes32 vkHash) external {
        if (vkHash == bytes32(0)) return;
        vm.prank(admin);
        try reg.registerSigner(vkHash) {
            if (!seenSigner[vkHash]) {
                seenSigner[vkHash] = true;
                observedSigners.push(vkHash);
            }
        } catch {}
    }

    // ----- Revoke a signer (admin only) -----
    function revokeSigner(bytes32 vkHash) external {
        vm.prank(admin);
        try reg.revokeSigner(vkHash) {} catch {}
    }

    // ----- Anchor an entity -----
    function anchor(
        bytes32 digest,
        bytes32 entityId,
        bytes32 merkleRoot,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntilOffset,
        uint8   receiptType
    ) external {
        if (digest == bytes32(0)) return;
        if (entityId == bytes32(0)) return;
        if (merkleRoot == bytes32(0)) return;
        if (signerVkHash == bytes32(0)) return;

        // Bound the validUntil offset so the call doesn't trivially
        // expire before it executes.
        uint64 validUntil = uint64(block.timestamp) + uint64(bound(validUntilOffset, 1, 365 days));

        // Snapshot whether the signer is authorized BEFORE the call.
        bool authBefore = reg.authorizedSigners(signerVkHash);

        try reg.anchor(
            digest, entityId, merkleRoot, bytes32(0),
            signerVkHash, sequence, validUntil, receiptType
        ) {
            // Call succeeded → record invariant-relevant facts.
            if (!seenAnchor[digest]) {
                seenAnchor[digest] = true;
                observedAnchors.push(digest);
            }
            wasAuthorizedAtWrite[signerVkHash] = wasAuthorizedAtWrite[signerVkHash] || authBefore;
            if (sequence > lastSeenSequence[signerVkHash]) {
                lastSeenSequence[signerVkHash] = sequence;
            }
        } catch {}
    }

    // ----- Pause / unpause (admin only) -----
    function pause() external {
        vm.prank(admin);
        try reg.pause() {} catch {}
    }

    function unpause() external {
        vm.prank(admin);
        try reg.unpause() {} catch {}
    }

    // ----- Time warp within sane window -----
    function warp(uint256 secs) external {
        secs = bound(secs, 0, 30 days);
        vm.warp(block.timestamp + secs);
    }
}
