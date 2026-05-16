// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_002_Nomad_InitBug.invariant
/// @notice Stateful invariant suite for SCN-002 (Nomad-class init-bug
///         pattern). See docs/security/campaigns/SCN-002-nomad-init-bug/.
///
/// Properties pinned across any reachable handler call sequence:
///
///   N1 (zero-digest-never-anchored):
///     `_anchors[bytes32(0)].anchoredAt` always equals 0. The sentinel
///     slot is never populated, regardless of how the handler exercises
///     anchor / register / pause.
///
///   N2 (no-zero-primary-input-accepted):
///     Every digest the handler observed as accepted has every primary
///     input (digest, entity, merkle, signer) strictly non-zero.
contract SCN002_Invariant is Test {
    LTPAnchorRegistry internal reg;
    SCN002_Handler internal handler;

    address internal constant ADMIN = address(0xA11CE);

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        handler = new SCN002_Handler(reg, ADMIN);
        targetContract(address(handler));
    }

    /// N1: zero-digest sentinel slot stays empty across the campaign.
    function invariant_zero_digest_never_anchored() public view {
        ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(bytes32(0));
        assertEq(uint256(rec.anchoredAt), 0);
    }

    /// N2: every accepted anchor has non-zero primary inputs.
    function invariant_no_zero_primary_input_accepted() public view {
        for (uint256 i = 0; i < handler.observedAnchorCount(); ++i) {
            bytes32 digest = handler.observedAnchors(i);
            ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(digest);
            assertTrue(digest != bytes32(0),       "digest is zero");
            assertTrue(rec.entityIdHash != bytes32(0), "entityIdHash is zero");
            assertTrue(rec.merkleRoot != bytes32(0),   "merkleRoot is zero");
            assertTrue(rec.signerVkHash != bytes32(0), "signerVkHash is zero");
        }
    }
}

/// @notice Handler bounds the fuzzer's call set to legal entrypoints,
///         and the `zero*` flags let it stress N1/N2 by attempting
///         zero-valued inputs on every call.
contract SCN002_Handler is Test {
    LTPAnchorRegistry public reg;
    address public immutable admin;

    bytes32[] public observedAnchors;
    mapping(bytes32 => bool) public seenAnchor;

    bytes32 internal constant SEED_VK = keccak256("scn002-seed-vk");

    constructor(LTPAnchorRegistry _reg, address _admin) {
        reg = _reg;
        admin = _admin;
        vm.prank(admin);
        try reg.registerSigner(SEED_VK) {} catch {}
    }

    function observedAnchorCount() external view returns (uint256) {
        return observedAnchors.length;
    }

    function registerSigner(bytes32 vkHash) external {
        vm.prank(admin);
        try reg.registerSigner(vkHash) {} catch {}
    }

    /// @dev Anchors with a controllable "force zero" toggle on each
    ///      primary input — the fuzzer can flip any of them to
    ///      bytes32(0) and the contract must still reject.
    function anchor(
        bool zeroDigest,
        bool zeroEntity,
        bool zeroRoot,
        bool zeroVk,
        bytes32 saltDigest,
        bytes32 saltEntity,
        bytes32 saltRoot,
        bytes32 saltVk,
        bytes32 policyHash,
        uint64  sequence,
        uint64  validUntilOffset,
        uint8   receiptType
    ) external {
        bytes32 digest = zeroDigest ? bytes32(0) : (saltDigest == bytes32(0) ? keccak256(abi.encode("d", saltDigest)) : saltDigest);
        bytes32 entity = zeroEntity ? bytes32(0) : (saltEntity == bytes32(0) ? keccak256(abi.encode("e", saltEntity)) : saltEntity);
        bytes32 root   = zeroRoot   ? bytes32(0) : (saltRoot   == bytes32(0) ? keccak256(abi.encode("r", saltRoot))   : saltRoot);
        bytes32 vk     = zeroVk     ? bytes32(0) : (saltVk     == bytes32(0) ? SEED_VK                                : saltVk);

        uint64 validUntil = uint64(block.timestamp) +
            uint64(bound(uint256(validUntilOffset), 1, 365 days));

        try reg.anchor(digest, entity, root, policyHash, vk, sequence, validUntil, receiptType) {
            if (!seenAnchor[digest]) {
                seenAnchor[digest] = true;
                observedAnchors.push(digest);
            }
        } catch {}
    }

    function pause() external {
        vm.prank(admin);
        try reg.pause() {} catch {}
    }

    function unpause() external {
        vm.prank(admin);
        try reg.unpause() {} catch {}
    }
}
