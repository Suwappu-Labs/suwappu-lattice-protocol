// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title L2ForkTest
/// @notice Fork test against Base Sepolia for real OP Stack behavior.
///         Skips automatically when BASE_SEPOLIA_RPC_URL is not set.
contract L2ForkTest is Test {
    // EIP-1967 implementation slot
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    LTPAnchorRegistry public registry;
    LTPMultiSig public multisig;
    TimelockController public timelock;
    address public proxyAddr;
    address public implAddr;

    address public owner1 = address(0xA1);
    address public owner2 = address(0xA2);
    bytes32 public signerVkHash = keccak256("test-signer-vk");

    bool private _skipped;

    function setUp() public {
        string memory rpcUrl = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            vm.skip(true);
            _skipped = true;
            return;
        }
        vm.createSelectFork(rpcUrl);

        // Deploy full governance stack on the fork
        LTPAnchorRegistry implementation = new LTPAnchorRegistry();
        implAddr = address(implementation);

        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (address(this)));
        ERC1967Proxy proxy = new ERC1967Proxy(implAddr, initData);
        proxyAddr = address(proxy);
        registry = LTPAnchorRegistry(proxyAddr);

        // MultiSig (2-of-2)
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;
        multisig = new LTPMultiSig(owners, 2);

        // Timelock
        address[] memory proposers = new address[](1);
        proposers[0] = address(multisig);
        address[] memory executors = new address[](1);
        executors[0] = address(multisig);

        timelock = new TimelockController(60, proposers, executors, address(0));

        // Register signer before admin transfer
        registry.registerSigner(signerVkHash);

        // Transfer admin to timelock
        registry.transferAdmin(address(timelock));
    }

    function test_anchor_happy_path() public {
        // Must anchor as timelock (the admin), but anchor() is not admin-only — anyone can call it
        // if signer is authorized. So we can call directly.
        bytes32 digest = keccak256("l2-anchor-1");
        bytes32 entityId = keccak256("l2-entity-1");
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.anchor(digest, entityId, keccak256("root"), keccak256("policy"), signerVkHash, 1, validUntil, 0);

        assertTrue(registry.isAnchored(digest));
        assertEq(registry.getEntityState(entityId), registry.STATE_ANCHORED());
    }

    function test_batch_anchor() public {
        bytes32[] memory digests = new bytes32[](3);
        bytes32[] memory entityIds = new bytes32[](3);
        bytes32[] memory roots = new bytes32[](3);
        bytes32[] memory policies = new bytes32[](3);
        bytes32[] memory signers = new bytes32[](3);
        uint64[] memory sequences = new uint64[](3);
        uint64[] memory validUntils = new uint64[](3);
        uint8[] memory receiptTypes = new uint8[](3);

        for (uint256 i = 0; i < 3; ++i) {
            digests[i] = keccak256(abi.encodePacked("l2-batch-digest-", i));
            entityIds[i] = keccak256(abi.encodePacked("l2-batch-entity-", i));
            roots[i] = keccak256(abi.encodePacked("l2-batch-root-", i));
            policies[i] = keccak256(abi.encodePacked("l2-batch-policy-", i));
            signers[i] = signerVkHash;
            sequences[i] = uint64(2 + i); // sequence after the single anchor in setUp
            validUntils[i] = uint64(block.timestamp + 3600);
            receiptTypes[i] = 0;
        }

        registry.batchAnchor(digests, entityIds, roots, policies, signers, sequences, validUntils, receiptTypes);

        bool[] memory anchored = registry.areAnchored(digests);
        for (uint256 i = 0; i < 3; ++i) {
            assertTrue(anchored[i]);
        }
    }

    function test_version_check() public view {
        uint256 ver = registry.version();
        assertEq(ver, 6);
    }

    function test_governance_path() public {
        // Verify admin is timelock
        assertEq(registry.admin(), address(timelock));

        // Schedule a pause via MultiSig → Timelock → Registry
        bytes memory pauseData = abi.encodeCall(registry.pause, ());
        bytes32 salt = keccak256("l2-pause-test");

        // Owner1 submits to multisig
        vm.prank(owner1);
        uint256 txIndex = multisig.submitTransaction(
            address(timelock),
            0,
            abi.encodeCall(timelock.schedule, (address(registry), 0, pauseData, bytes32(0), salt, 60))
        );

        // Owner2 confirms
        vm.prank(owner2);
        multisig.confirmTransaction(txIndex);

        // Execute multisig tx (schedules on timelock)
        vm.prank(owner1);
        multisig.executeTransaction(txIndex);

        // Warp past timelock delay
        vm.warp(block.timestamp + 61);

        // Execute on timelock
        vm.prank(address(multisig));
        timelock.execute(address(registry), 0, pauseData, bytes32(0), salt);

        assertTrue(registry.paused());
    }

    function test_entity_signer_binding() public {
        bytes32 digest = keccak256("l2-binding-test");
        bytes32 entityId = keccak256("l2-binding-entity");
        uint64 validUntil = uint64(block.timestamp + 3600);

        registry.anchor(digest, entityId, keccak256("root"), keccak256("policy"), signerVkHash, 1, validUntil, 0);

        assertEq(registry.entitySigners(entityId), signerVkHash);
    }

    function test_eip1967_slot() public view {
        bytes32 slotValue = vm.load(proxyAddr, IMPL_SLOT);
        address implFromSlot = address(uint160(uint256(slotValue)));
        assertEq(implFromSlot, implAddr);
    }
}
