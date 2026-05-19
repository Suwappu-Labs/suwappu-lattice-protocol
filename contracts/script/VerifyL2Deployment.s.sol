// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title VerifyL2Deployment
/// @notice Read-only verification script for L2 deployments.
///         Reads proxy/timelock/multisig/impl addresses from env, checks
///         version, admin, paused, threshold, EIP-1967 slot. Logs pass/fail.
///
/// Required environment variables:
///   L2_PROXY_ADDRESS    — UUPS proxy (registry) address
///   L2_TIMELOCK_ADDRESS — TimelockController address
///   L2_MULTISIG_ADDRESS — LTPMultiSig address
///   L2_IMPL_ADDRESS     — Expected implementation address
contract VerifyL2Deployment is Script {
    // EIP-1967 implementation slot: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function run() external view {
        address proxyAddr = vm.envAddress("L2_PROXY_ADDRESS");
        address timelockAddr = vm.envAddress("L2_TIMELOCK_ADDRESS");
        address payable multisigAddr = payable(vm.envAddress("L2_MULTISIG_ADDRESS"));
        address expectedImpl = vm.envAddress("L2_IMPL_ADDRESS");

        LTPAnchorRegistry registry = LTPAnchorRegistry(proxyAddr);
        LTPMultiSig multisig = LTPMultiSig(multisigAddr);

        uint256 passed = 0;
        uint256 failed = 0;

        // 1. Version check
        uint256 ver = registry.version();
        if (ver >= 1) {
            console.log("PASS: version() =", ver);
            passed++;
        } else {
            console.log("FAIL: version() =", ver, "(expected >= 1)");
            failed++;
        }

        // 2. Admin check — should be timelock
        address admin = registry.admin();
        if (admin == timelockAddr) {
            console.log("PASS: admin() = timelock");
            passed++;
        } else {
            console.log("FAIL: admin() =", admin, "(expected timelock)");
            failed++;
        }

        // 3. Paused check — should not be paused
        bool paused = registry.paused();
        if (!paused) {
            console.log("PASS: paused() = false");
            passed++;
        } else {
            console.log("FAIL: paused() = true (expected false)");
            failed++;
        }

        // 4. MultiSig threshold check
        uint256 threshold = multisig.threshold();
        if (threshold >= 2) {
            console.log("PASS: threshold() =", threshold);
            passed++;
        } else {
            console.log("FAIL: threshold() =", threshold, "(expected >= 2)");
            failed++;
        }

        // 5. EIP-1967 implementation slot
        bytes32 slotValue = vm.load(proxyAddr, IMPL_SLOT);
        address implFromSlot = address(uint160(uint256(slotValue)));
        if (implFromSlot == expectedImpl) {
            console.log("PASS: EIP-1967 impl slot matches expected");
            passed++;
        } else {
            console.log("FAIL: EIP-1967 impl slot mismatch");
            failed++;
        }

        // 6. Chain ID
        console.log("Chain ID:", block.chainid);

        // Summary
        console.log("========================================");
        console.log("Passed:", passed);
        console.log("Failed:", failed);
        if (failed > 0) {
            console.log("WARNING: Some checks failed!");
        }
    }
}
