// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title UpgradeV4
/// @notice Deploys new v4 implementation and schedules UUPS upgrade via
///         MultiSig → Timelock → Registry governance chain.
///
/// Usage (3 steps):
///   Step 1: Deploy new impl + schedule upgrade
///     forge script script/UpgradeV4.s.sol --sig "step1()" \
///       --rpc-url $SUWAPPU_RPC_URL --broadcast --private-key $SUWAPPU_DEPLOYER_KEY
///
///   Step 2: Second signer confirms (run with operator key)
///     forge script script/UpgradeV4.s.sol --sig "step2(uint256)" <txId> \
///       --rpc-url $SUWAPPU_RPC_URL --broadcast --private-key $SUWAPPU_OPERATOR_KEY
///
///   Step 3: Wait 60s, then execute upgrade
///     forge script script/UpgradeV4.s.sol --sig "step3(uint256,uint256)" <scheduleTxId> <executeTxId> \
///       --rpc-url $SUWAPPU_RPC_URL --broadcast --private-key $SUWAPPU_DEPLOYER_KEY
contract UpgradeV4 is Script {
    // Existing deployed addresses (from .env)
    address constant PROXY    = 0x6042e3083743568dac44B9eB4C31639540d238B3;
    address payable constant MULTISIG = payable(0x06332c17439d4a8aAf5cb721E136D3827C7949e8);
    address constant TIMELOCK = 0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0;

    uint256 constant TIMELOCK_DELAY = 60;

    /// @notice Step 1: Deploy v4 impl, submit schedule+confirm via deployer
    function step1() external {
        vm.startBroadcast();

        // 1. Deploy new implementation
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();
        console.log("New v4 implementation:", address(newImpl));

        // 2. Build the upgrade calldata chain:
        //    registry.upgradeToAndCall(newImpl, "")
        bytes memory upgradeCall = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall, (address(newImpl), "")
        );

        //    timelock.schedule(registry, 0, upgradeCall, 0, 0, 60)
        bytes memory scheduleCall = abi.encodeCall(
            TimelockController.schedule,
            (PROXY, 0, upgradeCall, bytes32(0), bytes32(0), TIMELOCK_DELAY)
        );

        // 3. Submit schedule call to multisig (auto-confirms for deployer)
        LTPMultiSig multisig = LTPMultiSig(MULTISIG);
        uint256 scheduleTxId = multisig.submitTransaction(TIMELOCK, 0, scheduleCall);
        console.log("Schedule txId:", scheduleTxId);

        // 4. Also submit the execute call (for later)
        bytes memory executeCall = abi.encodeCall(
            TimelockController.execute,
            (PROXY, 0, upgradeCall, bytes32(0), bytes32(0))
        );
        uint256 executeTxId = multisig.submitTransaction(TIMELOCK, 0, executeCall);
        console.log("Execute txId:", executeTxId);

        vm.stopBroadcast();

        console.log("");
        console.log("=== Step 1 Complete ===");
        console.log("Next: Run step2 with OPERATOR key to confirm both txIds:");
        console.log("  step2_confirm(scheduleTxId) then step2_confirm(executeTxId)");
    }

    /// @notice Step 2: Operator confirms a multisig transaction
    function step2(uint256 txId) external {
        vm.startBroadcast();
        LTPMultiSig(MULTISIG).confirmTransaction(txId);
        vm.stopBroadcast();
        console.log("Confirmed txId:", txId);
    }

    /// @notice Step 3: Execute schedule, wait, then execute upgrade
    function step3(uint256 scheduleTxId, uint256 executeTxId) external {
        vm.startBroadcast();

        LTPMultiSig multisig = LTPMultiSig(MULTISIG);

        // Execute the schedule call through multisig → timelock
        multisig.executeTransaction(scheduleTxId);
        console.log("Schedule executed (txId:", scheduleTxId, ")");
        console.log("Timelock delay started. Wait 60 seconds...");

        vm.stopBroadcast();

        console.log("");
        console.log("=== Step 3a Complete ===");
        console.log("After 60s, run step4 to execute the upgrade:");
        console.log("  step4(executeTxId)");
    }

    /// @notice Step 4: Execute the upgrade after timelock delay
    function step4(uint256 executeTxId) external {
        vm.startBroadcast();

        LTPMultiSig multisig = LTPMultiSig(MULTISIG);
        multisig.executeTransaction(executeTxId);

        // Verify
        LTPAnchorRegistry registry = LTPAnchorRegistry(PROXY);
        uint256 ver = registry.version();
        console.log("=== Upgrade Complete ===");
        console.log("Registry version:", ver);
        console.log("Proxy:", PROXY);

        vm.stopBroadcast();
    }
}
