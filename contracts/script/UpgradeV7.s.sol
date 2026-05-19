// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title UpgradeV7 — testnet ceremony
/// @notice Deploys the v7 implementation and schedules a UUPS upgrade via
///         MultiSig → Timelock → Registry. Structurally identical to
///         UpgradeV6.s.sol — v7's other deltas (5-of-7 threshold floor,
///         24h timelock floor, ZKBridgeVerifier.lockProduction(),
///         BridgeEmitter allowlist) are either enforced in DeployMainnet
///         (mainnet-only) or live in source and need no on-chain action.
///
///         Run this script against the EXISTING testnet proxies to swap
///         the implementation behind them. The proxy storage layout is
///         preserved; v7 only adds new functionality (rotateSignerWithGrace,
///         additional events) without reordering existing slots — verify
///         this with the forge storage-layout dry-run test.
///
/// Targets in this script: GSX testnet (chain 103115120). For Base
/// Sepolia (chain 84532), copy + adjust the constants below — both
/// chains use the same v7 source.
///
/// Pre-flight (run before step1):
///   forge build --sizes                # confirm v7 fits 24576-byte limit
///   forge test --fork-url $GSX_RPC_URL \
///       --match-path contracts/test/deployment/UpgradeV7.dryrun.t.sol
///                                      # storage-layout + pause-modifier
///                                      # invariants verified against
///                                      # current on-chain state
///
/// Usage (4 steps, matches UpgradeV6 cadence):
///
///   Step 1 — Deploy v7 impl + submit schedule + execute (deployer key)
///     forge script script/UpgradeV7.s.sol --sig "step1()" \
///       --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_DEPLOYER_KEY
///
///   Step 2 — Operator confirms each txId returned by step1
///     forge script script/UpgradeV7.s.sol --sig "step2(uint256)" <txId> \
///       --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_OPERATOR_KEY
///
///   Step 3 — Execute the schedule call through the multisig
///     forge script script/UpgradeV7.s.sol --sig "step3(uint256)" <scheduleTxId> \
///       --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_DEPLOYER_KEY
///
///   Step 4 — Wait TIMELOCK_DELAY (60 s on testnet), then execute upgrade
///     forge script script/UpgradeV7.s.sol --sig "step4(uint256)" <executeTxId> \
///       --rpc-url $GSX_RPC_URL --broadcast --private-key $GSX_DEPLOYER_KEY
///
///   Post-flight — drill the emergency pause path (separate ceremony)
///     See docs/runbooks/v7-upgrade-testnet.md §"Pause rehearsal".
contract UpgradeV7 is Script {
    // GSX Testnet (chain 103115120) deployed addresses
    address constant PROXY = 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4;
    address payable constant MULTISIG = payable(0x0106A79e9236009a05742B3fB1e3B7a52F44373D);
    address constant TIMELOCK = 0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8;

    // Testnet timelock delay (60 s). v7 keeps this — the 24-hour floor is
    // mainnet-only, enforced by DeployMainnet.s.sol.
    uint256 constant TIMELOCK_DELAY = 60;

    /// @notice Step 1: Deploy v7 impl, submit schedule + execute txs via deployer
    function step1() external {
        vm.startBroadcast();

        // 1. Deploy new implementation
        LTPAnchorRegistry newImpl = new LTPAnchorRegistry();
        console.log("New v7 implementation:", address(newImpl));

        // 2. Build the upgrade calldata chain:
        //    registry.upgradeToAndCall(newImpl, "")
        bytes memory upgradeCall = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(newImpl), ""));

        //    timelock.schedule(registry, 0, upgradeCall, 0, 0, 60)
        bytes memory scheduleCall =
            abi.encodeCall(TimelockController.schedule, (PROXY, 0, upgradeCall, bytes32(0), bytes32(0), TIMELOCK_DELAY));

        // 3. Submit schedule call to multisig (auto-confirms for deployer)
        LTPMultiSig multisig = LTPMultiSig(MULTISIG);
        uint256 scheduleTxId = multisig.submitTransaction(TIMELOCK, 0, scheduleCall);
        console.log("Schedule txId:", scheduleTxId);

        // 4. Also submit the execute call (for later)
        bytes memory executeCall =
            abi.encodeCall(TimelockController.execute, (PROXY, 0, upgradeCall, bytes32(0), bytes32(0)));
        uint256 executeTxId = multisig.submitTransaction(TIMELOCK, 0, executeCall);
        console.log("Execute txId:", executeTxId);

        vm.stopBroadcast();

        console.log("");
        console.log("=== Step 1 Complete ===");
        console.log("Next: Run step2 with OPERATOR key to confirm both txIds");
    }

    /// @notice Step 2: Operator confirms a multisig transaction
    function step2(uint256 txId) external {
        vm.startBroadcast();
        LTPMultiSig(MULTISIG).confirmTransaction(txId);
        vm.stopBroadcast();
        console.log("Confirmed txId:", txId);
    }

    /// @notice Step 3: Execute the schedule call through multisig → timelock
    function step3(uint256 scheduleTxId) external {
        vm.startBroadcast();

        LTPMultiSig multisig = LTPMultiSig(MULTISIG);
        multisig.executeTransaction(scheduleTxId);
        console.log("Schedule executed (txId:", scheduleTxId, ")");
        console.log("Timelock delay started. Wait 60 seconds...");

        vm.stopBroadcast();

        console.log("");
        console.log("=== Step 3 Complete ===");
        console.log("After 60s, run step4 to execute the upgrade");
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
