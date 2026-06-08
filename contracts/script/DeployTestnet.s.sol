// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployTestnet
/// @notice SUWAPPU Testnet deployment — UUPS proxy + multi-sig + timelock admin.
///
/// Architecture:
///   LTPMultiSig (proposer/executor/canceller)
///       ↓ schedule → wait → execute
///   TimelockController (admin of registry)
///       ↓
///   LTPAnchorRegistry (UUPS proxy)
contract DeployTestnet is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy implementation
        LTPAnchorRegistry implementation = new LTPAnchorRegistry();

        // 2. Deploy proxy with msg.sender as initial admin
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (msg.sender));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        LTPAnchorRegistry registry = LTPAnchorRegistry(address(proxy));

        // 3. Deploy 2-of-2 multi-sig with both operator wallets
        address deployer = msg.sender;
        address operator = vm.envAddress("SUWAPPU_OPERATOR_ADDRESS");

        address[] memory owners = new address[](2);
        owners[0] = deployer;
        owners[1] = operator;
        LTPMultiSig multisig = new LTPMultiSig(owners, 2);

        // 4. Deploy TimelockController
        //    - Multi-sig is proposer, executor, and canceller
        //    - 60s delay for testnet (production: 24-48h)
        //    - No additional admin (self-administered via timelock proposals)
        uint256 timelockDelay = 60; // seconds

        address[] memory proposers = new address[](1);
        proposers[0] = address(multisig);

        address[] memory executors = new address[](1);
        executors[0] = address(multisig);

        TimelockController timelock = new TimelockController(
            timelockDelay,
            proposers,
            executors,
            address(0) // no additional admin — fully self-administered
        );

        // 5. Transfer registry admin to the timelock (not directly to multi-sig)
        registry.transferAdmin(address(timelock));

        vm.stopBroadcast();

        console.log("=== SUWAPPU Testnet Deployment (v3 - Timelock Governance) ===");
        console.log("Implementation:", address(implementation));
        console.log("Proxy (registry):", address(proxy));
        console.log("MultiSig:", address(multisig));
        console.log("Timelock (admin):", address(timelock));
        console.log("Timelock delay:", timelockDelay, "seconds");
        console.log("Owner 1 (deployer):", deployer);
        console.log("Owner 2 (operator):", operator);
        console.log("Chain ID:", block.chainid);
    }
}
