// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {BridgeEmitter} from "../src/BridgeEmitter.sol";

/// @title DeployBridgeEmitter
/// @notice Deploys BridgeEmitter to Base Sepolia for gateway VM end-to-end testing.
///
/// Usage:
///   source .env
///   forge script script/DeployBridgeEmitter.s.sol:DeployBridgeEmitter \
///       --rpc-url "$BASE_SEPOLIA_RPC_URL" \
///       --private-key "$L2_DEPLOYER_KEY" \
///       --broadcast --chain-id 84532 -vvvv
contract DeployBridgeEmitter is Script {
    function run() external {
        // Deployer is admin by default; permissionless mode off so the
        // deployment is admin-gated until governance flips it on.
        address admin = msg.sender;
        bool permissionless = false;

        vm.startBroadcast();

        BridgeEmitter emitter = new BridgeEmitter(admin, permissionless);

        vm.stopBroadcast();

        console.log("=== BridgeEmitter Deployment ===");
        console.log("BridgeEmitter:", address(emitter));
        console.log("Admin:", admin);
        console.log("Permissionless:", permissionless);
        console.log("Chain ID:", block.chainid);
    }
}
