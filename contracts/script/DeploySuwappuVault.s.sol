// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SuwappuVault} from "../src/SuwappuVault.sol";

/// @notice Deploys a standalone SuwappuVault for the native-ETH lock demo.
///         No LTPMultiSig dependency (deprecated, C6) — admin is the deployer
///         EOA for the testnet demo. feeBps = 0 so a locked amount maps 1:1.
///
///         Usage:
///           PRIVATE_KEY=0x... forge script script/DeploySuwappuVault.s.sol \
///             --rpc-url https://sepolia.base.org --broadcast
contract DeploySuwappuVault is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);
        SuwappuVault vault = new SuwappuVault(deployer, deployer, 0);
        vm.stopBroadcast();

        console2.log("SuwappuVault deployed:", address(vault));
        console2.log("admin / feeRecipient:", deployer);
        console2.log("feeBps:", uint256(0));
    }
}
