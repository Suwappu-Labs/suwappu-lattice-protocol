// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../lib/forge-std/src/Script.sol";
import {console} from "forge-std/Test.sol";
import {ZKNOX_dilithium65} from "../src/ZKNOX_dilithium65.sol";
import {LTPQuorumAnchor} from "../src/LTPQuorumAnchor.sol";

/// Deploys the Keccak helper, the ML-DSA-65 verifier and LTPQuorumAnchor,
/// registers nine LTP-generated keys, then anchors one root signed by seven
/// of them. Reads test/KAT/ltp65.json and test/KAT/f1600_170.hex.
contract DeployLTPQuorum is Script {
    function run() external {
        string memory j = vm.readFile("test/KAT/ltp65.json");
        bytes memory runtime = vm.parseBytes(vm.readFile("test/KAT/f1600_170.hex"));
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);

        vm.startBroadcast();
        address helper;
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "helper CREATE failed");
        require(
            helper.codehash == 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b,
            "unexpected helper code hash"
        );
        ZKNOX_dilithium65 v = new ZKNOX_dilithium65(helper);
        LTPQuorumAnchor q = new LTPQuorumAnchor(v);
        for (uint256 i = 0; i < 9; i++) {
            q.registerKey(i, vm.parseJsonBytes(j, string.concat(".blobs[", vm.toString(i), "]")));
        }
        q.sealKeys();

        bytes32 root = bytes32(vm.parseJsonBytes(j, ".root"));
        uint8[7] memory who = [0, 1, 3, 4, 5, 7, 8];
        bytes[] memory sigs = new bytes[](7);
        uint256 bitmap;
        for (uint256 n = 0; n < 7; n++) {
            sigs[n] = vm.parseJsonBytes(j, string.concat(".sigRoot[", vm.toString(who[n]), "]"));
            bitmap |= 1 << who[n];
        }
        q.anchorQuorum(root, bitmap, sigs);
        vm.stopBroadcast();

        console.log("helper:", helper);
        console.log("verifier:", address(v));
        console.log("anchor:", address(q));
        console.logBytes32(root);
        console.log("bitmap:", bitmap);
    }
}
