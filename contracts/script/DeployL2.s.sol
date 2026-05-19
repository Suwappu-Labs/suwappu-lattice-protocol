// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployL2
/// @notice L2 deployment (Base Sepolia / Base Mainnet) — mirrors DeployMainnet.s.sol
///         with L2_ env var prefix. Identical governance chain.
///
/// Required environment variables:
///   L2_MULTISIG_OWNERS       — comma-separated owner addresses
///   L2_MULTISIG_THRESHOLD    — required confirmations
///   L2_TIMELOCK_DELAY        — seconds before timelocked ops execute
///   L2_INITIAL_SIGNERS       — comma-separated VK hashes (optional)
///
/// Architecture:
///   LTPMultiSig (proposer/executor/canceller)
///       ↓ schedule → wait → execute
///   TimelockController (admin of registry)
///       ↓
///   LTPAnchorRegistry (UUPS proxy)
contract DeployL2 is Script {
    function run() external {
        // ---- Read governance parameters from environment ----
        uint256 timelockDelay = vm.envUint("L2_TIMELOCK_DELAY");
        uint256 multisigThreshold = vm.envUint("L2_MULTISIG_THRESHOLD");
        string memory ownersRaw = vm.envString("L2_MULTISIG_OWNERS");

        // Parse comma-separated owner addresses
        address[] memory owners = _parseAddresses(ownersRaw);
        require(owners.length >= multisigThreshold, "threshold exceeds owner count");
        require(multisigThreshold >= 2, "L2 deployment requires threshold >= 2");
        require(timelockDelay >= 60, "L2 deployment requires timelock >= 60 seconds");

        vm.startBroadcast();

        // 1. Deploy implementation
        LTPAnchorRegistry implementation = new LTPAnchorRegistry();

        // 2. Deploy proxy with msg.sender as initial admin (temporary)
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (msg.sender));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        LTPAnchorRegistry registry = LTPAnchorRegistry(address(proxy));

        // 3. Deploy multi-sig
        LTPMultiSig multisig = new LTPMultiSig(owners, multisigThreshold);

        // 4. Deploy TimelockController
        address[] memory proposers = new address[](1);
        proposers[0] = address(multisig);

        address[] memory executors = new address[](1);
        executors[0] = address(multisig);

        TimelockController timelock = new TimelockController(
            timelockDelay,
            proposers,
            executors,
            address(0) // no additional admin
        );

        // 5. Register initial signers (if any) before admin transfer
        string memory signersRaw = vm.envOr("L2_INITIAL_SIGNERS", string(""));
        if (bytes(signersRaw).length > 0) {
            bytes32[] memory signers = _parseBytes32(signersRaw);
            for (uint256 i = 0; i < signers.length; ++i) {
                registry.registerSigner(signers[i]);
            }
            console.log("Registered initial signers:", signers.length);
        }

        // 6. Transfer admin to timelock — irreversible without timelock governance
        registry.transferAdmin(address(timelock));

        vm.stopBroadcast();

        // ---- Deployment summary ----
        console.log("=== L2 Deployment ===");
        console.log("Implementation:", address(implementation));
        console.log("Proxy (registry):", address(proxy));
        console.log("MultiSig:", address(multisig));
        console.log("Timelock (admin):", address(timelock));
        console.log("Timelock delay:", timelockDelay, "seconds");
        console.log("MultiSig threshold:", multisigThreshold, "/", owners.length);
        console.log("Chain ID:", block.chainid);
    }

    /// @dev Parse comma-separated hex addresses. Reverts on malformed input.
    function _parseAddresses(string memory csv) internal pure returns (address[] memory) {
        bytes memory raw = bytes(csv);
        uint256 count = 1;
        for (uint256 i = 0; i < raw.length; ++i) {
            if (raw[i] == ",") count++;
        }

        address[] memory result = new address[](count);
        uint256 start = 0;
        uint256 idx = 0;

        for (uint256 i = 0; i <= raw.length; ++i) {
            if (i == raw.length || raw[i] == ",") {
                bytes memory segment = new bytes(i - start);
                for (uint256 j = start; j < i; ++j) {
                    segment[j - start] = raw[j];
                }
                result[idx] = _parseAddress(string(segment));
                idx++;
                start = i + 1;
            }
        }

        return result;
    }

    /// @dev Parse a single hex address string.
    function _parseAddress(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        uint256 start = 0;
        uint256 end = b.length;
        while (start < end && (b[start] == " " || b[start] == "\t")) start++;
        while (end > start && (b[end-1] == " " || b[end-1] == "\t")) end--;

        require(end - start == 42, "invalid address length");
        require(b[start] == "0" && (b[start+1] == "x" || b[start+1] == "X"), "missing 0x prefix");

        uint160 addr;
        for (uint256 i = start + 2; i < end; ++i) {
            uint8 c = uint8(b[i]);
            uint8 nibble;
            if (c >= 48 && c <= 57) nibble = c - 48;
            else if (c >= 65 && c <= 70) nibble = c - 55;
            else if (c >= 97 && c <= 102) nibble = c - 87;
            else revert("invalid hex char in address");
            addr = addr * 16 + nibble;
        }
        return address(addr);
    }

    /// @dev Parse comma-separated bytes32 hex values.
    function _parseBytes32(string memory csv) internal pure returns (bytes32[] memory) {
        bytes memory raw = bytes(csv);
        uint256 count = 1;
        for (uint256 i = 0; i < raw.length; ++i) {
            if (raw[i] == ",") count++;
        }

        bytes32[] memory result = new bytes32[](count);
        uint256 start = 0;
        uint256 idx = 0;

        for (uint256 i = 0; i <= raw.length; ++i) {
            if (i == raw.length || raw[i] == ",") {
                bytes memory segment = new bytes(i - start);
                for (uint256 j = start; j < i; ++j) {
                    segment[j - start] = raw[j];
                }
                result[idx] = _parseBytes32Single(string(segment));
                idx++;
                start = i + 1;
            }
        }

        return result;
    }

    /// @dev Parse a single bytes32 hex string (0x + 64 hex chars).
    function _parseBytes32Single(string memory s) internal pure returns (bytes32) {
        bytes memory b = bytes(s);
        uint256 start = 0;
        uint256 end = b.length;
        while (start < end && (b[start] == " " || b[start] == "\t")) start++;
        while (end > start && (b[end-1] == " " || b[end-1] == "\t")) end--;

        require(end - start == 66, "invalid bytes32 length");
        require(b[start] == "0" && (b[start+1] == "x" || b[start+1] == "X"), "missing 0x prefix");

        bytes32 result;
        for (uint256 i = start + 2; i < end; ++i) {
            uint8 c = uint8(b[i]);
            uint8 nibble;
            if (c >= 48 && c <= 57) nibble = c - 48;
            else if (c >= 65 && c <= 70) nibble = c - 55;
            else if (c >= 97 && c <= 102) nibble = c - 87;
            else revert("invalid hex char in bytes32");
            result = bytes32(uint256(result) * 16 + nibble);
        }
        return result;
    }
}
