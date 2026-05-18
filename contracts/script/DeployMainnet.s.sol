// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {LTPMultiSig} from "../src/LTPMultiSig.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployMainnet
/// @notice Production deployment — all governance parameters read from environment.
///
/// Required environment variables:
///   MULTISIG_OWNERS       — comma-separated owner addresses (e.g. "0xA,0xB,0xC")
///   MULTISIG_THRESHOLD    — required confirmations (e.g. 3)
///   TIMELOCK_DELAY        — seconds before timelocked ops execute (e.g. 86400 = 24h)
///   INITIAL_SIGNERS       — comma-separated VK hashes to register at deploy time (optional)
///
/// Architecture (same as testnet):
///   LTPMultiSig (proposer/executor/canceller)
///       ↓ schedule → wait → execute
///   TimelockController (admin of registry)
///       ↓
///   LTPAnchorRegistry (UUPS proxy)
contract DeployMainnet is Script {
    function run() external {
        // ---- Read governance parameters from environment ----
        uint256 timelockDelay = vm.envUint("TIMELOCK_DELAY");
        uint256 multisigThreshold = vm.envUint("MULTISIG_THRESHOLD");
        string memory ownersRaw = vm.envString("MULTISIG_OWNERS");

        // Parse comma-separated owner addresses
        address[] memory owners = _parseAddresses(ownersRaw);
        require(owners.length >= multisigThreshold, "threshold exceeds owner count");

        // LTP-A-002 / LTP-A-009 (docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md):
        // production-grade Byzantine threshold + 24-hour Timelock.
        //   - threshold >= ceil(N/2) + 1 prevents Ronin/Harmony-class
        //     single-key compromise from gaining quorum
        //   - timelock >= 24h gives honest governance a real reaction
        //     window for malicious upgrades (Cypher Protocol class)
        //   - reject deploy on known testnets unless ALLOW_TESTNET_DEPLOY=true
        uint256 minThreshold = (owners.length / 2) + 1;
        require(
            multisigThreshold >= minThreshold,
            "mainnet requires threshold >= ceil(N/2) + 1"
        );
        require(timelockDelay >= 24 hours, "mainnet requires timelock >= 24 hours");

        // LTP-A-001 (docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md): wide challenge
        // window. Mainnet floor is 24h so the OptimisticBridgeChallenge
        // gives honest challengers (and the symmetric ZK fraud-proof
        // path in finalizeWithFraudProof) a real detection window
        // before the operator can finalize. Recommended 48-72h.
        uint256 challengePeriod = vm.envOr("CHALLENGE_PERIOD", uint256(48 hours));
        require(
            challengePeriod >= 24 hours,
            "mainnet requires challengePeriod >= 24 hours"
        );

        uint256 chainId = block.chainid;
        bool allowTestnet = vm.envOr("ALLOW_TESTNET_DEPLOY", false);
        // 31337 = anvil, 84532 = Base Sepolia, 11155111 = Ethereum Sepolia,
        // 103115120 = GSX testnet. Add more as needed.
        bool isTestnet =
            chainId == 31337 ||
            chainId == 84532 ||
            chainId == 11155111 ||
            chainId == 103115120;
        require(
            !isTestnet || allowTestnet,
            "DeployMainnet refuses to deploy on a known testnet without ALLOW_TESTNET_DEPLOY=true"
        );

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
        string memory signersRaw = vm.envOr("INITIAL_SIGNERS", string(""));
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
        console.log("=== Mainnet Deployment ===");
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
        // Count commas to determine array size
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

    /// @dev Parse a single hex address string. Uses vm.parseAddress for Foundry scripts.
    function _parseAddress(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        // Trim leading/trailing whitespace
        uint256 start = 0;
        uint256 end = b.length;
        while (start < end && (b[start] == " " || b[start] == "\t")) start++;
        while (end > start && (b[end-1] == " " || b[end-1] == "\t")) end--;

        require(end - start == 42, "invalid address length");

        // Manual hex parsing (0x prefix + 40 hex chars)
        require(b[start] == "0" && (b[start+1] == "x" || b[start+1] == "X"), "missing 0x prefix");

        uint160 addr;
        for (uint256 i = start + 2; i < end; ++i) {
            uint8 c = uint8(b[i]);
            uint8 nibble;
            if (c >= 48 && c <= 57) nibble = c - 48;           // 0-9
            else if (c >= 65 && c <= 70) nibble = c - 55;      // A-F
            else if (c >= 97 && c <= 102) nibble = c - 87;     // a-f
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
