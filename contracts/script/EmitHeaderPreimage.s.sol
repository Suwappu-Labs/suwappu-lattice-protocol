// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

/// @notice Emits the EXACT abi.encodePacked preimage of the GSX-DAG header
///         attestation digest, for a canonical set of TEST scalars.
///
///         This mirrors the packing in
///         `GsxDagQuorumHeaderOracle.headerDigest` / `submitHeader`:
///           abi.encodePacked(
///             HEADER_DOMAIN,           // bytes32 = keccak256("SUWAPPU_GSXDAG_HEADER_V1")
///             registry.networkId(),    // uint256 (32 bytes)
///             address(this),           // 20 raw address bytes (here: oracleAddr)
///             blockNumber,             // uint256 (32 bytes)
///             stateRoot                // bytes32 (32 bytes)
///           )
///         Total = 32 + 32 + 20 + 32 + 32 = 148 bytes.
///
///         This script DELIBERATELY does NOT compute the BLAKE3 digest. The
///         0x0102 BLAKE3 precompile does not exist in a bare `forge` run, so any
///         on-chain blake3 here would return garbage. We only emit the preimage;
///         the Rust side computes the digest from the real `blake3` crate and
///         asserts byte-equality against the preimage logged here.
///
///         Usage:
///           forge script script/EmitHeaderPreimage.s.sol
contract EmitHeaderPreimage is Script {
    /// keccak256("SUWAPPU_GSXDAG_HEADER_V1") — must match the oracle constant.
    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1");

    function run() external pure {
        // Canonical TEST scalars (deterministic, no external state).
        uint256 networkId = uint256(keccak256("suwappu-perf-7r"));
        address oracleAddr = 0x00000000000000000000000000000000000000A1;
        uint256 blockNumber = 4242;
        bytes32 stateRoot = keccak256("suwappu-state-root-fixture");

        bytes memory preimage =
            abi.encodePacked(HEADER_DOMAIN, networkId, oracleAddr, blockNumber, stateRoot);

        console2.log("HEADER_DOMAIN:");
        console2.logBytes32(HEADER_DOMAIN);
        console2.log("networkId:");
        console2.logBytes32(bytes32(networkId));
        console2.log("oracleAddr:");
        console2.log(oracleAddr);
        console2.log("blockNumber:", blockNumber);
        console2.log("stateRoot:");
        console2.logBytes32(stateRoot);
        console2.log("preimage:");
        console2.logBytes(preimage);
        console2.log("preimage length:", preimage.length);
    }
}
