// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Sp1HeliosHeaderOracle, ISP1Helios} from "../src/verifiers/Sp1HeliosHeaderOracle.sol";

interface ISP1HeliosHead {
    function head() external view returns (uint256);
}

/// @notice P10 Phase C — LIVE integration: forks BNB Chain (which hosts an Across
///         V4 SP1Helios ZK light client) and proves Sp1HeliosHeaderOracle surfaces
///         a REAL execution state root that the light client proved from Ethereum
///         consensus. The SP1 prover is the external Succinct network; this test
///         validates the on-chain CONSUMER side against genuine proven output.
///         Self-skips when no BSC RPC is configured (set BSC_RPC_URL).
contract Sp1HeliosForkTest is Test {
    // Across V4 SP1Helios on BNB Smart Chain (chainId 56). Tracks Ethereum (1).
    address internal constant BNB_SP1HELIOS = 0x19256DCEa4B63c56B3EFc8708cd62F595B2d1922;
    uint256 internal constant ETH_SOURCE_CHAIN = 1;

    function test_LiveSp1Helios_AdapterSurfacesProvenRoot() public {
        // pin the fork for determinism; skip cleanly if no RPC endpoint is set
        try vm.createSelectFork("bsc") {}
        catch {
            vm.skip(true);
            return;
        }
        if (BNB_SP1HELIOS.code.length == 0) {
            vm.skip(true);
            return;
        }

        ISP1Helios helios = ISP1Helios(BNB_SP1HELIOS);
        uint256 head = ISP1HeliosHead(BNB_SP1HELIOS).head();
        bytes32 provenRoot = helios.executionStateRoots(head);
        // the latest finalized slot must carry a non-zero proven execution root
        assertTrue(provenRoot != bytes32(0), "live SP1Helios has a proven root at head");

        Sp1HeliosHeaderOracle oracle = new Sp1HeliosHeaderOracle(helios, ETH_SOURCE_CHAIN);

        // the adapter faithfully surfaces the light-client-proven root...
        assertEq(
            oracle.headerStateRoot(ETH_SOURCE_CHAIN, head),
            provenRoot,
            "adapter must surface the live proven execution state root"
        );
        // ...and returns 0 for the wrong source chain (no silent cross-chain reuse)
        assertEq(oracle.headerStateRoot(ETH_SOURCE_CHAIN + 1, head), bytes32(0));

        emit log_named_uint("SP1Helios head slot", head);
        emit log_named_bytes32("proven execution stateRoot", provenRoot);
    }
}
