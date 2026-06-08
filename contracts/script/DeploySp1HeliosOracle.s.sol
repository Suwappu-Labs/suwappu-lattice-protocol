// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Sp1HeliosHeaderOracle, ISP1Helios} from "../src/verifiers/Sp1HeliosHeaderOracle.sol";
import {StorageProofSourceLockVerifier} from "../src/verifiers/StorageProofSourceLockVerifier.sol";
import {ISourceHeaderOracle} from "../src/interfaces/ISourceHeaderOracle.sol";

/// @notice P10 Phase C deploy: wires the EVM-source header trust root (a deployed
///         SP1 Helios ZK light client) into the bridge —
///         SP1Helios → Sp1HeliosHeaderOracle → StorageProofSourceLockVerifier.
///
///         The SP1Helios contract + its Succinct prover/relayer are deployed and
///         operated SEPARATELY (succinctlabs/sp1-helios); pass its address. This
///         script only stands up the consumer side. After it runs, governance
///         (the MintAdapter admin / Timelock) must:
///           adapter.setSourceVault(SOURCE_CHAIN_ID, SOURCE_VAULT)
///           adapter.setSourceLockVerifier(<printed verifier address>)
///         which flips mint() onto the proof path for that corridor.
///
///   Env: SP1HELIOS (deployed light client), SOURCE_CHAIN_ID (chain it tracks).
contract DeploySp1HeliosOracle is Script {
    function run()
        external
        returns (Sp1HeliosHeaderOracle oracle, StorageProofSourceLockVerifier verifier)
    {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address helios = vm.envAddress("SP1HELIOS");
        uint256 sourceChainId = vm.envUint("SOURCE_CHAIN_ID");

        vm.startBroadcast(pk);
        oracle = new Sp1HeliosHeaderOracle(ISP1Helios(helios), sourceChainId);
        verifier = new StorageProofSourceLockVerifier(ISourceHeaderOracle(address(oracle)));
        vm.stopBroadcast();

        console2.log("SP1Helios (external light client):", helios);
        console2.log("Sp1HeliosHeaderOracle:            ", address(oracle));
        console2.log("StorageProofSourceLockVerifier:   ", address(verifier));
        console2.log("source chain id:                  ", sourceChainId);
        console2.log("NEXT (governance/Timelock on the MintAdapter):");
        console2.log("  adapter.setSourceVault(sourceChainId, <source Vault address>)");
        console2.log("  adapter.setSourceLockVerifier(StorageProofSourceLockVerifier)");
    }
}
