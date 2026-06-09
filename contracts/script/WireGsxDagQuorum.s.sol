// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuThresholdMintVerifier} from "../src/verifiers/SuwappuThresholdMintVerifier.sol";
import {GsxDagValidatorRegistry} from "../src/verifiers/GsxDagValidatorRegistry.sol";
import {GsxDagQuorumHeaderOracle} from "../src/verifiers/GsxDagQuorumHeaderOracle.sol";

/// @title WireGsxDagQuorum
/// @notice Interim trust-min wiring for the Suwappu bridge's destination side.
///
///   This performs TWO independent, honestly-scoped steps:
///
///   (1) THRESHOLD SWAP (active, on the live mint path):
///       Replace the adapter's single-key ECDSA mint-attestation verifier with a
///       k-of-N SuwappuThresholdMintVerifier. This swaps ONE key for an operator
///       SET — still a TRUSTED operator quorum, just no longer a single point of
///       failure. It is NOT trustless and NOT a source-event proof.
///
///   (2) READY-BUT-UNFED quorum infrastructure (NOT on any path yet):
///       Deploy a GsxDagValidatorRegistry (bootstrapped at epoch 0 with a genesis
///       placeholder set) and a GsxDagQuorumHeaderOracle pointed at it. These are
///       a validator-quorum SIDE-ATTESTATION surface (sync-committee trust class:
///       honest >2/3 stake). They are UNFED: GSX-DAG validators do NOT yet sign
///       epoch transitions or header attestations (the source-side signing duty is
///       a separate repo/PR), and nothing here is wired into consensus or the mint
///       path. This is NOT a consensus light client and NOT end-to-end PQ.
///
///   DELIBERATELY NOT WIRED: StorageProofSourceLockVerifier. The GSX-DAG home
///   chain has no EVM/keccak-MPT state root, so a storage-proof source-lock
///   verifier is structurally unsupplied — wiring it would install a verifier that
///   can never receive a valid proof. adapter.sourceLockVerifier() stays address(0).
///
///   Usage:
///     PRIVATE_KEY=0x... ADAPTER=0x... forge script \
///       script/WireGsxDagQuorum.s.sol --rpc-url <DEST_RPC> --broadcast
contract WireGsxDagQuorum is Script {
    /// networkId binding the registry/oracle digests to this GSX-DAG network.
    /// Byte-identical to the Vector phase networkId
    /// 0xff431b3851ff00be6b5a4bd9b67e7d4118300693937865dfe75847dfd7cdd78a.
    uint256 internal constant NETWORK_ID = uint256(keccak256("suwappu-perf-7r"));

    /// The GSX-DAG source chain id the oracle serves (placeholder, UNFED).
    uint256 internal constant GSXDAG_CHAIN_ID = 7000;

    /// Initial k-of-N quorum size for the threshold verifier.
    uint256 internal constant THRESHOLD_K = 2;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address me = vm.addr(pk);
        SuwappuMintAdapter adapter = SuwappuMintAdapter(vm.envAddress("ADAPTER"));

        vm.startBroadcast(pk);
        (
            SuwappuThresholdMintVerifier threshold,
            GsxDagValidatorRegistry registry,
            GsxDagQuorumHeaderOracle oracle
        ) = _wire(adapter, me);
        vm.stopBroadcast();

        console2.log("ThresholdMintVerifier (k-of-N):", address(threshold));
        console2.log("adapter.verifier() now:        ", address(adapter.verifier()));
        console2.log("GsxDagValidatorRegistry:       ", address(registry));
        console2.log("GsxDagQuorumHeaderOracle:      ", address(oracle));
        console2.log("registry.networkId():");
        console2.logBytes32(bytes32(registry.networkId()));
        console2.log("sourceLockVerifier (must be 0):", address(adapter.sourceLockVerifier()));
    }

    /// @dev The deploy+wire body. Kept as an internal call (not a separate script
    ///      instance) so msg.sender for the onlyAdmin calls is the broadcaster in
    ///      `run()` and the test contract in the test — both of which are `admin`.
    /// @param adminAddr the admin/operator principal (broadcaster `me`, or the test).
    function _wire(SuwappuMintAdapter adapter, address adminAddr)
        internal
        returns (
            SuwappuThresholdMintVerifier threshold,
            GsxDagValidatorRegistry registry,
            GsxDagQuorumHeaderOracle oracle
        )
    {
        // (1) Deploy the k-of-N threshold verifier and REPLACE the adapter's
        //     single-key ECDSA verifier with it. One key -> an operator SET.
        threshold = new SuwappuThresholdMintVerifier(adminAddr, THRESHOLD_K);
        adapter.setVerifier(address(threshold));

        // (2) Deploy READY-BUT-UNFED quorum infrastructure. The registry is
        //     bootstrapped with a genesis placeholder set so epoch 0 is non-empty;
        //     UNFED means the validators do not SIGN anything yet (no epoch
        //     transition, no header attestation), not that the set is empty.
        registry = new GsxDagValidatorRegistry(adminAddr, NETWORK_ID);
        (bytes32[] memory pkHashes, uint256[] memory stakes) = _genesisPlaceholder();
        registry.bootstrapEpoch0(pkHashes, stakes);

        // Oracle points at the registry but is UNFED: no validator signs headers.
        oracle = new GsxDagQuorumHeaderOracle(registry, GSXDAG_CHAIN_ID);

        // NOTE: StorageProofSourceLockVerifier is intentionally NOT deployed or
        // wired here (structurally unsupplied — no EVM/keccak-MPT state root on the
        // GSX-DAG home chain). adapter.sourceLockVerifier() remains address(0).
    }

    /// @dev Genesis placeholder validator set — UNFED, validators do not sign yet.
    ///      Just enough to satisfy bootstrapEpoch0's non-empty / strictly-increasing
    ///      pkHash / non-zero-stake invariants. NOT a real GSX-DAG validator set.
    function _genesisPlaceholder()
        internal
        pure
        returns (bytes32[] memory pkHashes, uint256[] memory stakes)
    {
        pkHashes = new bytes32[](3);
        stakes = new uint256[](3);
        // strictly increasing pkHashes (sorted, distinct); each non-zero stake.
        pkHashes[0] = keccak256("gsxdag-genesis-placeholder-1");
        pkHashes[1] = keccak256("gsxdag-genesis-placeholder-2");
        pkHashes[2] = keccak256("gsxdag-genesis-placeholder-3");
        _sortAscending(pkHashes);
        stakes[0] = 1;
        stakes[1] = 1;
        stakes[2] = 1;
    }

    /// @dev Tiny ascending sort (n=3) so the placeholder pkHashes always satisfy
    ///      the registry's strictly-increasing requirement regardless of keccak.
    function _sortAscending(bytes32[] memory a) private pure {
        for (uint256 i = 0; i < a.length; i++) {
            for (uint256 j = i + 1; j < a.length; j++) {
                if (a[j] < a[i]) {
                    (a[i], a[j]) = (a[j], a[i]);
                }
            }
        }
    }
}
