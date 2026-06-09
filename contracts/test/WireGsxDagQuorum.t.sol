// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WireGsxDagQuorum} from "../script/WireGsxDagQuorum.s.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuThresholdMintVerifier} from "../src/verifiers/SuwappuThresholdMintVerifier.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {GsxDagValidatorRegistry} from "../src/verifiers/GsxDagValidatorRegistry.sol";
import {GsxDagQuorumHeaderOracle} from "../src/verifiers/GsxDagQuorumHeaderOracle.sol";

/// @notice Asserts the WireGsxDagQuorum wiring: the threshold (k-of-N) swap on the
///         adapter's mint-attestation verifier, plus the READY-BUT-UNFED registry +
///         oracle.
///
///   HONEST TRUST MODEL: the threshold verifier replaces ONE key with a k-of-N
///   operator SET — still a TRUSTED quorum, not trustless and not a source-event
///   proof. The registry/oracle are a validator-quorum SIDE-ATTESTATION surface
///   (sync-committee trust class, honest >2/3 stake), and they are UNFED: GSX-DAG
///   validators do NOT sign epoch transitions or header attestations yet (the
///   source-side signing duty is a separate repo/PR), and nothing here is wired
///   into consensus or the mint path. So there is NO end-to-end / trustless flow to
///   test here — these are wiring invariants only.
///
///   The test inherits WireGsxDagQuorum so it can call the internal `_wire` body
///   directly with `address(this)` as admin. That preserves msg.sender for the
///   onlyAdmin calls (setVerifier / bootstrapEpoch0) — exactly as `run()` does
///   under vm.startBroadcast(broadcaster).
contract WireGsxDagQuorumTest is Test, WireGsxDagQuorum {
    /// Vector-phase networkId, as a byte-identical LITERAL (cross-phase guard —
    /// deliberately NOT a recompute of keccak256("suwappu-perf-7r"), so a
    /// fat-fingered domain string in the script cannot pass both sides).
    bytes32 internal constant EXPECTED_NETWORK_ID =
        0xff431b3851ff00be6b5a4bd9b67e7d4118300693937865dfe75847dfd7cdd78a;

    SuwappuMintAdapter adapter;
    SuwappuEcdsaMintVerifier singleKey;

    SuwappuThresholdMintVerifier threshold;
    GsxDagValidatorRegistry registry;
    GsxDagQuorumHeaderOracle oracle;

    function setUp() public {
        // Adapter with a non-zero placeholder wrapped token (the constructor only
        // null-checks it; the wiring-only test never calls it). admin = this test.
        adapter = new SuwappuMintAdapter(address(this), address(0xBEEF));

        // Start from the single-key ECDSA verifier, then let _wire REPLACE it.
        // This makes the "is NOT the single-key one" assertion load-bearing.
        singleKey = new SuwappuEcdsaMintVerifier(address(this));
        adapter.setVerifier(address(singleKey));
        assertEq(address(adapter.verifier()), address(singleKey), "precondition: single-key set");

        (threshold, registry, oracle) = _wire(adapter, address(this));
    }

    /// After wiring, the adapter's verifier is the deployed k-of-N threshold
    /// verifier, and it is NOT the single-key ECDSA verifier it replaced.
    function test_thresholdVerifierReplacesSingleKeyOnAdapter() public view {
        assertEq(
            address(adapter.verifier()),
            address(threshold),
            "adapter.verifier should be the threshold verifier"
        );
        assertTrue(
            address(adapter.verifier()) != address(singleKey),
            "adapter.verifier must NOT be the single-key ECDSA verifier"
        );
    }

    /// The threshold verifier is a real k-of-N set, not a single key.
    function test_thresholdVerifierIsKofN() public view {
        assertEq(threshold.threshold(), THRESHOLD_K, "k mismatch");
        assertGt(threshold.threshold(), 1, "k-of-N must require more than one signer");
    }

    /// The registry reports the expected (Vector-phase byte-identical) networkId.
    function test_registryReportsExpectedNetworkId() public view {
        assertEq(bytes32(registry.networkId()), EXPECTED_NETWORK_ID, "registry networkId mismatch");
    }

    /// The oracle references the deployed registry.
    function test_oracleReferencesRegistry() public view {
        assertEq(
            address(oracle.registry()), address(registry), "oracle.registry should be the registry"
        );
    }

    /// The registry is bootstrapped (epoch 0) but UNFED: no epoch transition has
    /// occurred (currentEpoch stays 0) because GSX-DAG validators do not sign yet.
    function test_registryUnfedAtEpoch0() public view {
        assertTrue(registry.bootstrapped(), "epoch 0 should be bootstrapped");
        assertEq(registry.currentEpoch(), 0, "UNFED: no validator-signed transition has happened");
    }

    /// StorageProofSourceLockVerifier was NOT wired: the source-lock verifier slot
    /// stays address(0), so mint() uses the (threshold) attestation path, never a
    /// structurally-unsupplied storage proof.
    function test_storageProofSourceLockVerifierNotWired() public view {
        assertEq(
            address(adapter.sourceLockVerifier()),
            address(0),
            "StorageProofSourceLockVerifier must NOT be wired (structurally unsupplied)"
        );
    }
}
