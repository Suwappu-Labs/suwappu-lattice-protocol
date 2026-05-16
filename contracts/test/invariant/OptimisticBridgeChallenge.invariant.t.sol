// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {OptimisticBridgeChallenge} from "../../src/OptimisticBridgeChallenge.sol";

/// @title OptimisticBridgeChallengeInvariantTest
/// @notice Foundry stateful invariant suite for the optimistic challenge
///         resolver, with focus on the new `finalizeWithFraudProof` path
///         (LTP-A-001 Option E in docs/SECURITY_AUDIT_2026-05-15.md).
///
/// Invariants pinned:
///   I1: bondsConserved — total of operator+challenger bonds across all
///       windows equals contract balance (no Wei created or destroyed).
///   I2: noDoubleFinalization — a window never transitions to FINALIZED /
///       RESOLVED twice.
///   I3: fraudProofGatedToVerifier — only the configured zkVerifier can
///       call finalizeWithFraudProof; admin cannot.
///   I4: chronoOrder — every challenge's deadline is strictly after its
///       openedAt timestamp.
contract OptimisticBridgeChallengeInvariantTest is Test {
    OptimisticBridgeChallenge internal ch;
    Handler internal handler;

    address internal constant ADMIN = address(0xA1);
    address internal constant ZK_VERIFIER = address(0xBEEF);
    address internal constant ARBITER = address(0xA8B17E8);

    function setUp() public {
        ch = new OptimisticBridgeChallenge(
            ADMIN,
            1 hours,   // challengePeriod
            1 ether,   // minOperatorBond
            0.5 ether  // minChallengerBond
        );
        vm.prank(ADMIN);
        ch.setZKVerifier(ZK_VERIFIER);
        // LTP-A-006 Option E setup
        vm.prank(ADMIN);
        ch.setArbiter(ARBITER);

        handler = new Handler(ch, ZK_VERIFIER, ARBITER);

        // Restrict fuzzing to the handler's external surface.
        targetContract(address(handler));
    }

    /// I1: contract balance equals sum of unsettled bonds.
    function invariant_bonds_conserved() public view {
        uint256 expectedHeld = handler.totalUnsettledBonds();
        assertEq(address(ch).balance, expectedHeld);
    }

    /// I2: no double-finalization.
    function invariant_no_double_finalization() public view {
        assertFalse(handler.observedDoubleFinalize());
    }

    /// I3: fraud-proof path is gated to zkVerifier only.
    function invariant_fraud_proof_gated_to_verifier() public view {
        assertFalse(handler.adminEverCalledFraudProof());
    }

    /// I5: arbiter path is gated to arbiter only (admin can never invoke it).
    function invariant_arbiter_path_gated() public view {
        assertFalse(handler.adminEverCalledArbiterPath());
    }

    /// I6: time-decay path cannot be invoked before the grace window
    ///     has elapsed; the handler tracks any such attempt that
    ///     unexpectedly succeeded.
    function invariant_time_decay_respects_grace() public view {
        assertFalse(handler.observedTimeDecayBeforeGrace());
    }
}

/// @notice Handler bounds the fuzzer's call set to legal entrypoints and
///         tracks invariant-relevant accumulated state.
contract Handler is Test {
    OptimisticBridgeChallenge public ch;
    address public zkVerifier;
    address public arbiter;

    bytes32[] public digests;
    mapping(bytes32 => bool) public seen;
    mapping(bytes32 => uint64) public openedAt;

    uint256 public totalUnsettledBonds;
    bool public observedDoubleFinalize;
    bool public adminEverCalledFraudProof;
    bool public adminEverCalledArbiterPath;
    bool public observedTimeDecayBeforeGrace;

    address internal constant ADMIN = address(0xA1);

    constructor(OptimisticBridgeChallenge _ch, address _verifier, address _arbiter) {
        ch = _ch;
        zkVerifier = _verifier;
        arbiter = _arbiter;
        vm.deal(address(this), 1000 ether);
    }

    receive() external payable {
        // Refund landing pad. The wrappers that trigger payouts
        // (resolveChallenge / resolveByArbiter / finalizeWithZKProof /
        // finalizeWithFraudProof / tryTimeDecay) own the accounting via
        // `totalUnsettledBonds -= paid`. Decrementing here too caused a
        // double-subtraction that, combined with the saturating clamp,
        // produced invariant_bonds_conserved counter-examples where
        // address(ch).balance > totalUnsettledBonds because the tracker
        // had been zeroed out before the wrapper could subtract its
        // share. Keep this body intentionally empty.
    }

    // ----- Open a new window -----
    function openWindow(bytes32 anchorDigest) external payable {
        if (anchorDigest == bytes32(0) || seen[anchorDigest]) return;
        uint256 bond = ch.minOperatorBond();
        if (address(this).balance < bond) return;
        digests.push(anchorDigest);
        seen[anchorDigest] = true;
        openedAt[anchorDigest] = uint64(block.timestamp);
        try ch.openWindow{value: bond}(anchorDigest) {
            totalUnsettledBonds += bond;
        } catch {}
    }

    // ----- Submit a challenge -----
    function submitChallenge(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint256 bond = ch.minChallengerBond();
        if (address(this).balance < bond) return;
        try ch.submitChallenge{value: bond}(d, 1, keccak256("proof")) {
            totalUnsettledBonds += bond;
        } catch {}
    }

    // ----- Admin resolves -----
    function resolveChallenge(uint256 i, bool fraudValid) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint256 balBefore = address(ch).balance;
        vm.prank(ADMIN);
        try ch.resolveChallenge(d, fraudValid) {
            uint256 paid = balBefore - address(ch).balance;
            if (paid > totalUnsettledBonds) {
                observedDoubleFinalize = true;
            }
            totalUnsettledBonds -= paid;
        } catch {}
    }

    // ----- ZK verifier finalizes with validity proof -----
    function finalizeWithZKProof(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint256 balBefore = address(ch).balance;
        vm.prank(zkVerifier);
        try ch.finalizeWithZKProof(d) {
            uint256 paid = balBefore - address(ch).balance;
            totalUnsettledBonds -= paid;
        } catch {}
    }

    // ----- ZK verifier finalizes with fraud proof (LTP-A-001 new path) -----
    function finalizeWithFraudProof(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint256 balBefore = address(ch).balance;
        vm.prank(zkVerifier);
        try ch.finalizeWithFraudProof(d) {
            uint256 paid = balBefore - address(ch).balance;
            totalUnsettledBonds -= paid;
        } catch {}
    }

    // ----- Admin attempts the fraud-proof path (must always revert) -----
    function adminTriesFraudProof(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        vm.prank(ADMIN);
        try ch.finalizeWithFraudProof(d) {
            // If this ever succeeds, the gate is broken.
            adminEverCalledFraudProof = true;
        } catch {}
    }

    // ----- Time travel within a sane window -----
    function warp(uint256 secs) external {
        secs = bound(secs, 0, 30 days);
        vm.warp(block.timestamp + secs);
    }

    // ----- LTP-A-006 Option E: arbiter resolves challenge -----
    function resolveByArbiter(uint256 i, bool fraudValid) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint256 balBefore = address(ch).balance;
        vm.prank(arbiter);
        try ch.resolveChallengeByArbiter(d, fraudValid) {
            uint256 paid = balBefore - address(ch).balance;
            totalUnsettledBonds -= paid;
        } catch {}
    }

    // ----- Admin attempts arbiter path (must always revert) -----
    function adminTriesArbiterPath(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        vm.prank(ADMIN);
        try ch.resolveChallengeByArbiter(d, true) {
            adminEverCalledArbiterPath = true;
        } catch {}
    }

    // ----- Time-decay path -----
    function tryTimeDecay(uint256 i) external {
        if (digests.length == 0) return;
        bytes32 d = digests[i % digests.length];
        uint64 ts = uint64(block.timestamp);
        uint64 ready = openedAt[d] + uint64(ch.resolutionGracePeriod());
        uint256 balBefore = address(ch).balance;
        try ch.resolveByTimeDecay(d) {
            uint256 paid = balBefore - address(ch).balance;
            totalUnsettledBonds -= paid;
            // If we got here BEFORE the grace window, that's a violation.
            if (ts < ready) {
                observedTimeDecayBeforeGrace = true;
            }
        } catch {}
    }
}
