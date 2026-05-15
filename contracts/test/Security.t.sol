// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BridgeEmitter} from "../src/BridgeEmitter.sol";
import {OptimisticBridgeChallenge} from "../src/OptimisticBridgeChallenge.sol";
import {ZKBridgeVerifier} from "../src/ZKBridgeVerifier.sol";

/// @title Security.t.sol
/// @notice Forge regression tests for the Solidity-layer hardening fixes in
///         docs/SECURITY_AUDIT_2026-05-15.md (LTP-A-006, LTP-A-007,
///         LTP-A-017, LTP-A-029).
contract SecurityTest is Test {
    address admin = address(0xA11CE);
    address bob = address(0xB0B);

    // -----------------------------------------------------------------------
    // LTP-A-017: BridgeEmitter authorized-senders gate
    // -----------------------------------------------------------------------

    function test_bridgeemitter_permissionless_mode_emits() public {
        BridgeEmitter be = new BridgeEmitter(address(0), true);
        vm.prank(bob);
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
        assertEq(be.nextNonce(), 1);
    }

    function test_bridgeemitter_gated_mode_rejects_unauthorized() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeEmitter.NotAuthorized.selector, bob)
        );
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
    }

    function test_bridgeemitter_gated_mode_accepts_authorized() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(admin);
        be.setAuthorized(bob, true);
        vm.prank(bob);
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
        assertEq(be.nextNonce(), 1);
    }

    function test_bridgeemitter_setauthorized_admin_only() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeEmitter.NotAdmin.selector, bob)
        );
        be.setAuthorized(bob, true);
    }

    // -----------------------------------------------------------------------
    // LTP-A-007: ZKBridgeVerifier production-mode locks out MODE_SIMULATED
    // -----------------------------------------------------------------------

    function test_zkverifier_lock_production_requires_admin() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 1); // MODE_SP1
        vm.prank(bob);
        vm.expectRevert(ZKBridgeVerifier.Unauthorized.selector);
        zk.lockProduction();
    }

    function test_zkverifier_lock_production_rejects_when_mode_is_simulated() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 0); // MODE_SIMULATED
        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.SimulatedModeNotAllowedInProduction.selector);
        zk.lockProduction();
    }

    function test_zkverifier_lock_production_locks_and_blocks_switch_back() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 1); // MODE_SP1
        vm.prank(admin);
        zk.lockProduction();
        assertTrue(zk.productionMode());

        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.SimulatedModeNotAllowedInProduction.selector);
        zk.setVerificationMode(0); // MODE_SIMULATED
    }

    // -----------------------------------------------------------------------
    // LTP-A-006: OptimisticBridgeChallenge already supports permissionless
    //            finalizeWindow for unchallenged windows after deadline.
    //            This test pins that behavior so a future "admin-only"
    //            refactor surfaces as a regression.
    // -----------------------------------------------------------------------

    function test_anyone_can_finalize_unchallenged_window() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        bytes32 digest = keccak256("test-anchor");
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);
        // Fast-forward past the challenge deadline.
        vm.warp(block.timestamp + 2 hours);
        // A third party (not the opener, not the admin) finalizes.
        address eve = address(0xEEEE);
        vm.deal(eve, 1 ether);
        vm.prank(eve);
        ch.finalizeWindow(digest);
        assertTrue(ch.isFinalized(digest));
    }

    // -----------------------------------------------------------------------
    // LTP-A-001 Option E: symmetric ZK fraud-proof finalization
    // -----------------------------------------------------------------------

    address constant ZK_VERIFIER = address(0xBEEFCAFE);

    function _openChallenge(uint256 opBond, uint256 chBond)
        internal
        returns (OptimisticBridgeChallenge ch, bytes32 digest)
    {
        ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        ch.setZKVerifier(ZK_VERIFIER);
        digest = keccak256("contested-anchor");

        // Operator opens window.
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: opBond}(digest);

        // Challenger submits.
        address alice = address(0xA11CE);
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        ch.submitChallenge{value: chBond}(digest, 1, keccak256("proof"));
    }

    function test_fraud_proof_finalize_pays_challenger() public {
        uint256 opBond = 1 ether;
        uint256 chBond = 0.5 ether;
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(opBond, chBond);
        address alice = address(0xA11CE);

        uint256 aliceBefore = alice.balance;
        vm.prank(ZK_VERIFIER);
        ch.finalizeWithFraudProof(digest);

        // Challenger receives operator + challenger bonds.
        assertEq(alice.balance - aliceBefore, opBond + chBond);
    }

    function test_fraud_proof_admin_cannot_call() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(1 ether, 0.5 ether);
        vm.prank(admin);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.finalizeWithFraudProof(digest);
    }

    function test_fraud_proof_rejects_unchallenged_window() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        ch.setZKVerifier(ZK_VERIFIER);
        bytes32 digest = keccak256("untouched");

        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);

        // No challenge filed; fraud-proof path must reject.
        vm.prank(ZK_VERIFIER);
        vm.expectRevert(OptimisticBridgeChallenge.WindowNotChallenged.selector);
        ch.finalizeWithFraudProof(digest);
    }

    function test_fraud_proof_arbitrary_caller_rejected() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(1 ether, 0.5 ether);
        vm.prank(address(0xDEAD));
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.finalizeWithFraudProof(digest);
    }
}
