// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {OptimisticBridgeChallenge} from "../../../src/OptimisticBridgeChallenge.sol";

/// @title SCN_017_LayerZero_DVN
/// @notice Red-team scenario SCN-017 — LayerZero DVN-class
///         "verifier-set governance downgrade" pattern.
///
/// Historical pattern: in early 2024, the LayerZero community
/// debated whether stargate integrators could be reduced to a single
/// DVN (Decentralized Verifier Network entity) for cost / UX
/// reasons. The structural risk is "any path that lets an operator
/// silently reduce the independent-verifier count is a path that
/// degrades the trust model." No specific exploit shipped (the
/// debate was prospective), but the class is shared with several
/// real incidents where a verifier-set governance path proved too
/// permissive.
///
/// LTP analogue: `OptimisticBridgeChallenge` (LTP-A-006 Option E)
/// uses THREE independent resolution paths to defend against
/// single-key compromise of the admin OR the arbiter:
///
///   Path A: resolveChallenge — admin-only
///   Path B: resolveChallengeByArbiter — arbiter-only
///   Path C: resolveByTimeDecay — anyone, after grace period
///
/// The defenses pinned in this scenario:
///
///   (D1) `setArbiter` rejects setting arbiter == admin
///        (the InvalidArbiter check enforces verifier separation).
///   (D2) `setArbiter` is `onlyAdmin`.
///   (D3) `setZKVerifier` is `onlyAdmin`.
///   (D4) `setResolutionGracePeriod` enforces a 24h floor
///        (GracePeriodBelowFloor) — operator cannot silently
///        shrink the time-decay path to a no-op.
///   (D5) `resolveChallengeByArbiter` is gated to arbiter — admin
///        cannot call it (path-separation enforcement).
///   (D6) `resolveByTimeDecay` requires the grace period to have
///        elapsed (ResolutionGraceNotElapsed).
contract SCN017_LayerZero_DVN is Test {
    OptimisticBridgeChallenge internal ch;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ARBITER = address(0xA8B17E8);
    address internal constant ZK_VERIFIER = address(0xBEEF);
    address internal constant ATTACKER = address(0xBADC0DE);

    function setUp() public {
        ch = new OptimisticBridgeChallenge(
            ADMIN,
            1 hours,
            1 ether,
            0.5 ether
        );
        vm.prank(ADMIN);
        ch.setArbiter(ARBITER);
        vm.prank(ADMIN);
        ch.setZKVerifier(ZK_VERIFIER);
    }

    // -----------------------------------------------------------------------
    // D1 — arbiter cannot equal admin (verifier separation enforced)
    // -----------------------------------------------------------------------

    function test_D1_setArbiter_rejects_admin_as_arbiter() public {
        vm.prank(ADMIN);
        vm.expectRevert(OptimisticBridgeChallenge.InvalidArbiter.selector);
        ch.setArbiter(ADMIN);
    }

    function test_D1_setArbiter_rejects_admin_after_arbiter_change() public {
        // Try to first set a legit arbiter, then re-set to admin —
        // still rejected.
        vm.prank(ADMIN);
        ch.setArbiter(address(0xC0FFEE));
        vm.prank(ADMIN);
        vm.expectRevert(OptimisticBridgeChallenge.InvalidArbiter.selector);
        ch.setArbiter(ADMIN);
    }

    // -----------------------------------------------------------------------
    // D2 — setArbiter is onlyAdmin
    // -----------------------------------------------------------------------

    function test_D2_non_admin_cannot_setArbiter() public {
        vm.prank(ATTACKER);
        vm.expectRevert(); // onlyAdmin
        ch.setArbiter(ATTACKER);
    }

    // -----------------------------------------------------------------------
    // D3 — setZKVerifier is onlyAdmin
    // -----------------------------------------------------------------------

    function test_D3_non_admin_cannot_setZKVerifier() public {
        vm.prank(ATTACKER);
        vm.expectRevert(); // onlyAdmin
        ch.setZKVerifier(ATTACKER);
    }

    // -----------------------------------------------------------------------
    // D4 — setResolutionGracePeriod enforces 24h floor
    // -----------------------------------------------------------------------

    function test_D4_setResolutionGracePeriod_rejects_below_floor() public {
        vm.prank(ADMIN);
        vm.expectPartialRevert(
            OptimisticBridgeChallenge.GracePeriodBelowFloor.selector
        );
        ch.setResolutionGracePeriod(23 hours);
    }

    function test_D4_setResolutionGracePeriod_accepts_at_floor() public {
        vm.prank(ADMIN);
        ch.setResolutionGracePeriod(24 hours);
        assertEq(ch.resolutionGracePeriod(), 24 hours);
    }

    function test_D4_setResolutionGracePeriod_non_admin_rejected() public {
        vm.prank(ATTACKER);
        vm.expectRevert(); // onlyAdmin
        ch.setResolutionGracePeriod(7 days);
    }

    // -----------------------------------------------------------------------
    // D5 — resolveChallengeByArbiter is gated to arbiter (not admin)
    // -----------------------------------------------------------------------

    function test_D5_admin_cannot_call_arbiter_path() public {
        bytes32 digest = keccak256("d5-digest");
        vm.deal(address(this), 5 ether);
        ch.openWindow{value: 1 ether}(digest);

        address challenger = address(0xCC);
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));

        vm.prank(ADMIN);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.resolveChallengeByArbiter(digest, true);
    }

    function test_D5_attacker_cannot_call_arbiter_path() public {
        bytes32 digest = keccak256("d5-attacker-digest");
        vm.deal(address(this), 5 ether);
        ch.openWindow{value: 1 ether}(digest);

        address challenger = address(0xCC);
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));

        vm.prank(ATTACKER);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.resolveChallengeByArbiter(digest, true);
    }

    // -----------------------------------------------------------------------
    // D6 — resolveByTimeDecay requires grace period elapsed
    // -----------------------------------------------------------------------

    function test_D6_time_decay_before_grace_reverts() public {
        bytes32 digest = keccak256("d6-digest");
        vm.deal(address(this), 5 ether);
        ch.openWindow{value: 1 ether}(digest);

        address challenger = address(0xCC);
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));

        // BEFORE grace elapses (default 14d).
        vm.warp(block.timestamp + 13 days);
        vm.expectPartialRevert(
            OptimisticBridgeChallenge.ResolutionGraceNotElapsed.selector
        );
        ch.resolveByTimeDecay(digest);
    }

    function test_D6_time_decay_after_grace_succeeds() public {
        bytes32 digest = keccak256("d6-after-digest");
        vm.deal(address(this), 5 ether);
        ch.openWindow{value: 1 ether}(digest);

        address challenger = address(0xCC);
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));

        vm.warp(block.timestamp + 15 days);
        // Anyone can call.
        ch.resolveByTimeDecay(digest);
    }
}
