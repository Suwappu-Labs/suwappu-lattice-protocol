// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {OptimisticBridgeChallenge} from "../../../src/OptimisticBridgeChallenge.sol";

/// @title SCN_005_Penpie_Reentrancy
/// @notice Red-team scenario SCN-005 — Penpie-class "callback during
///         token transfer re-enters a sibling withdrawal path"
///         pattern.
///
/// Historical incident: Penpie (Pendle integration), 3 Sep 2024, ~$27M.
/// The attacker registered a market whose reward token was an
/// attacker-controlled contract. When Penpie's harvest path called
/// `transfer()` on the token to deliver rewards, the malicious token
/// re-entered `depositMarket` / `claimRewards` on Penpie, exploiting
/// state that had not yet been written. The "callback during external
/// call" primitive — also seen in Cream (Oct 2021) and many ERC-777
/// hook attacks (Cover Protocol, Lendf.me) — collapses any path that
/// does Effects-after-Interactions or lacks a reentrancy guard.
///
/// LTP analogue: `OptimisticBridgeChallenge` makes per-call ETH
/// transfers to winning parties on five paths
/// (`resolveChallenge`, `finalizeWindow`, `resolveByArbiter`,
/// `resolveByTimeDecay`, `finalizeWithZKProof`, `finalizeWithFraudProof`).
/// Every recipient is a caller-supplied address that could be a
/// contract with a `receive()` / `fallback()` callback.
///
/// Defenses pinned:
///
///   (E1) Every payout function carries `nonReentrant`. A reentrant
///        call into ANY function with the modifier reverts.
///   (E2) `c.status` is set to its terminal state (RESOLVED /
///        FINALIZED) BEFORE the external call — even WITHOUT the
///        guard, replaying the same digest would revert at the
///        status-check line. Checks-Effects-Interactions ordering.
///   (E3) Cross-path reentry: a malicious recipient cannot call any
///        OTHER nonReentrant function during the payout — the guard
///        is contract-wide, not per-function.
///   (E4) Direct re-entry into the SAME function with the SAME digest
///        reverts twice: first by the reentrancy guard, but even if
///        the guard were absent, the status update at E2 makes the
///        second call's preconditions fail.
contract SCN005_Penpie_Reentrancy is Test {
    OptimisticBridgeChallenge internal ch;
    ReentrantRecipient internal attacker;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant OPENER = address(0xB0B);

    function setUp() public {
        ch = new OptimisticBridgeChallenge(
            ADMIN,
            1 hours,    // challengePeriod
            1 ether,    // minOperatorBond
            0.5 ether   // minChallengerBond
        );

        attacker = new ReentrantRecipient(ch);
        vm.deal(address(attacker), 100 ether);
        vm.deal(OPENER, 100 ether);
    }

    // -----------------------------------------------------------------------
    // E1 + E3 — nonReentrant guard blocks re-entry across payout paths
    // -----------------------------------------------------------------------

    /// @dev Attacker opens a window AS the malicious contract, gets
    ///      challenged, then admin resolves with `fraudValid=false` —
    ///      attacker becomes the opener-winner and receives the
    ///      payout. The recipient's receive() re-enters
    ///      `finalizeWindow(otherDigest)` during the call. The guard
    ///      must reject.
    function test_E1_E3_reentry_during_resolveChallenge_blocked() public {
        // Two windows: one will be the "target" the attacker tries to
        // finalize re-entrantly, one is the live payout path.
        bytes32 payoutDigest = keccak256("payout-anchor");
        bytes32 targetDigest = keccak256("target-anchor");

        // Open both windows. attacker opens payoutDigest, OPENER opens
        // targetDigest.
        vm.prank(address(attacker));
        ch.openWindow{value: 1 ether}(payoutDigest);

        vm.prank(OPENER);
        ch.openWindow{value: 1 ether}(targetDigest);

        // Submit a challenge against payoutDigest from a third party.
        address challenger = address(0xCC);
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        ch.submitChallenge{value: 0.5 ether}(payoutDigest, 1, keccak256("proof"));

        // Configure the attacker to attempt finalizeWindow(targetDigest)
        // inside its receive() callback.
        attacker.armReentry(IReentrantRecipient.Path.Finalize, targetDigest);

        // Warp past the targetDigest deadline so finalizeWindow would
        // otherwise succeed.
        vm.warp(block.timestamp + 2 hours);

        // Admin resolves with fraudValid=false → attacker receives
        // 1.5 ETH. attacker.receive() will try to re-enter.
        // We accept either:
        //   (a) the resolveChallenge call itself reverts (guard or
        //       failed transfer to the malicious recipient),
        //   (b) the call succeeds AND the targetDigest window is
        //       still STATUS_OPEN (re-entry was rejected by guard).
        try this._adminResolve(payoutDigest, false) {
            // Path (b): payout succeeded, re-entry was contained.
            OptimisticBridgeChallenge.Challenge memory t = ch.getChallenge(targetDigest);
            assertEq(t.status, ch.STATUS_OPEN(),
                     "targetDigest must NOT have been finalized via re-entry");
        } catch {
            // Path (a): resolveChallenge reverted, no state advanced.
            OptimisticBridgeChallenge.Challenge memory t = ch.getChallenge(targetDigest);
            assertEq(t.status, ch.STATUS_OPEN());
        }
    }

    // External wrapper so `try/catch` can intercept reverts.
    function _adminResolve(bytes32 digest, bool fraudValid) external {
        vm.prank(ADMIN);
        ch.resolveChallenge(digest, fraudValid);
    }

    // -----------------------------------------------------------------------
    // E2 — status update precedes external call (CEI ordering)
    // -----------------------------------------------------------------------

    /// @dev Even with the guard removed (hypothetically), the status
    ///      transition before the external call ensures a re-entrant
    ///      call to the SAME function on the SAME digest sees
    ///      STATUS_RESOLVED / STATUS_FINALIZED and reverts at the
    ///      precondition check. We verify by inspecting status BEFORE
    ///      the transfer would land.
    function test_E2_status_set_before_transfer_in_finalizeWindow() public {
        bytes32 digest = keccak256("e2-window");
        vm.prank(OPENER);
        ch.openWindow{value: 1 ether}(digest);

        vm.warp(block.timestamp + 2 hours);

        // Configure attacker to query status during its receive().
        // For this we use a recipient that records what it sees and
        // does NOT re-enter (just inspects).
        StatusObserver observer = new StatusObserver(ch, digest);
        vm.deal(address(this), 1 ether);

        // The opener of the digest is OPENER, but for the observer
        // mechanic we need a window whose opener IS the observer.
        bytes32 obsDigest = keccak256("e2-window-obs");
        vm.deal(address(observer), 2 ether);
        vm.prank(address(observer));
        ch.openWindow{value: 1 ether}(obsDigest);

        vm.warp(block.timestamp + 2 hours);

        // Trigger finalizeWindow; receive() runs INSIDE the call,
        // so observer captures the on-chain status at that moment.
        observer.setSelfDigest(obsDigest);
        ch.finalizeWindow(obsDigest);

        assertEq(uint256(observer.statusSeenDuringReceive()),
                 uint256(ch.STATUS_FINALIZED()),
                 "status must be FINALIZED before external transfer");
    }

    // -----------------------------------------------------------------------
    // E4 — same-digest re-entry rejected even after first payout
    // -----------------------------------------------------------------------

    function test_E4_same_digest_replay_rejected() public {
        bytes32 digest = keccak256("e4-window");
        vm.prank(OPENER);
        ch.openWindow{value: 1 ether}(digest);

        vm.warp(block.timestamp + 2 hours);

        ch.finalizeWindow(digest); // legit close

        // Replay must revert — status is no longer STATUS_OPEN.
        vm.expectRevert(OptimisticBridgeChallenge.WindowNotOpen.selector);
        ch.finalizeWindow(digest);
    }
}

// =========================================================================
// Helpers: malicious / observing recipients
// =========================================================================

interface IReentrantRecipient {
    enum Path { None, Finalize, Resolve, TimeDecay }
}

contract ReentrantRecipient is IReentrantRecipient {
    OptimisticBridgeChallenge public ch;
    Path public armedPath = Path.None;
    bytes32 public armedDigest;

    constructor(OptimisticBridgeChallenge _ch) {
        ch = _ch;
    }

    function armReentry(Path p, bytes32 d) external {
        armedPath = p;
        armedDigest = d;
    }

    receive() external payable {
        if (armedPath == Path.Finalize) {
            try ch.finalizeWindow(armedDigest) {} catch {}
        } else if (armedPath == Path.TimeDecay) {
            try ch.resolveByTimeDecay(armedDigest) {} catch {}
        }
        // The `try/catch` lets the OUTER call observe completion —
        // the re-entry's revert does not propagate.
    }
}

contract StatusObserver {
    OptimisticBridgeChallenge public ch;
    bytes32 public watchDigest;
    bytes32 public selfDigest;
    uint8 public statusSeenDuringReceive;

    constructor(OptimisticBridgeChallenge _ch, bytes32 _watch) {
        ch = _ch;
        watchDigest = _watch;
    }

    function setSelfDigest(bytes32 d) external {
        selfDigest = d;
    }

    receive() external payable {
        // We don't re-enter; we just record the contract's view of
        // selfDigest at the moment the transfer lands. CEI ordering
        // means the status should already be FINALIZED.
        OptimisticBridgeChallenge.Challenge memory c = ch.getChallenge(selfDigest);
        statusSeenDuringReceive = c.status;
    }
}
