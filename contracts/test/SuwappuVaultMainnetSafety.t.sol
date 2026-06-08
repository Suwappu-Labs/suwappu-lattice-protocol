// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuVault} from "../src/SuwappuVault.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";

/// @title SuwappuVault mainnet-safety regression tests (P9)
/// @notice Covers the three at-risk fixes from the fix-verification pass:
///   - C2 refund-liveness: an offline/censoring operator can freeze locked
///     principal; emergencyRefund (timelock rescuer) is the trustless backstop.
///   - P3-4 partial release: a commit larger than the daily release cap must not
///     become permanently un-unlockable.
///   - P3-4 leaky bucket: the release cap must not allow a ~2x burst across a
///     day boundary.
contract SuwappuVaultMainnetSafetyTest is Test {
    SuwappuVault vault;
    SuwappuEcdsaMintVerifier refundVerifier;

    address admin = makeAddr("admin");
    address relayer = makeAddr("relayer"); // unlocker
    address rescuer = makeAddr("rescuer"); // emergency rescuer (Timelock in prod)
    address alice = makeAddr("alice");
    address ETH = address(0);

    uint256 constant OPERATOR_PK = 0xA110CE;
    address operator;
    uint256 constant DEST = 8453;

    function setUp() public {
        vault = new SuwappuVault(admin, admin, 0); // feeBps = 0 → 1:1 amounts
        refundVerifier = new SuwappuEcdsaMintVerifier(admin);
        operator = vm.addr(OPERATOR_PK);

        vm.startPrank(admin);
        vault.addUnlocker(relayer);
        vault.setRefundVerifier(address(refundVerifier));
        vault.setEmergencyRescuer(rescuer);
        refundVerifier.setOperator(operator, true);
        vm.stopPrank();

        vm.deal(alice, 100 ether);
    }

    function _lock(uint256 amount) internal returns (bytes32 commitId) {
        vm.prank(alice);
        commitId = vault.lockETH{value: amount}(DEST, alice);
    }

    // -----------------------------------------------------------------------
    // C2 — emergency refund (trustless-exit backstop)
    // -----------------------------------------------------------------------

    function test_C2_EmergencyRefund_RescuesStuckCommit_NoAttestation() public {
        bytes32 id = _lock(1 ether);
        uint256 before = alice.balance;
        vm.warp(block.timestamp + vault.refundTimeout());

        // Operator is offline: a normal claimRefund cannot be authorized.
        vm.expectRevert(); // RefundNotAuthorized / verifier rejects empty attestation
        vault.claimRefund(id, "");

        // The timelock rescuer can refund without an operator attestation.
        vm.prank(rescuer);
        vault.emergencyRefund(id);

        assertEq(alice.balance, before + 1 ether, "principal returned to depositor");
        assertEq(uint8(vault.getCommit(id).status), uint8(SuwappuVault.LockStatus.REFUNDED));
        assertEq(vault.totalLocked(ETH), 0);
    }

    function test_C2_EmergencyRefund_OnlyRescuer() public {
        bytes32 id = _lock(1 ether);
        vm.warp(block.timestamp + vault.refundTimeout());
        vm.prank(admin); // even admin is not the rescuer
        vm.expectRevert(SuwappuVault.Unauthorized.selector);
        vault.emergencyRefund(id);
    }

    function test_C2_EmergencyRefund_RevertsBeforeTimeout() public {
        bytes32 id = _lock(1 ether);
        vm.prank(rescuer);
        vm.expectRevert();
        vault.emergencyRefund(id);
    }

    function test_C2_EmergencyRefund_RevertsIfNotLocked() public {
        bytes32 id = _lock(1 ether);
        vm.prank(relayer);
        vault.unlock(id, alice); // now UNLOCKED
        vm.warp(block.timestamp + vault.refundTimeout());
        vm.prank(rescuer);
        vm.expectRevert();
        vault.emergencyRefund(id);
    }

    // -----------------------------------------------------------------------
    // P3-4 — partial release (commit > daily release cap)
    // -----------------------------------------------------------------------

    function test_P3_4_FullUnlockReverts_PartialDrainsOverCap() public {
        vm.prank(admin);
        vault.setDailyReleaseCap(ETH, 0.4 ether);

        bytes32 id = _lock(1 ether); // single commit larger than the cap

        // Full unlock can't fit under the cap → would be permanently stuck
        // without unlockPartial.
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SuwappuVault.ReleaseCapExceeded.selector, ETH, 1 ether, 0.4 ether
            )
        );
        vault.unlock(id, alice);

        // Drain in tranches across days.
        vm.prank(relayer);
        vault.unlockPartial(id, alice, 0.4 ether);
        // Same day, bucket exhausted.
        vm.prank(relayer);
        vm.expectRevert();
        vault.unlockPartial(id, alice, 0.4 ether);

        vm.warp(block.timestamp + 1 days);
        vm.prank(relayer);
        vault.unlockPartial(id, alice, 0.4 ether);

        vm.warp(block.timestamp + 1 days);
        vm.prank(relayer);
        vault.unlockPartial(id, alice, 0.2 ether); // final tranche → fully released

        assertEq(vault.released(id), 1 ether);
        assertEq(uint8(vault.getCommit(id).status), uint8(SuwappuVault.LockStatus.UNLOCKED));
        assertEq(vault.totalLocked(ETH), 0);
    }

    function test_P3_4_RefundBlockedAfterPartialRelease() public {
        vm.prank(admin);
        vault.setDailyReleaseCap(ETH, 0.4 ether);
        bytes32 id = _lock(1 ether);

        vm.prank(relayer);
        vault.unlockPartial(id, alice, 0.4 ether);

        vm.warp(block.timestamp + vault.refundTimeout());
        // Neither refund path can double-spend a partially-released commit.
        vm.expectRevert(abi.encodeWithSelector(SuwappuVault.CommitPartiallyReleased.selector, id));
        vault.claimRefund(id, "");
        vm.prank(rescuer);
        vm.expectRevert(abi.encodeWithSelector(SuwappuVault.CommitPartiallyReleased.selector, id));
        vault.emergencyRefund(id);
    }

    function test_P3_4_UnlockPartial_ExceedsRemainingReverts() public {
        bytes32 id = _lock(1 ether);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuVault.ReleaseExceedsCommit.selector, id, 2 ether, 1 ether)
        );
        vault.unlockPartial(id, alice, 2 ether);
    }

    // -----------------------------------------------------------------------
    // P3-4 — leaky bucket (no day-boundary burst)
    // -----------------------------------------------------------------------

    function test_P3_4_LeakyBucket_RefillsLinearly_NoMidnightBurst() public {
        vm.prank(admin);
        vault.setDailyReleaseCap(ETH, 1 ether);

        bytes32 a = _lock(1 ether);
        vm.prank(relayer);
        vault.unlock(a, alice); // consumes the full daily cap

        assertEq(vault.dailyReleaseRemaining(ETH), 0, "bucket empty after full cap used");

        // Half a day later the bucket has refilled to ~50% of cap — NOT a full
        // reset (the old fixed-calendar-day bucket allowed a 2x burst here).
        vm.warp(block.timestamp + 12 hours);
        assertApproxEqAbs(vault.dailyReleaseRemaining(ETH), 0.5 ether, 1e12, "linear ~50% refill");

        bytes32 b = _lock(1 ether);
        vm.prank(relayer);
        vm.expectRevert(); // 0.6 > ~0.5 available
        vault.unlockPartial(b, alice, 0.6 ether);

        vm.prank(relayer);
        vault.unlockPartial(b, alice, 0.5 ether); // fits the refilled bucket
        assertEq(vault.released(b), 0.5 ether);
    }
}
