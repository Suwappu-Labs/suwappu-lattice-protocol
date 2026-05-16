// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPMultiSig} from "../../../src/LTPMultiSig.sol";

/// @title SCN_004_Orbit_MultisigSubversion
/// @notice Red-team scenario SCN-004 — Orbit Chain-class "multisig
///         threshold subverted via N-of-M with M-effective less than
///         advertised" pattern.
///
/// Historical incident: Orbit Bridge, 1 Jan 2024, ~$82M. The bridge
/// ran a 7-of-10 validator multisig; reports indicate that a subset
/// of signing keys were compromised AND a validator's signature was
/// forged using stored data. Effective threshold collapsed and the
/// attacker drained the bridge. Maps to LTP-A-002 / LTP-A-008.
///
/// LTP analogue: `LTPMultiSig` (contracts/src/LTPMultiSig.sol) is the
/// governance multisig that controls the upgrade and admin paths to
/// LTPAnchorRegistry. The Orbit-equivalent claim is "no transaction
/// executes unless `confirmations >= threshold`, and that threshold
/// cannot be reduced except by a multisig-confirmed `changeThreshold`
/// call."
///
///   (M1) `executeTransaction` reverts with InsufficientConfirmations
///        when fewer than `threshold` owners have confirmed.
///   (M2) A non-owner cannot submit, confirm, revoke, or execute.
///   (M3) `addOwner`, `removeOwner`, `changeThreshold` are
///        `onlySelf` — callable only via the multisig itself; an
///        owner cannot unilaterally lower the threshold.
///   (M4) Constructor rejects `threshold == 0` or `threshold > owners`.
///   (M5) An owner cannot double-confirm a transaction (each
///        confirmation counts once).
///   (M6) `revokeConfirmation` reduces the confirmation count;
///        re-attempting `executeTransaction` after revocation reverts.
contract SCN004_Orbit_MultisigSubversion is Test {
    LTPMultiSig internal ms;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB   = address(0xB0B);
    address internal constant CAROL = address(0xCA601);
    address internal constant ATTACKER = address(0xBADC0DE);

    function setUp() public {
        address[] memory owners = new address[](3);
        owners[0] = ALICE; owners[1] = BOB; owners[2] = CAROL;
        ms = new LTPMultiSig(owners, 2); // 2-of-3
    }

    // -----------------------------------------------------------------------
    // M1 — sub-threshold execution rejected
    // -----------------------------------------------------------------------

    function test_M1_execute_below_threshold_reverts() public {
        uint256 txId = _submit(ALICE);

        // Only one confirmation (the implicit one from submit by ALICE).
        // Try to execute with confirmations=1 < threshold=2.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2
        ));
        ms.executeTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // M2 — non-owner rejected from every owner-gated entrypoint
    // -----------------------------------------------------------------------

    function test_M2_non_owner_cannot_submit() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, ATTACKER));
        ms.submitTransaction(address(0xDEAD), 0, "");
    }

    function test_M2_non_owner_cannot_confirm() public {
        uint256 txId = _submit(ALICE);
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, ATTACKER));
        ms.confirmTransaction(txId);
    }

    function test_M2_non_owner_cannot_revoke() public {
        uint256 txId = _submit(ALICE);
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, ATTACKER));
        ms.revokeConfirmation(txId);
    }

    function test_M2_non_owner_cannot_execute() public {
        uint256 txId = _submit(ALICE);
        vm.prank(BOB);
        ms.confirmTransaction(txId); // now 2-of-3

        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, ATTACKER));
        ms.executeTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // M3 — onlySelf gates on threshold / owner mutation
    // -----------------------------------------------------------------------

    function test_M3_owner_cannot_unilaterally_change_threshold() public {
        vm.prank(ALICE);
        vm.expectRevert(LTPMultiSig.OnlySelf.selector);
        ms.changeThreshold(1);
    }

    function test_M3_owner_cannot_unilaterally_add_owner() public {
        vm.prank(ALICE);
        vm.expectRevert(LTPMultiSig.OnlySelf.selector);
        ms.addOwner(ATTACKER);
    }

    function test_M3_owner_cannot_unilaterally_remove_owner() public {
        vm.prank(ALICE);
        vm.expectRevert(LTPMultiSig.OnlySelf.selector);
        ms.removeOwner(BOB);
    }

    function test_M3_attacker_cannot_change_threshold() public {
        vm.prank(ATTACKER);
        vm.expectRevert(LTPMultiSig.OnlySelf.selector);
        ms.changeThreshold(1);
    }

    // -----------------------------------------------------------------------
    // M4 — constructor enforces threshold bounds
    // -----------------------------------------------------------------------

    function test_M4_constructor_rejects_zero_threshold() public {
        address[] memory owners = new address[](2);
        owners[0] = ALICE; owners[1] = BOB;
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.InvalidThreshold.selector, 0, 2));
        new LTPMultiSig(owners, 0);
    }

    function test_M4_constructor_rejects_threshold_above_owners() public {
        address[] memory owners = new address[](2);
        owners[0] = ALICE; owners[1] = BOB;
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.InvalidThreshold.selector, 3, 2));
        new LTPMultiSig(owners, 3);
    }

    function test_M4_constructor_rejects_empty_owners() public {
        address[] memory owners = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.InvalidThreshold.selector, 1, 0));
        new LTPMultiSig(owners, 1);
    }

    // -----------------------------------------------------------------------
    // M5 — double-confirmation rejected
    // -----------------------------------------------------------------------

    function test_M5_double_confirm_rejected() public {
        uint256 txId = _submit(ALICE);
        // ALICE auto-confirms on submit. Re-confirming must revert.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.TxAlreadyConfirmed.selector, txId, ALICE
        ));
        ms.confirmTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // M6 — revoke-then-execute fails below threshold
    // -----------------------------------------------------------------------

    function test_M6_revoke_drops_below_threshold() public {
        uint256 txId = _submit(ALICE);
        vm.prank(BOB);
        ms.confirmTransaction(txId); // 2-of-3

        vm.prank(BOB);
        ms.revokeConfirmation(txId); // back to 1-of-3

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2
        ));
        ms.executeTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // Fuzz — arbitrary non-owner cannot drive execution
    // -----------------------------------------------------------------------

    /// @dev Property: no caller outside the owner set can advance any
    ///      multisig-controlled state, regardless of which entrypoint
    ///      they try.
    function testFuzz_arbitrary_non_owner_blocked(address caller, uint256 txId) public {
        vm.assume(caller != ALICE && caller != BOB && caller != CAROL);
        vm.assume(caller != address(0));
        vm.assume(caller != address(ms));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, caller));
        ms.submitTransaction(address(0xDEAD), 0, "");

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, caller));
        ms.confirmTransaction(txId);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(LTPMultiSig.NotOwner.selector, caller));
        ms.executeTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _submit(address who) internal returns (uint256 txId) {
        vm.prank(who);
        txId = ms.submitTransaction(address(0xCAFE), 0, hex"");
    }
}
