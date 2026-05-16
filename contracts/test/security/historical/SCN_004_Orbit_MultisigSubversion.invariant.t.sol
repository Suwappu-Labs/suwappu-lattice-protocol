// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPMultiSig} from "../../../src/LTPMultiSig.sol";

/// @title SCN_004_Orbit_MultisigSubversion.invariant
/// @notice Stateful invariant suite for SCN-004 (Orbit Chain-class
///         multisig subversion pattern).
///
/// Properties pinned across any reachable handler call sequence:
///
///   T1 (no-execute-below-threshold):
///     Every executed txId had at least `threshold` confirmations at
///     the time of execution. The handler tracks this by snapshotting
///     `confirmations` immediately before each successful execute.
///
///   T2 (threshold-stable-without-self-call):
///     `threshold` only changes through `changeThreshold` (which is
///     `onlySelf`). The handler never wires up a multisig-confirmed
///     changeThreshold call, so threshold must equal the constructor
///     value throughout the campaign.
///
///   T3 (owner-set-stable-without-self-call):
///     Same as T2 for the owner set. `addOwner`/`removeOwner` are
///     `onlySelf`; no handler path completes such a call, so the
///     owner set must equal the constructor value throughout.
contract SCN004_Invariant is Test {
    LTPMultiSig internal ms;
    SCN004_Handler internal handler;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB   = address(0xB0B);
    address internal constant CAROL = address(0xCA601);
    uint256 internal constant THRESHOLD = 2;

    function setUp() public {
        address[] memory owners = new address[](3);
        owners[0] = ALICE; owners[1] = BOB; owners[2] = CAROL;
        ms = new LTPMultiSig(owners, THRESHOLD);

        handler = new SCN004_Handler(ms, ALICE, BOB, CAROL);
        targetContract(address(handler));
    }

    /// T1: every executed tx had >= threshold confirmations at exec time.
    function invariant_no_execute_below_threshold() public view {
        for (uint256 i = 0; i < handler.executedCount(); ++i) {
            uint256 confAtExec = handler.confirmationsAtExec(i);
            assertGe(confAtExec, THRESHOLD,
                     "tx executed with confirmations below threshold");
        }
    }

    /// T2: threshold did not drift.
    function invariant_threshold_stable() public view {
        assertEq(ms.threshold(), THRESHOLD);
    }

    /// T3: owner set did not drift.
    function invariant_owner_set_stable() public view {
        assertTrue(ms.isOwner(ALICE));
        assertTrue(ms.isOwner(BOB));
        assertTrue(ms.isOwner(CAROL));
        address[] memory currentOwners = ms.getOwners();
        assertEq(currentOwners.length, 3);
    }
}

/// @notice Handler bounds the fuzzer to legal entrypoints (with both
///         owner and non-owner addresses) and records execution
///         witnesses for T1.
contract SCN004_Handler is Test {
    LTPMultiSig public ms;
    address public immutable alice;
    address public immutable bob;
    address public immutable carol;

    uint256[] public executedTxs;
    uint256[] public confirmationsAtExecArr;

    constructor(LTPMultiSig _ms, address _a, address _b, address _c) {
        ms = _ms;
        alice = _a; bob = _b; carol = _c;
    }

    function executedCount() external view returns (uint256) {
        return executedTxs.length;
    }

    function confirmationsAtExec(uint256 i) external view returns (uint256) {
        return confirmationsAtExecArr[i];
    }

    function _ownerByIndex(uint8 idx) internal view returns (address) {
        uint8 m = idx % 3;
        if (m == 0) return alice;
        if (m == 1) return bob;
        return carol;
    }

    // ----- Submit (owner only) -----
    function submit(uint8 fromIdx, address to, bytes calldata data) external {
        address from = _ownerByIndex(fromIdx);
        vm.prank(from);
        try ms.submitTransaction(to, 0, data) {} catch {}
    }

    // ----- Confirm (owner only) -----
    function confirm(uint8 fromIdx, uint256 txId) external {
        address from = _ownerByIndex(fromIdx);
        vm.prank(from);
        try ms.confirmTransaction(txId) {} catch {}
    }

    // ----- Revoke (owner only) -----
    function revoke(uint8 fromIdx, uint256 txId) external {
        address from = _ownerByIndex(fromIdx);
        vm.prank(from);
        try ms.revokeConfirmation(txId) {} catch {}
    }

    // ----- Execute (owner only) -----
    function execute(uint8 fromIdx, uint256 txId) external {
        address from = _ownerByIndex(fromIdx);
        // Snapshot confirmations BEFORE execute; if execute succeeds,
        // record the witness for T1.
        (, , , , uint256 confBefore) = _txTuple(txId);
        vm.prank(from);
        try ms.executeTransaction(txId) {
            executedTxs.push(txId);
            confirmationsAtExecArr.push(confBefore);
        } catch {}
    }

    // ----- Attacker attempts (must always revert) -----
    function attackerExecute(address attacker, uint256 txId) external {
        if (attacker == alice || attacker == bob || attacker == carol) return;
        vm.prank(attacker);
        try ms.executeTransaction(txId) {
            // If this lands, T2/T3 wouldn't catch it but a sub-threshold
            // execute would; record so the witness is visible.
            executedTxs.push(txId);
            (, , , , uint256 confAt) = _txTuple(txId);
            confirmationsAtExecArr.push(confAt);
        } catch {}
    }

    /// @dev Read transaction fields. LTPMultiSig stores transactions
    ///      as a struct; the auto-getter returns the tuple.
    function _txTuple(uint256 txId) internal view returns (
        address to, uint256 value, bytes memory data, bool executed, uint256 confirmations
    ) {
        return ms.transactions(txId);
    }
}
