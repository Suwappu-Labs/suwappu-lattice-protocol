// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuTimelockController} from "../src/SuwappuTimelockController.sol";

/// @dev Minimal target contract for timelock integration tests.
contract TimelockTarget {
    bool public paused;
    address public owner;
    uint256 public value;

    constructor(address owner_) { owner = owner_; }

    function pause() external { paused = true; }
    function unpause() external { paused = false; }
    function setValue(uint256 v) external { value = v; }
    function transferAdmin(address newOwner) external { owner = newOwner; }
}

contract SuwappuTimelockControllerTest is Test {
    SuwappuTimelockController timelock;
    TimelockTarget target;

    address safe     = makeAddr("gnosisSafe");
    address guardian = makeAddr("guardian");
    address alice    = makeAddr("alice");

    bytes4  SEL_PAUSE         = bytes4(keccak256("pause()"));
    bytes4  SEL_SET_VALUE     = bytes4(keccak256("setValue(uint256)"));
    bytes4  SEL_TRANSFER_ADMIN = bytes4(keccak256("transferAdmin(address)"));

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = safe;

        address[] memory guardians = new address[](1);
        guardians[0] = guardian;

        timelock = new SuwappuTimelockController(proposers, guardians);
        target   = new TimelockTarget(address(timelock));
    }

    // -----------------------------------------------------------------------
    // Delay constants
    // -----------------------------------------------------------------------

    function test_upgradeDelay_is_7days() public view {
        assertEq(timelock.UPGRADE_DELAY(), 7 days);
    }

    function test_paramDelay_is_3days() public view {
        assertEq(timelock.PARAM_DELAY(), 3 days);
    }

    function test_minDelay_equals_paramDelay() public view {
        assertEq(timelock.getMinDelay(), timelock.PARAM_DELAY());
    }

    // -----------------------------------------------------------------------
    // transferAdmin selector pre-registered with UPGRADE_DELAY
    // -----------------------------------------------------------------------

    function test_transferAdmin_selector_has_upgradeDelay() public view {
        assertEq(timelock.selectorDelay(SEL_TRANSFER_ADMIN), timelock.UPGRADE_DELAY());
    }

    function test_schedule_transferAdmin_reverts_below_upgradeDelay() public {
        bytes memory data   = abi.encodeWithSelector(SEL_TRANSFER_ADMIN, alice);
        uint256 paramDelay  = timelock.PARAM_DELAY(); // cache before prank

        vm.prank(safe);
        vm.expectRevert(); // SelectorDelayTooShort
        timelock.schedule(
            address(target), 0, data, bytes32(0), bytes32(0),
            paramDelay // only 3 days — below 7-day required
        );
    }

    function test_schedule_transferAdmin_succeeds_with_upgradeDelay() public {
        bytes memory data    = abi.encodeWithSelector(SEL_TRANSFER_ADMIN, alice);
        uint256 upgradeDelay = timelock.UPGRADE_DELAY(); // cache before prank

        vm.prank(safe);
        timelock.schedule(
            address(target), 0, data, bytes32(0), bytes32("salt1"),
            upgradeDelay
        );
        // Operation should now be pending
        bytes32 opId = timelock.hashOperation(
            address(target), 0, data, bytes32(0), bytes32("salt1")
        );
        assertTrue(timelock.isOperationPending(opId));
    }

    // -----------------------------------------------------------------------
    // Normal param operation (setValue — no special selector delay)
    // -----------------------------------------------------------------------

    function test_schedule_execute_paramOp() public {
        bytes memory data  = abi.encodeWithSelector(SEL_SET_VALUE, uint256(42));
        bytes32 salt       = bytes32("setValue-salt");
        uint256 paramDelay = timelock.PARAM_DELAY(); // cache before prank

        // Schedule
        vm.prank(safe);
        timelock.schedule(address(target), 0, data, bytes32(0), salt, paramDelay);

        // Advance past delay
        vm.warp(block.timestamp + paramDelay + 1);

        // Execute (anyone can, executor role is open)
        timelock.execute(address(target), 0, data, bytes32(0), salt);

        assertEq(target.value(), 42);
    }

    function test_schedule_reverts_below_minDelay() public {
        bytes memory data = abi.encodeWithSelector(SEL_SET_VALUE, uint256(1));

        vm.prank(safe);
        vm.expectRevert(); // base TimelockInsufficientDelay
        timelock.schedule(
            address(target), 0, data, bytes32(0), bytes32(0),
            1 hours // way below PARAM_DELAY
        );
    }

    // -----------------------------------------------------------------------
    // Guardian emergency execution
    // -----------------------------------------------------------------------

    function test_guardianExecute_pauses_target() public {
        // First register pause() as an emergency selector (via timelock self-call)
        // We'll do this directly via the timelock itself (simulating a completed proposal)
        vm.prank(address(timelock)); // only self can call setSelectorDelay / setEmergencySelector
        timelock.setEmergencySelector(SEL_PAUSE, true);

        // Guardian can now call pause() immediately
        bytes memory data = abi.encodeWithSelector(SEL_PAUSE);
        vm.prank(guardian);
        timelock.guardianExecute(address(target), data);

        assertTrue(target.paused());
    }

    function test_guardianExecute_reverts_nonEmergencySelector() public {
        bytes memory data = abi.encodeWithSelector(SEL_SET_VALUE, uint256(999));

        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuTimelockController.NotEmergencySelector.selector, SEL_SET_VALUE)
        );
        timelock.guardianExecute(address(target), data);
    }

    function test_guardianExecute_reverts_notGuardian() public {
        vm.prank(address(timelock));
        timelock.setEmergencySelector(SEL_PAUSE, true);

        vm.prank(alice); // not a guardian
        vm.expectRevert();
        timelock.guardianExecute(address(target), abi.encodeWithSelector(SEL_PAUSE));
    }

    function test_guardianExecute_reverts_emptyCalldata() public {
        vm.prank(guardian);
        vm.expectRevert(SuwappuTimelockController.EmptyCalldata.selector);
        timelock.guardianExecute(address(target), "");
    }

    // -----------------------------------------------------------------------
    // setSelectorDelay — self-administered
    // -----------------------------------------------------------------------

    function test_setSelectorDelay_reverts_notSelf() public {
        vm.prank(safe);
        vm.expectRevert("SuwappuTimelock: caller is not this contract");
        timelock.setSelectorDelay(SEL_SET_VALUE, 1 days);
    }

    function test_setSelectorDelay_via_self() public {
        vm.prank(address(timelock));
        timelock.setSelectorDelay(SEL_SET_VALUE, 5 days);
        assertEq(timelock.selectorDelay(SEL_SET_VALUE), 5 days);
    }

    // -----------------------------------------------------------------------
    // requiredDelay view
    // -----------------------------------------------------------------------

    function test_requiredDelay_unknownSelector_returns_minDelay() public view {
        bytes memory data = abi.encodeWithSelector(bytes4(keccak256("unknown()")));
        assertEq(timelock.requiredDelay(data), timelock.getMinDelay());
    }

    function test_requiredDelay_transferAdmin_returns_upgradeDelay() public view {
        bytes memory data = abi.encodeWithSelector(SEL_TRANSFER_ADMIN, alice);
        assertEq(timelock.requiredDelay(data), timelock.UPGRADE_DELAY());
    }

    // -----------------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------------

    function test_safe_has_proposerRole() public view {
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), safe));
    }

    function test_safe_has_cancellerRole() public view {
        assertTrue(timelock.hasRole(timelock.CANCELLER_ROLE(), safe));
    }

    function test_guardian_has_guardianRole() public view {
        assertTrue(timelock.hasRole(timelock.GUARDIAN_ROLE(), guardian));
    }

    function test_executor_role_is_open() public view {
        // address(0) holding EXECUTOR_ROLE means anyone can execute
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), address(0)));
    }

    // -----------------------------------------------------------------------
    // Cancel
    // -----------------------------------------------------------------------

    function test_canceller_can_cancel_pending_op() public {
        bytes memory data  = abi.encodeWithSelector(SEL_SET_VALUE, uint256(99));
        bytes32 salt       = bytes32("cancel-test");
        uint256 paramDelay = timelock.PARAM_DELAY(); // cache before prank

        vm.prank(safe);
        timelock.schedule(address(target), 0, data, bytes32(0), salt, paramDelay);

        bytes32 opId = timelock.hashOperation(address(target), 0, data, bytes32(0), salt);
        assertTrue(timelock.isOperationPending(opId));

        vm.prank(safe);
        timelock.cancel(opId);

        assertFalse(timelock.isOperation(opId));
    }
}
