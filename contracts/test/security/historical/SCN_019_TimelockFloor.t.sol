// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title SCN_019_TimelockFloor
/// @notice Red-team scenario SCN-019 — Cypher-class "production-
///         Timelock delay not asserted" pattern, addressed at deploy
///         time via DeployMainnet's hard floor.
///
/// Historical pattern: Cypher Protocol (Aug 2023) shipped with a
/// near-zero-delay Timelock. When the team paused after an exploit,
/// the attacker scheduled and executed an upgrade through the
/// Timelock within seconds. The defense is a HARD FLOOR on the
/// Timelock's minimum delay enforced at deploy time.
///
/// LTP analogue: `contracts/script/DeployMainnet.s.sol:48` enforces
///
///     require(timelockDelay >= 24 hours,
///             "mainnet requires timelock >= 24 hours");
///
/// LTP-A-009. This test replicates the require predicate in a
/// wrapper (the SCN-009 pattern) and pins boundary cases.
contract SCN019_TimelockFloor is Test {
    uint256 internal constant MAINNET_FLOOR = 24 hours;

    // ------------------------------------------------------------------
    // F1 — replicate the deploy-script require as pure Solidity logic.
    //
    // The actual DeployMainnet script reads MULTISIG_THRESHOLD,
    // TIMELOCK_DELAY, etc. from env. We can't run it directly in a
    // forge test without forge-script, but we CAN pin the boundary
    // logic as a free function.
    // ------------------------------------------------------------------

    function _passesMainnetFloor(uint256 proposedDelay) internal pure returns (bool) {
        return proposedDelay >= MAINNET_FLOOR;
    }

    function test_F1_floor_rejects_zero_delay() public {
        assertFalse(_passesMainnetFloor(0), "0-delay must fail mainnet floor");
    }

    function test_F1_floor_rejects_one_second() public {
        // Cypher Protocol's bug shape.
        assertFalse(_passesMainnetFloor(1));
    }

    function test_F1_floor_rejects_below_24h() public {
        assertFalse(_passesMainnetFloor(23 hours));
        assertFalse(_passesMainnetFloor(60));
        assertFalse(_passesMainnetFloor(1 hours));
    }

    function test_F1_floor_accepts_exactly_24h() public {
        assertTrue(_passesMainnetFloor(24 hours));
    }

    function test_F1_floor_accepts_recommended_48h() public {
        assertTrue(_passesMainnetFloor(48 hours));
    }

    function testFuzz_F1_floor_rejects_below_24h(uint256 delay) public {
        delay = bound(delay, 0, MAINNET_FLOOR - 1);
        assertFalse(_passesMainnetFloor(delay));
    }

    function testFuzz_F1_floor_accepts_at_or_above_24h(uint256 delay) public {
        delay = bound(delay, MAINNET_FLOOR, 365 days);
        assertTrue(_passesMainnetFloor(delay));
    }

    // ------------------------------------------------------------------
    // F2 — TimelockController constructed with delay < floor is
    // ABLE to be constructed (the contract itself imposes no floor)
    // — the protection is the deploy-script. Document this boundary.
    // ------------------------------------------------------------------

    function test_F2_oz_timelock_accepts_low_delay_at_contract_layer() public {
        // OZ TimelockController has no Byzantine-style floor; it accepts
        // any non-negative delay. The defense lives in our deploy
        // script. Documented here so the boundary is explicit.
        address[] memory proposers = new address[](1);
        proposers[0] = address(0xA1);
        address[] memory executors = new address[](1);
        executors[0] = address(0xA1);
        TimelockController lowDelayTimelock = new TimelockController(
            60,             // 60 seconds — well below mainnet floor
            proposers,
            executors,
            address(0)      // no admin
        );
        assertEq(lowDelayTimelock.getMinDelay(), 60);
    }

    function test_F2_oz_timelock_accepts_floor_delay() public {
        address[] memory proposers = new address[](1);
        proposers[0] = address(0xA1);
        address[] memory executors = new address[](1);
        executors[0] = address(0xA1);
        TimelockController floorTimelock = new TimelockController(
            MAINNET_FLOOR,
            proposers,
            executors,
            address(0)
        );
        assertEq(floorTimelock.getMinDelay(), MAINNET_FLOOR);
    }
}
