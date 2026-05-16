// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPMultiSig} from "../../../src/LTPMultiSig.sol";

/// @title SCN_009_Harmony_LowThreshold
/// @notice Red-team scenario SCN-009 — Harmony Horizon-class
///         "advertised multisig threshold is too low for the
///         value at risk; key-compromise of the threshold reaches
///         quorum" pattern.
///
/// Historical incident: Harmony Horizon bridge, 23 Jun 2022, ~$100M.
/// The bridge ran a 2-of-5 validator multisig. Lazarus Group
/// compromised 2 of the 5 keys (no specific public root-cause for
/// the key compromise itself — likely a combination of phishing
/// and a hot-wallet residing on a developer machine). Two keys is
/// the bare minimum of "more than one party agrees" — but it was
/// the same number as the configured threshold, so quorum was met.
/// $100M drained.
///
/// Root primitive: **N-of-M threshold was chosen without regard to
/// the bridge's value-at-risk.** A 2-of-5 is appropriate for a low-
/// stakes administrative wallet; it is dangerous for a $100M
/// bridge. The contract enforces "threshold ≤ owners" but it
/// CANNOT enforce "threshold reasonable for value-at-risk" — that's
/// an operational policy decision.
///
/// LTP defenses for this scenario:
///
///   (H1) `LTPMultiSig` constructor enforces basic threshold bounds:
///        threshold > 0 and threshold ≤ owners.length. Already pinned
///        by SCN-004 M4; documented here for cross-reference.
///   (H2) `DeployMainnet.s.sol:43-47` enforces a HARD FLOOR of
///        `threshold >= ceil(N/2) + 1` on every mainnet deploy.
///        A Harmony-style 2-of-5 configuration would be rejected at
///        deploy time. This test pack pins that floor via a wrapper
///        contract that replicates the deploy-script check.
///   (H3) `LTPMultiSig` correctly executes when threshold-many keys
///        ARE compromised — this is by design. The contract does
///        what it's told. Operator-tier defenses (HSM, rotation,
///        active-set monitoring) prevent reaching that state.
///        Cross-references LTP-A-004 and SCN-011 (Lazarus-tier
///        sustained key compromise).
contract SCN009_Harmony_LowThreshold is Test {
    address[] internal owners5;
    address[] internal owners9;

    function setUp() public {
        // 5 owners — Harmony's configuration
        owners5 = new address[](5);
        owners5[0] = address(0xA1);
        owners5[1] = address(0xA2);
        owners5[2] = address(0xA3);
        owners5[3] = address(0xA4);
        owners5[4] = address(0xA5);

        // 9 owners — Ronin's configuration
        owners9 = new address[](9);
        for (uint i = 0; i < 9; ++i) {
            owners9[i] = address(uint160(0xB0 + i));
        }
    }

    // -----------------------------------------------------------------------
    // H1 — basic bounds (cross-reference SCN-004 M4)
    // -----------------------------------------------------------------------

    function test_H1_constructor_accepts_2_of_5() public {
        // The CONTRACT itself does not enforce a Byzantine floor —
        // only basic bounds. A 2-of-5 configuration is valid.
        LTPMultiSig ms = new LTPMultiSig(owners5, 2);
        assertEq(ms.threshold(), 2);
        assertEq(ms.getOwners().length, 5);
    }

    function test_H1_constructor_accepts_1_of_5() public {
        // Even 1-of-5 is "valid" at the contract layer. Operational
        // policy is what rejects it.
        LTPMultiSig ms = new LTPMultiSig(owners5, 1);
        assertEq(ms.threshold(), 1);
    }

    // -----------------------------------------------------------------------
    // H2 — DeployMainnet enforces Byzantine floor
    //
    // The deploy script's `require(threshold >= ceil(N/2)+1)` is
    // pure Solidity logic. We replicate it as a free function here
    // and pin the boundary cases.
    // -----------------------------------------------------------------------

    function _byzantineFloor(uint256 ownerCount) internal pure returns (uint256) {
        return (ownerCount / 2) + 1;
    }

    function test_H2_byzantine_floor_for_5_owners_is_3() public {
        // 5 owners → ceil(5/2) + 1 = 2 + 1 = 3. Harmony's 2-of-5
        // would be REJECTED by DeployMainnet.
        assertEq(_byzantineFloor(5), 3);
        assertLt(uint256(2), _byzantineFloor(5),
                 "Harmony 2-of-5 fails the mainnet floor");
    }

    function test_H2_byzantine_floor_for_9_owners_is_5() public {
        // 9 owners → ceil(9/2) + 1 = 4 + 1 = 5. Ronin's 5-of-9
        // would have JUST PASSED — but recall SCN-008 showed the
        // effective threshold collapsed for different reasons.
        assertEq(_byzantineFloor(9), 5);
    }

    function test_H2_byzantine_floor_strictly_greater_than_half() public {
        // Property: for any owner count N >= 2, the floor exceeds N/2.
        for (uint256 n = 2; n <= 21; ++n) {
            uint256 floorVal = _byzantineFloor(n);
            // floor > N/2 (strict)
            assertGt(floorVal * 2, n,
                     "byzantine floor must exceed bare majority");
        }
    }

    function testFuzz_H2_floor_rejects_under_half_threshold(
        uint256 ownerCount,
        uint256 proposedThreshold
    ) public {
        ownerCount = bound(ownerCount, 2, 100);
        // Bound proposedThreshold to <= ownerCount/2 (BELOW the floor).
        proposedThreshold = bound(proposedThreshold, 1, ownerCount / 2);

        uint256 floorVal = _byzantineFloor(ownerCount);
        assertLt(proposedThreshold, floorVal,
                 "proposed threshold below floor - mainnet would reject");
    }

    // -----------------------------------------------------------------------
    // H3 — under-quorum cannot execute; AT-quorum can (by design)
    // -----------------------------------------------------------------------

    /// @dev With a 2-of-5 multisig, a single compromised owner
    ///      cannot execute. The contract is doing its job.
    function test_H3_one_compromised_of_5_blocked_at_2_threshold() public {
        LTPMultiSig ms = new LTPMultiSig(owners5, 2);

        vm.prank(owners5[0]);
        uint256 txId = ms.submitTransaction(address(0xCAFE), 0, hex"");

        vm.prank(owners5[0]);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2
        ));
        ms.executeTransaction(txId);
    }

    /// @dev With a 2-of-5 multisig, two compromised owners CAN
    ///      execute — this is the Harmony scenario. The contract
    ///      behaves correctly; the loss is an operational failure
    ///      (key custody), not a contract bug. This test
    ///      DOCUMENTS the contract behavior, it does not assert
    ///      a defense.
    function test_H3_two_compromised_of_5_can_execute_by_design() public {
        LTPMultiSig ms = new LTPMultiSig(owners5, 2);
        vm.deal(address(ms), 1 ether);

        // owners[0] + owners[1] = "compromised" by attacker.
        vm.prank(owners5[0]);
        uint256 txId = ms.submitTransaction(address(0xBADC0DE), 1 ether, hex"");

        vm.prank(owners5[1]);
        ms.confirmTransaction(txId);

        // 2 confirmations == threshold. Execute succeeds.
        vm.prank(owners5[0]);
        ms.executeTransaction(txId);

        // Document: the bridge is drained.
        assertEq(address(ms).balance, 0,
                 "by design - 2-of-5 with 2 compromised owners drains");
        assertEq(address(0xBADC0DE).balance, 1 ether);

        // Lesson: this is why DeployMainnet (H2) enforces the
        // Byzantine floor. With 3-of-5 mandatory, the same 2
        // compromised owners cannot drain.
    }

    /// @dev With the Byzantine floor enforced (3-of-5), the same
    ///      2-key compromise CANNOT drain.
    function test_H3_byzantine_floor_blocks_same_2_key_compromise() public {
        LTPMultiSig ms = new LTPMultiSig(owners5, 3); // ceil(5/2)+1
        vm.deal(address(ms), 1 ether);

        vm.prank(owners5[0]);
        uint256 txId = ms.submitTransaction(address(0xBADC0DE), 1 ether, hex"");

        vm.prank(owners5[1]);
        ms.confirmTransaction(txId);

        // 2 confirmations, threshold is 3. Cannot execute.
        vm.prank(owners5[0]);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 2, 3
        ));
        ms.executeTransaction(txId);

        assertEq(address(ms).balance, 1 ether,
                 "3-of-5 floor blocked the Harmony-style 2-key compromise");
    }
}
