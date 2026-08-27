// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ETPGovernance} from "../src/ETPGovernance.sol";

contract ETPGovernanceTest is Test {
    ETPGovernance public gov;
    address admin = address(0xAD);
    address voter1 = address(0x1001);
    address voter2 = address(0x1002);
    address voter3 = address(0x1003);
    address voter4 = address(0x1004);

    bytes32 constant VK1 = keccak256("operator-1-vk");
    bytes32 constant VK2 = keccak256("operator-2-vk");
    bytes32 constant VK3 = keccak256("operator-3-vk");
    bytes32 constant VK4 = keccak256("operator-4-vk");

    bytes32 transitionKey;

    function setUp() public {
        gov = new ETPGovernance(admin, 6667); // 66.67% supermajority
        transitionKey = keccak256(abi.encodePacked(
            gov.PHASE_BOOTSTRAP(), "->", gov.PHASE_GROWTH()
        ));
    }

    // -----------------------------------------------------------------------
    // Operator Registration
    // -----------------------------------------------------------------------

    function test_registerOperator_success() public {
        vm.prank(admin);
        gov.registerOperator(VK1, voter1);
        assertTrue(gov.authorizedOperators(VK1));
        assertEq(gov.operatorCount(), 1);
    }

    function test_registerOperator_nonAdmin_reverts() public {
        vm.prank(voter1);
        vm.expectRevert(abi.encodeWithSelector(ETPGovernance.NotAdmin.selector, voter1));
        gov.registerOperator(VK1, voter1);
    }

    function test_registerOperator_duplicate_reverts() public {
        vm.prank(admin);
        gov.registerOperator(VK1, voter1);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(ETPGovernance.OperatorAlreadyRegistered.selector, VK1));
        gov.registerOperator(VK1, voter1);
    }

    function test_registerOperator_zeroHash_reverts() public {
        vm.prank(admin);
        vm.expectRevert(ETPGovernance.ZeroVkHash.selector);
        gov.registerOperator(bytes32(0), voter1);
    }

    function test_revokeOperator() public {
        vm.prank(admin);
        gov.registerOperator(VK1, voter1);
        assertEq(gov.operatorCount(), 1);
        vm.prank(admin);
        gov.revokeOperator(VK1);
        assertFalse(gov.authorizedOperators(VK1));
        assertEq(gov.operatorCount(), 0);
    }

    // -----------------------------------------------------------------------
    // Voting
    // -----------------------------------------------------------------------

    function test_castVote_success() public {
        _registerOperators(1);
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));
        assertEq(gov.getVoteCount(transitionKey), 1);
        assertTrue(gov.hasOperatorVoted(transitionKey, VK1));
    }

    function test_castVote_unauthorized_reverts() public {
        bytes32 fakeVk = keccak256("not-registered");
        vm.prank(voter1);
        vm.expectRevert(abi.encodeWithSelector(ETPGovernance.OperatorNotAuthorized.selector, fakeVk));
        gov.castVote(transitionKey, fakeVk, 1, uint64(block.timestamp + 3600));
    }

    function test_castVote_duplicate_reverts() public {
        _registerOperators(1);
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));
        vm.prank(voter1);
        vm.expectRevert(abi.encodeWithSelector(ETPGovernance.DuplicateVote.selector, transitionKey, VK1));
        gov.castVote(transitionKey, VK1, 2, uint64(block.timestamp + 3600));
    }

    function test_castVote_sequenceTooLow_reverts() public {
        _registerOperators(1);
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 5, uint64(block.timestamp + 3600));
        // Try voting on a different transition with lower sequence
        bytes32 otherKey = keccak256("other-transition");
        vm.prank(voter1);
        vm.expectRevert(abi.encodeWithSelector(ETPGovernance.SequenceTooLow.selector, VK1, 3, 5));
        gov.castVote(otherKey, VK1, 3, uint64(block.timestamp + 3600));
    }

    function test_castVote_expired_reverts() public {
        _registerOperators(1);
        vm.prank(voter1);
        vm.expectRevert(abi.encodeWithSelector(
            ETPGovernance.VoteExpired.selector,
            uint64(block.timestamp - 1),
            uint64(block.timestamp)
        ));
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp - 1));
    }

    // -----------------------------------------------------------------------
    // Supermajority
    // -----------------------------------------------------------------------

    function test_supermajority_detection() public {
        _registerOperators(4); // Need 3 of 4 for 66.67%

        assertEq(gov.getRequiredVotes(), 3); // ceil(4 * 6667 / 10000) = 3

        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));
        assertFalse(gov.isSupermajority(transitionKey));

        vm.prank(voter2);
        gov.castVote(transitionKey, VK2, 1, uint64(block.timestamp + 3600));
        assertFalse(gov.isSupermajority(transitionKey));

        vm.prank(voter3);
        gov.castVote(transitionKey, VK3, 1, uint64(block.timestamp + 3600));
        assertTrue(gov.isSupermajority(transitionKey));
        assertEq(gov.getVoteCount(transitionKey), 3);
    }

    // -----------------------------------------------------------------------
    // Phase Transition
    // -----------------------------------------------------------------------

    function test_executeTransition_success() public {
        _registerAndVoteSupermajority();

        gov.executeTransition(gov.PHASE_BOOTSTRAP(), gov.PHASE_GROWTH());
        assertEq(gov.currentPhase(), gov.PHASE_GROWTH());
    }

    /// @dev C3: with zero operators registered (and thus zero votes possible),
    ///      `required` used to compute to 0 via integer division, letting any
    ///      EOA execute a transition with no votes at all. Must now revert.
    function test_executeTransition_zeroOperators_reverts() public {
        assertEq(gov.operatorCount(), 0);
        bytes32 bootstrap = gov.PHASE_BOOTSTRAP();
        bytes32 growth = gov.PHASE_GROWTH();

        vm.expectRevert(bytes("SuwappuGovernance: no operators registered"));
        gov.executeTransition(bootstrap, growth);

        assertEq(gov.currentPhase(), bootstrap);
    }

    function test_executeTransition_wrongPhase_reverts() public {
        // Current phase is BOOTSTRAP, trying to transition GROWTH -> MATURITY
        bytes32 growth = gov.PHASE_GROWTH();
        bytes32 maturity = gov.PHASE_MATURITY();
        vm.expectRevert();
        gov.executeTransition(growth, maturity);
    }

    function test_executeTransition_noSupermajority_reverts() public {
        _registerOperators(4);
        // Only 1 vote, need 3
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));

        bytes32 bootstrap = gov.PHASE_BOOTSTRAP();
        bytes32 growth = gov.PHASE_GROWTH();
        vm.expectRevert();
        gov.executeTransition(bootstrap, growth);
    }

    function test_invalidTransition_reverts() public {
        // BOOTSTRAP -> MATURITY is invalid (must go through GROWTH)
        // Even with supermajority, invalid transition should revert
        _registerOperators(4);
        bytes32 invalidKey = keccak256(abi.encodePacked(
            gov.PHASE_BOOTSTRAP(), "->", gov.PHASE_MATURITY()
        ));

        vm.prank(voter1);
        gov.castVote(invalidKey, VK1, 1, uint64(block.timestamp + 3600));
        vm.prank(voter2);
        gov.castVote(invalidKey, VK2, 1, uint64(block.timestamp + 3600));
        vm.prank(voter3);
        gov.castVote(invalidKey, VK3, 1, uint64(block.timestamp + 3600));

        bytes32 bootstrap = gov.PHASE_BOOTSTRAP();
        bytes32 maturity = gov.PHASE_MATURITY();
        vm.expectRevert();
        gov.executeTransition(bootstrap, maturity);
    }

    // -----------------------------------------------------------------------
    // Admin Transfer
    // -----------------------------------------------------------------------

    function test_transferAdmin() public {
        vm.prank(admin);
        gov.transferAdmin(address(0xBEEF));
        assertEq(gov.admin(), address(0xBEEF));
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    function test_getRequiredVotes_zero_operators() public view {
        assertEq(gov.getRequiredVotes(), 0);
    }

    function test_getRequiredVotes_one_operator() public {
        _registerOperators(1);
        assertEq(gov.getRequiredVotes(), 1); // ceil(1 * 6667 / 10000) = 1
    }

    function test_initialPhase_is_bootstrap() public view {
        assertEq(gov.currentPhase(), gov.PHASE_BOOTSTRAP());
    }

    // -----------------------------------------------------------------------
    // Full Lifecycle
    // -----------------------------------------------------------------------

    function test_fullLifecycle_bootstrap_to_growth() public {
        // 1. Register 3 operators
        _registerOperators(3);
        assertEq(gov.operatorCount(), 3);
        assertEq(gov.getRequiredVotes(), 3); // ceil(3 * 6667 / 10000) = 3

        // 2. Vote (need 3 of 3 — unanimous for 3 operators at 66.67%)
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));
        assertFalse(gov.isSupermajority(transitionKey));

        vm.prank(voter2);
        gov.castVote(transitionKey, VK2, 1, uint64(block.timestamp + 3600));
        assertFalse(gov.isSupermajority(transitionKey));

        vm.prank(voter3);
        gov.castVote(transitionKey, VK3, 1, uint64(block.timestamp + 3600));
        assertTrue(gov.isSupermajority(transitionKey));

        // 3. Execute transition
        gov.executeTransition(gov.PHASE_BOOTSTRAP(), gov.PHASE_GROWTH());
        assertEq(gov.currentPhase(), gov.PHASE_GROWTH());

        // 4. Verify phase is now GROWTH
        assertEq(gov.currentPhase(), keccak256("growth"));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _registerOperators(uint256 count) internal {
        vm.startPrank(admin);
        if (count >= 1) gov.registerOperator(VK1, voter1);
        if (count >= 2) gov.registerOperator(VK2, voter2);
        if (count >= 3) gov.registerOperator(VK3, voter3);
        if (count >= 4) gov.registerOperator(VK4, voter4);
        vm.stopPrank();
    }

    function _registerAndVoteSupermajority() internal {
        _registerOperators(4); // 4 operators, need 3 for supermajority
        vm.prank(voter1);
        gov.castVote(transitionKey, VK1, 1, uint64(block.timestamp + 3600));
        vm.prank(voter2);
        gov.castVote(transitionKey, VK2, 1, uint64(block.timestamp + 3600));
        vm.prank(voter3);
        gov.castVote(transitionKey, VK3, 1, uint64(block.timestamp + 3600));
    }
}
