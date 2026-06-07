// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SuwappuVault} from "../../src/SuwappuVault.sol";
import {SuwappuRefundEscrow} from "../../src/SuwappuRefundEscrow.sol";
import {SuwappuTimelockController} from "../../src/SuwappuTimelockController.sol";

/// @title SuwappuCustody.security.t.sol
/// @notice Deterministic regression proofs for confirmed custody-layer findings
///         C5–C8 (audit program P1/P3). Each test asserts the SECURE property
///         we want, so it is RED on the current (buggy) code and must go GREEN
///         once the corresponding P7 fix lands — and RED again if reverted.
///
///   C5  INV-FOT          — fee-on-transfer token under-collateralizes the vault
///   C6  INV-ESCROW-SOLV  — sweepUnclaimed drains funds owed to still-open rounds
///   C7  INV-ESCROW-MULTI — multi-token entitlement in one round under-claims
///   C8  INV-GUARD-TARGET — guardian selector whitelist is not bound to a target

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

/// @dev ERC-20 that burns a 2% fee on every account-to-account transfer.
contract FeeOnTransferToken is ERC20 {
    uint256 public constant FEE_BPS = 200; // 2%
    constructor() ERC20("FeeOnTransfer", "FOT") {}
    function mint(address to, uint256 amt) external { _mint(to, amt); }
    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = (value * FEE_BPS) / 10_000;
            super._update(from, to, value - fee);
            super._update(from, address(0xdEaD), fee);
        } else {
            super._update(from, to, value);
        }
    }
}

/// @dev Plain ERC-20 with no transfer fee (for the C7 multi-token claim test).
contract PlainToken is ERC20 {
    constructor() ERC20("Plain", "PLN") {}
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

/// @dev Two distinct targets sharing the same `pause()` selector (0x8456cb59).
contract PausableTarget {
    bool public paused;
    function pause() external { paused = true; }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

contract SuwappuCustodySecurityTest is Test {
    address internal constant ADMIN = address(0xA1);
    address internal constant TREASURY = address(0x7);
    address internal alice = makeAddr("alice");
    address internal bob   = makeAddr("bob");

    // ----- C5: fee-on-transfer under-collateralization -----
    function test_C5_fot_does_not_overstate_collateral() public {
        SuwappuVault vault = new SuwappuVault(ADMIN, ADMIN, 0); // feeBps=0
        FeeOnTransferToken fot = new FeeOnTransferToken();
        fot.mint(alice, 1_000 ether);
        // P3-7: a FOT token would normally be excluded by the allowlist; allow it
        // here to exercise C5's received-balance accounting (the second defence).
        vm.prank(ADMIN);
        vault.setAllowedToken(address(fot), true);

        vm.startPrank(alice);
        fot.approve(address(vault), type(uint256).max);
        vault.lockERC20(address(fot), 100 ether, 8453, alice);
        vm.stopPrank();

        // SECURE PROPERTY: recorded collateral must never exceed real balance.
        // Today totalLocked == 100e18 but only 98e18 actually arrived → RED.
        assertLe(
            vault.totalLocked(address(fot)),
            fot.balanceOf(address(vault)),
            "C5: totalLocked overstates real vault balance (FOT under-collateralization)"
        );
    }

    // ----- C6: sweepUnclaimed drains a still-open round -----
    function test_C6_sweep_preserves_open_round_solvency() public {
        // admin == this test so it can openRound / sweep directly.
        SuwappuRefundEscrow escrow = new SuwappuRefundEscrow(address(this), TREASURY);

        // Fund the reserve with 20 ETH (10 owed in round1, 10 owed in round2).
        escrow.depositETH{value: 20 ether}();

        uint256 window = escrow.claimWindow(); // 30 days default

        // Round 1: alice entitled to 10 ETH (single-leaf tree → root == leaf).
        bytes32 leaf1 = keccak256(abi.encodePacked(alice, address(0), uint256(10 ether), uint256(1)));
        escrow.openRound(leaf1, "round1");        // closesAt1 = now + window

        // Round 2 opens one day later, so its window closes one day after round 1's.
        vm.warp(block.timestamp + 1 days);
        bytes32 leaf2 = keccak256(abi.encodePacked(bob, address(0), uint256(10 ether), uint256(2)));
        escrow.openRound(leaf2, "round2");        // closesAt2 = closesAt1 + 1 day

        // Advance so round 1 is CLOSED but round 2 is STILL OPEN.
        vm.warp(block.timestamp + window - 1 days + 1); // just past closesAt1, before closesAt2

        // Sweeping the closed round1 must not be able to take funds owed to the
        // still-open round2. Under the fix this reverts; under the bug it drains all 20.
        try escrow.sweepUnclaimed(1, address(0)) {} catch {}

        // SECURE PROPERTY: bob's 10 ETH entitlement (round 2, still open) survives.
        assertGe(
            address(escrow).balance,
            10 ether,
            "C6: sweepUnclaimed drained funds owed to a still-open round"
        );
    }

    // ----- C7: multi-token entitlement in one round under-claims -----
    function test_C7_multi_token_claim_in_one_round() public {
        SuwappuRefundEscrow escrow = new SuwappuRefundEscrow(address(this), TREASURY);
        PlainToken tok = new PlainToken(); // no transfer fee — isolate the C7 behavior

        escrow.depositETH{value: 10 ether}();
        tok.mint(address(this), 100 ether);
        tok.approve(address(escrow), type(uint256).max);
        escrow.depositERC20(address(tok), 5 ether);

        // Round with TWO leaves for the same claimant: (alice, ETH, 10) and (alice, tok, 5).
        uint256 rid = 1;
        bytes32 leafEth = keccak256(abi.encodePacked(alice, address(0),     uint256(10 ether), rid));
        bytes32 leafTok = keccak256(abi.encodePacked(alice, address(tok),   uint256(5 ether),  rid));
        bytes32 root = _hashPair(leafEth, leafTok);
        escrow.openRound(root, "multi-token round");

        bytes32[] memory proofEth = new bytes32[](1);
        proofEth[0] = leafTok;
        bytes32[] memory proofTok = new bytes32[](1);
        proofTok[0] = leafEth;

        vm.startPrank(alice);
        escrow.claim(rid, address(0), 10 ether, proofEth);   // claim ETH first
        // SECURE PROPERTY: the token leaf is a SEPARATE entitlement and must also be claimable.
        escrow.claim(rid, address(tok), 5 ether, proofTok);  // today reverts AlreadyClaimed → RED
        vm.stopPrank();

        assertEq(tok.balanceOf(alice), 5 ether,
            "C7: second-token claim in same round did not pay out");
    }

    // ----- C8: guardian selector whitelist not bound to a target -----
    function test_C8_guardian_cannot_hit_unintended_target() public {
        address[] memory proposers = new address[](1);
        proposers[0] = makeAddr("safe");
        address guardian = makeAddr("guardian");
        address[] memory guardians = new address[](1);
        guardians[0] = guardian;

        SuwappuTimelockController tl = new SuwappuTimelockController(proposers, guardians);

        PausableTarget intended = new PausableTarget();
        PausableTarget victim   = new PausableTarget();

        // Governance whitelists pause() FOR THE INTENDED TARGET ONLY (self-administered).
        vm.prank(address(tl));
        tl.setEmergencySelector(address(intended), PausableTarget.pause.selector, true);

        // SECURE PROPERTY: a selector whitelisted for emergency use must not let
        // the guardian invoke it on an arbitrary, unintended target.
        vm.prank(guardian);
        vm.expectRevert(); // today this SUCCEEDS (whitelist is selector-only) → RED
        tl.guardianExecute(address(victim), abi.encodeWithSelector(PausableTarget.pause.selector));

        assertFalse(victim.paused(), "C8: guardian paused an unintended target");
        assertFalse(intended.paused());
    }

    // OZ MerkleProof uses commutative (sorted) pair hashing.
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    receive() external payable {}
}
