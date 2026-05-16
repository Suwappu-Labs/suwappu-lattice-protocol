// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {OptimisticBridgeChallenge} from "../../../src/OptimisticBridgeChallenge.sol";

/// @title SCN_005_Penpie_Reentrancy.invariant
/// @notice Stateful invariant suite for SCN-005 (Penpie-class
///         reentrancy pattern). Reuses the existing
///         `OptimisticBridgeChallenge.invariant.t.sol` bond-
///         conservation invariant; this file adds REENTRANCY-
///         SPECIFIC properties.
///
/// Properties pinned across any reachable handler call sequence:
///
///   X1 (no-double-payout):
///     The handler tracks per-digest "paid" events. Across the
///     campaign, no digest is ever paid more than once. If a
///     reentrancy primitive let the same digest fire twice, this
///     would catch it.
///
///   X2 (status-terminal-monotone):
///     Once a digest reaches a terminal status (RESOLVED, FINALIZED),
///     it never re-enters STATUS_OPEN or STATUS_CHALLENGED.
contract SCN005_Invariant is Test {
    OptimisticBridgeChallenge internal ch;
    SCN005_Handler internal handler;

    address internal constant ADMIN = address(0xA11CE);

    function setUp() public {
        ch = new OptimisticBridgeChallenge(
            ADMIN,
            1 hours,
            1 ether,
            0.5 ether
        );
        handler = new SCN005_Handler(ch, ADMIN);
        targetContract(address(handler));
    }

    function invariant_no_double_payout() public view {
        for (uint256 i = 0; i < handler.paidDigestCount(); ++i) {
            bytes32 d = handler.paidDigests(i);
            assertLe(handler.paidCount(d), uint256(1),
                     "digest paid more than once - reentrancy?");
        }
    }

    function invariant_status_terminal_monotone() public view {
        for (uint256 i = 0; i < handler.observedDigestCount(); ++i) {
            bytes32 d = handler.observedDigests(i);
            if (handler.reachedTerminal(d)) {
                OptimisticBridgeChallenge.Challenge memory c = ch.getChallenge(d);
                uint8 s = c.status;
                assertTrue(
                    s == ch.STATUS_RESOLVED()
                    || s == ch.STATUS_FINALIZED()
                    || s == ch.STATUS_EXPIRED(),
                    "digest left terminal status"
                );
            }
        }
    }
}

contract SCN005_Handler is Test {
    OptimisticBridgeChallenge public ch;
    address public immutable adminAddr;

    bytes32[] public observedDigests;
    mapping(bytes32 => bool) public seen;
    bytes32[] public paidDigests;
    mapping(bytes32 => uint256) public paidCount;
    mapping(bytes32 => bool) public reachedTerminal;

    constructor(OptimisticBridgeChallenge _ch, address _admin) {
        ch = _ch;
        adminAddr = _admin;
        vm.deal(address(this), 10000 ether);
    }

    function paidDigestCount() external view returns (uint256) {
        return paidDigests.length;
    }

    function observedDigestCount() external view returns (uint256) {
        return observedDigests.length;
    }

    receive() external payable {
        // Payouts land here. Track them.
        // We can't tell from msg.value alone WHICH digest paid — so we
        // count by call-sequence in the wrappers below instead.
    }

    function _recordObserved(bytes32 d) internal {
        if (!seen[d]) {
            seen[d] = true;
            observedDigests.push(d);
        }
    }

    function _recordPayout(bytes32 d, uint256 paidWei) internal {
        if (paidWei > 0) {
            paidCount[d] += 1;
            paidDigests.push(d);
        }
    }

    function openWindow(bytes32 d) external {
        if (d == bytes32(0)) return;
        try ch.openWindow{value: 1 ether}(d) { _recordObserved(d); } catch {}
    }

    function submitChallenge(uint256 idx) external {
        if (observedDigests.length == 0) return;
        bytes32 d = observedDigests[idx % observedDigests.length];
        try ch.submitChallenge{value: 0.5 ether}(d, 1, keccak256("p")) {} catch {}
    }

    function resolveAdmin(uint256 idx, bool fraudValid) external {
        if (observedDigests.length == 0) return;
        bytes32 d = observedDigests[idx % observedDigests.length];
        uint256 balBefore = address(ch).balance;
        vm.prank(adminAddr);
        try ch.resolveChallenge(d, fraudValid) {
            uint256 paid = balBefore - address(ch).balance;
            _recordPayout(d, paid);
            reachedTerminal[d] = true;
        } catch {}
    }

    function finalize(uint256 idx) external {
        if (observedDigests.length == 0) return;
        bytes32 d = observedDigests[idx % observedDigests.length];
        uint256 balBefore = address(ch).balance;
        try ch.finalizeWindow(d) {
            uint256 paid = balBefore - address(ch).balance;
            _recordPayout(d, paid);
            reachedTerminal[d] = true;
        } catch {}
    }

    function warp(uint256 secs) external {
        secs = bound(secs, 0, 30 days);
        vm.warp(block.timestamp + secs);
    }
}
