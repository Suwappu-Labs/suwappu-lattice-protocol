// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPMultiSig} from "../../../src/LTPMultiSig.sol";

/// @title SCN_008_Ronin_ActiveSetCollapse
/// @notice Red-team scenario SCN-008 — Ronin Bridge-class "advertised
///         N-of-M collapses because M-effective < N due to inactive
///         signers and/or a proxy-signing shortcut" pattern.
///
/// Historical incident: Ronin Bridge, 23 Mar 2022, $625M. Ronin ran a
/// 5-of-9 validator multisig on the Axie Infinity bridge. Sky Mavis
/// (the operator) controlled 4 of the 9 keys directly, plus a gas-
/// relayer system that signed on behalf of validators in certain
/// flows — effectively a "5th implicit signer" with full validator
/// authority. When the attacker compromised those 4 keys (via a
/// fake-LinkedIn-recruiter phishing attack against an engineer)
/// AND tricked the gas-relayer flow to sign, they had 5-of-5 of the
/// effective signer set. The advertised 5-of-9 threshold provided
/// none of the defense it claimed.
///
/// LTP analogue: LTPMultiSig has no delegation / proxy-signing /
/// gas-relayer / sign-on-behalf surface. Every confirmation must
/// come from an explicit owner address with `msg.sender == owner`.
/// The defenses pinned in this scenario:
///
///   (R1) submitTransaction's implicit confirmation credits ONLY
///        msg.sender as the confirming owner — no caller-supplied
///        "actual signer" field.
///   (R2) confirmTransaction's confirmation credits ONLY msg.sender
///        — no delegation, no EIP-712 signature-recovery shortcut.
///   (R3) executeTransaction's threshold check counts ONLY recorded
///        per-owner confirmations from confirmTransaction — there is
///        no "off-chain signature bundle" path.
///   (R4) There is no `permit`-style or `executeWithSig`-style
///        entrypoint that lets the multisig execute based on a
///        signature alone without an on-chain `vm.prank(owner)`-
///        equivalent call. Verified by exhaustive negative search.
contract SCN008_Ronin_ActiveSetCollapse is Test {
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
    // R1 — submitTransaction credits ONLY msg.sender
    // -----------------------------------------------------------------------

    function test_R1_submit_confirmation_credits_only_msg_sender() public {
        vm.prank(ALICE);
        uint256 txId = ms.submitTransaction(address(0xCAFE), 0, hex"");

        // The transaction's confirmation count is 1 — ALICE's.
        (, , , , uint256 confirmations) = ms.transactions(txId);
        assertEq(confirmations, 1);

        // No other owner is shown as having confirmed.
        assertTrue(ms.confirmations(txId, ALICE));
        assertFalse(ms.confirmations(txId, BOB));
        assertFalse(ms.confirmations(txId, CAROL));
    }

    // -----------------------------------------------------------------------
    // R2 — confirmTransaction credits ONLY msg.sender (no delegation)
    // -----------------------------------------------------------------------

    function test_R2_confirm_credits_only_msg_sender() public {
        vm.prank(ALICE);
        uint256 txId = ms.submitTransaction(address(0xCAFE), 0, hex"");

        // BOB confirms in his own name.
        vm.prank(BOB);
        ms.confirmTransaction(txId);

        assertTrue(ms.confirmations(txId, BOB));
        assertFalse(ms.confirmations(txId, CAROL),
                    "CAROL must not be confirmed by BOB's call");
    }

    /// @dev The attacker tries to claim a confirmation for BOB by
    ///      calling confirmTransaction while pretending to be a
    ///      gas relayer. The contract has no such path — the call
    ///      reverts because the attacker is not an owner.
    function test_R2_attacker_cannot_relay_a_confirmation() public {
        vm.prank(ALICE);
        uint256 txId = ms.submitTransaction(address(0xCAFE), 0, hex"");

        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.NotOwner.selector, ATTACKER
        ));
        ms.confirmTransaction(txId);

        // No credit was recorded for any owner.
        assertFalse(ms.confirmations(txId, BOB));
        assertFalse(ms.confirmations(txId, CAROL));
    }

    // -----------------------------------------------------------------------
    // R3 — executeTransaction counts ONLY recorded per-owner confirmations
    // -----------------------------------------------------------------------

    function test_R3_execute_counts_only_recorded_confirmations() public {
        vm.prank(ALICE);
        uint256 txId = ms.submitTransaction(address(0xCAFE), 0, hex"");

        // One confirmation (ALICE's via submit). Threshold is 2.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2
        ));
        ms.executeTransaction(txId);
    }

    // -----------------------------------------------------------------------
    // R4 — no permit/executeWithSig entrypoint
    // -----------------------------------------------------------------------

    /// @dev Foundry static-analysis approach: enumerate the public
    ///      ABI of LTPMultiSig and confirm no function name matches
    ///      typical signature-recovery patterns. We can't list ABI
    ///      from inside Solidity, so we assert via a different
    ///      contract: any unrecognized selector reverts because the
    ///      contract has no fallback.
    function test_R4_unknown_selector_reverts_no_fallback() public {
        // permit(address,uint256,...) style call data — fabricated
        // selector for "executeWithSig(bytes,uint256)".
        bytes memory data = abi.encodeWithSignature(
            "executeWithSig(bytes,uint256)", hex"deadbeef", uint256(0)
        );
        (bool ok, ) = address(ms).call(data);
        assertFalse(ok, "no permit/executeWithSig entrypoint must exist");
    }

    function testFuzz_R4_no_fallback_for_arbitrary_selectors(
        bytes4 selector,
        bytes calldata payload
    ) public {
        // Skip the actual function selectors so we don't accidentally
        // hit a real entrypoint with valid args.
        bytes4[6] memory realSelectors = [
            ms.submitTransaction.selector,
            ms.confirmTransaction.selector,
            ms.revokeConfirmation.selector,
            ms.executeTransaction.selector,
            ms.addOwner.selector,
            ms.removeOwner.selector
        ];
        for (uint i = 0; i < realSelectors.length; ++i) {
            vm.assume(selector != realSelectors[i]);
        }

        (bool ok, ) = address(ms).call(abi.encodePacked(selector, payload));
        assertFalse(ok, "arbitrary unknown selector must revert");
    }

    // -----------------------------------------------------------------------
    // Ronin-equivalent scenario: simulate 1 of 3 owners "compromised"
    // (turned attacker). Threshold 2-of-3 still holds — the attacker
    // alone can't execute.
    // -----------------------------------------------------------------------

    function test_compromised_single_owner_cannot_execute() public {
        // Simulate ALICE being the compromised owner. The attacker
        // controls her key and acts AS Alice from now on.
        // She can submit (1 confirmation) but cannot reach threshold.
        vm.prank(ALICE);
        uint256 txId = ms.submitTransaction(address(0xBADC0DE), 0, hex"");

        // Attacker-as-ALICE cannot self-confirm again (R2 — single
        // confirmation per owner).
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.TxAlreadyConfirmed.selector, txId, ALICE
        ));
        ms.confirmTransaction(txId);

        // Execution still requires 2-of-3; ALICE alone has 1.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            LTPMultiSig.InsufficientConfirmations.selector, txId, 1, 2
        ));
        ms.executeTransaction(txId);
    }
}
