// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BridgeEmitter} from "../../../src/BridgeEmitter.sol";
import {ZKBridgeVerifier} from "../../../src/ZKBridgeVerifier.sol";
import {OptimisticBridgeChallenge} from "../../../src/OptimisticBridgeChallenge.sol";

/// @title SCN_007_THORChain_DecodeBug
/// @notice Red-team scenario SCN-007 — THORChain Router-class "user-
///         supplied bytes get decoded into an instruction dispatch"
///         pattern.
///
/// Historical incident: THORChain ETH Router exploit, 22 Jul 2021,
/// ~$5M (and a separate ~$8M follow-on). The Router accepted a
/// `bytes memo` field on deposit() that the Bifrost relayer parsed
/// off-chain. The attacker crafted a memo that when interpreted
/// caused outbound transfers without an inbound deposit — the
/// off-chain decode dispatched a transferOut() that the on-chain
/// state had no record of.
///
/// LTP analogue: LTP's two user-controlled-bytes surfaces are
/// `BridgeEmitter.emitBridgeTransfer(string payloadHash)` and
/// `ZKBridgeVerifier.verifyAndFinalize(bytes proofBytes, ...)`.
/// NEITHER decodes user bytes into a control-flow dispatch:
///
///   (T1) BridgeEmitter only EMITS `payloadHash` as an event field.
///        The string is never decoded, parsed, or dispatched on. The
///        contract has zero logic conditioned on its content.
///   (T2) ZKBridgeVerifier slices `proofBytes` into fixed-purpose
///        chunks (proof_hash + verification_tag) and uses them in
///        keccak256-based verification. Content cannot redirect
///        control flow — at most it can fail verification.
///   (T3) The verifier's mode dispatch (MODE_SIMULATED / MODE_SP1 /
///        MODE_STARK / MODE_RISC0) is gated by `verificationMode`
///        storage, set by ADMIN only. User input cannot select the
///        backend.
///   (T4) `productionMode + MODE_SIMULATED` is fail-closed
///        (LTP-A-007). Even if a relayer mis-configures, simulated
///        proofs are rejected on production.
///   (T5) `verifyAndFinalize` only ever calls
///        `challengeContract.finalizeWithZKProof(anchorDigest)` —
///        ONE downstream target, not caller-supplied. There is no
///        equivalent to THORChain's `(target, method, args)`
///        dispatch.
contract SCN007_THORChain_DecodeBug is Test {
    BridgeEmitter internal emitter;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ATTACKER = address(0xBADC0DE);

    function setUp() public {
        emitter = new BridgeEmitter(ADMIN, true); // permissionless v5/v6 mode
    }

    // -----------------------------------------------------------------------
    // T1 — BridgeEmitter does NOT dispatch on payloadHash content
    // -----------------------------------------------------------------------

    /// @dev Attacker submits a "memo-like" payload that, on a
    ///      THORChain-style router, would have triggered a transferOut.
    ///      The contract only emits it as a string event field.
    function test_T1_malicious_payload_only_emitted_not_dispatched() public {
        // A THORChain-style malicious memo would look like
        // `OUT:<txid>` or `=:ETH.ETH:<attacker>`. LTP's emitter
        // treats the bytes opaquely.
        string memory maliciousPayload = "OUT:transferOut(0xBADC0DE,1000ETH)";

        uint256 nonceBefore = emitter.nextNonce();

        vm.recordLogs();
        vm.prank(ATTACKER);
        emitter.emitBridgeTransfer(ATTACKER, maliciousPayload, 0);

        // Verify the only effect is the event + nonce++
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one event must fire");
        assertEq(logs[0].topics[0],
                 keccak256("BridgeTransfer(address,address,string,uint256,uint256)"));
        assertEq(emitter.nextNonce(), nonceBefore + 1);

        // No state change beyond the nonce — admin, permissionless,
        // and authorizedSenders are untouched.
        assertEq(emitter.admin(), ADMIN);
        assertEq(emitter.permissionless(), true);
        assertEq(emitter.authorizedSenders(ATTACKER), false);
    }

    /// @dev Payload of arbitrary bytes (including raw control chars,
    ///      null bytes, very long content) is accepted without any
    ///      attempted parse.
    function testFuzz_T1_arbitrary_payload_emitted_safely(
        bytes calldata payloadBytes
    ) public {
        // Bound length so the fuzz doesn't OOM CI.
        vm.assume(payloadBytes.length <= 4096);
        string memory payload = string(payloadBytes);

        uint256 nonceBefore = emitter.nextNonce();
        vm.prank(ATTACKER);
        emitter.emitBridgeTransfer(ATTACKER, payload, 0);

        // Property: nonce always advances by exactly 1, no side effects.
        assertEq(emitter.nextNonce(), nonceBefore + 1);
        assertEq(emitter.admin(), ADMIN);
    }

    // -----------------------------------------------------------------------
    // T3 — verifier mode is admin-controlled, not user-input-selectable
    // -----------------------------------------------------------------------

    /// @dev Attacker cannot change verificationMode through any path
    ///      reachable via user-controlled bytes. Only `setVerificationMode`
    ///      gated by `onlyAdmin` can change it.
    function test_T3_user_cannot_change_verification_mode() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            ADMIN, 1 hours, 1 ether, 0.5 ether
        );
        // MODE_SIMULATED = 0; passing it keeps test deterministic
        ZKBridgeVerifier ver = new ZKBridgeVerifier(ADMIN, address(ch), 0);

        uint8 modeBefore = ver.verificationMode();

        // Attacker tries to flip the mode. Only admin path exists;
        // there's no user-input bridge surface that drives mode.
        vm.prank(ATTACKER);
        vm.expectRevert(); // onlyAdmin (NotAdmin)
        ver.setVerificationMode(99);

        assertEq(ver.verificationMode(), modeBefore);
    }

    // -----------------------------------------------------------------------
    // T5 — verifier dispatch target is FIXED (challengeContract), not
    //      caller-supplied
    // -----------------------------------------------------------------------

    /// @dev Verify the verifier's `challengeContract` reference is
    ///      immutable post-construction. THORChain's bug was that the
    ///      Router accepted `(target, method, args)`; LTP's
    ///      ZKBridgeVerifier hard-codes the downstream call.
    function test_T5_verifier_dispatch_target_is_immutable() public {
        OptimisticBridgeChallenge ch1 = new OptimisticBridgeChallenge(
            ADMIN, 1 hours, 1 ether, 0.5 ether
        );
        ZKBridgeVerifier ver = new ZKBridgeVerifier(ADMIN, address(ch1));

        address targetBefore = address(ver.challengeContract());
        assertEq(targetBefore, address(ch1));

        // No public setter exists. We cannot test what isn't there;
        // we assert by reading the public reference and confirming
        // it matches construction-time.
        assertEq(address(ver.challengeContract()), address(ch1));
    }
}
