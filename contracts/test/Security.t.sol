// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BridgeEmitter} from "../src/BridgeEmitter.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {OptimisticBridgeChallenge} from "../src/OptimisticBridgeChallenge.sol";
import {ZKBridgeVerifier} from "../src/ZKBridgeVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title Security.t.sol
/// @notice Forge regression tests for the Solidity-layer hardening fixes in
///         docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md (LTP-A-006, LTP-A-007,
///         LTP-A-017, LTP-A-029).
contract SecurityTest is Test {
    address admin = address(0xA11CE);
    address bob = address(0xB0B);

    // -----------------------------------------------------------------------
    // LTP-A-017: BridgeEmitter authorized-senders gate
    // -----------------------------------------------------------------------

    function test_bridgeemitter_permissionless_mode_emits() public {
        BridgeEmitter be = new BridgeEmitter(address(0), true);
        vm.prank(bob);
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
        assertEq(be.nextNonce(), 1);
    }

    function test_bridgeemitter_gated_mode_rejects_unauthorized() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeEmitter.NotAuthorized.selector, bob)
        );
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
    }

    function test_bridgeemitter_gated_mode_accepts_authorized() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(admin);
        be.setAuthorized(bob, true);
        vm.prank(bob);
        be.emitBridgeTransfer(bob, "sha3:0xdeadbeef", 1 ether);
        assertEq(be.nextNonce(), 1);
    }

    function test_bridgeemitter_setauthorized_admin_only() public {
        BridgeEmitter be = new BridgeEmitter(admin, false);
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeEmitter.NotAdmin.selector, bob)
        );
        be.setAuthorized(bob, true);
    }

    // -----------------------------------------------------------------------
    // LTP-A-007: ZKBridgeVerifier production-mode locks out MODE_SIMULATED
    // -----------------------------------------------------------------------

    function test_zkverifier_lock_production_requires_admin() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 1); // MODE_SP1
        vm.prank(bob);
        vm.expectRevert(ZKBridgeVerifier.Unauthorized.selector);
        zk.lockProduction();
    }

    function test_zkverifier_lock_production_rejects_when_mode_is_simulated() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 0); // MODE_SIMULATED
        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.SimulatedModeNotAllowedInProduction.selector);
        zk.lockProduction();
    }

    function test_zkverifier_lock_production_locks_and_blocks_switch_back() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 1); // MODE_SP1
        vm.prank(admin);
        zk.lockProduction();
        assertTrue(zk.productionMode());

        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.SimulatedModeNotAllowedInProduction.selector);
        zk.setVerificationMode(0); // MODE_SIMULATED
    }

    // -----------------------------------------------------------------------
    // LTP-A-006: OptimisticBridgeChallenge already supports permissionless
    //            finalizeWindow for unchallenged windows after deadline.
    //            This test pins that behavior so a future "admin-only"
    //            refactor surfaces as a regression.
    // -----------------------------------------------------------------------

    function test_anyone_can_finalize_unchallenged_window() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(
            admin, 1 hours, 1 wei, 1 wei
        );
        bytes32 digest = keccak256("test-anchor");
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);
        // Fast-forward past the challenge deadline.
        vm.warp(block.timestamp + 2 hours);
        // A third party (not the opener, not the admin) finalizes.
        address eve = address(0xEEEE);
        vm.deal(eve, 1 ether);
        vm.prank(eve);
        ch.finalizeWindow(digest);
        assertTrue(ch.isFinalized(digest));
    }

    // -----------------------------------------------------------------------
    // LTP-A-001 Option E: symmetric ZK fraud-proof finalization
    // -----------------------------------------------------------------------

    address constant ZK_VERIFIER = address(0xBEEFCAFE);

    function _openChallenge(uint256 opBond, uint256 chBond)
        internal
        returns (OptimisticBridgeChallenge ch, bytes32 digest)
    {
        ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        ch.setZKVerifier(ZK_VERIFIER);
        digest = keccak256("contested-anchor");

        // Operator opens window.
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: opBond}(digest);

        // Challenger submits.
        address alice = address(0xA11CE);
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        ch.submitChallenge{value: chBond}(digest, 1, keccak256("proof"));
    }

    function test_fraud_proof_finalize_pays_challenger() public {
        uint256 opBond = 1 ether;
        uint256 chBond = 0.5 ether;
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(opBond, chBond);
        address alice = address(0xA11CE);

        uint256 aliceBefore = alice.balance;
        vm.prank(ZK_VERIFIER);
        ch.finalizeWithFraudProof(digest);

        // Challenger receives operator + challenger bonds.
        assertEq(alice.balance - aliceBefore, opBond + chBond);
    }

    function test_fraud_proof_admin_cannot_call() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(1 ether, 0.5 ether);
        vm.prank(admin);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.finalizeWithFraudProof(digest);
    }

    function test_fraud_proof_rejects_unchallenged_window() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        ch.setZKVerifier(ZK_VERIFIER);
        bytes32 digest = keccak256("untouched");

        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);

        // No challenge filed; fraud-proof path must reject.
        vm.prank(ZK_VERIFIER);
        vm.expectRevert(OptimisticBridgeChallenge.WindowNotChallenged.selector);
        ch.finalizeWithFraudProof(digest);
    }

    function test_fraud_proof_arbitrary_caller_rejected() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallenge(1 ether, 0.5 ether);
        vm.prank(address(0xDEAD));
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.finalizeWithFraudProof(digest);
    }

    // -----------------------------------------------------------------------
    // LTP-A-006 Option E: independent arbiter MultiSig + time-decay
    // -----------------------------------------------------------------------

    address constant ARBITER = address(0xA8B17E8);

    function _openChallengeWithArbiter()
        internal
        returns (OptimisticBridgeChallenge ch, bytes32 digest)
    {
        ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        ch.setArbiter(ARBITER);
        digest = keccak256("arbiter-anchor");
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);
        vm.deal(address(0xA11CE), 10 ether);
        vm.prank(address(0xA11CE));
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));
    }

    function test_arbiter_resolves_fraud_pays_challenger() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        address alice = address(0xA11CE);
        uint256 aliceBefore = alice.balance;
        vm.prank(ARBITER);
        ch.resolveChallengeByArbiter(digest, true);
        assertEq(alice.balance - aliceBefore, 1.5 ether);
    }

    function test_arbiter_resolves_dismissal_pays_operator() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        uint256 bobBefore = bob.balance;
        vm.prank(ARBITER);
        ch.resolveChallengeByArbiter(digest, false);
        assertEq(bob.balance - bobBefore, 1.5 ether);
    }

    function test_admin_cannot_call_arbiter_path() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        vm.prank(admin);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.resolveChallengeByArbiter(digest, true);
    }

    function test_arbiter_cannot_equal_admin() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        vm.expectRevert(OptimisticBridgeChallenge.InvalidArbiter.selector);
        ch.setArbiter(admin);
    }

    function test_unset_arbiter_cannot_resolve() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        // arbiter is address(0); even a call from address(0) must reject.
        bytes32 digest = keccak256("no-arbiter");
        vm.deal(bob, 10 ether);
        vm.prank(bob);
        ch.openWindow{value: 1 ether}(digest);
        vm.deal(address(0xA11CE), 10 ether);
        vm.prank(address(0xA11CE));
        ch.submitChallenge{value: 0.5 ether}(digest, 1, keccak256("proof"));
        vm.prank(address(0)); // worst case: someone calls as zero
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        ch.resolveChallengeByArbiter(digest, true);
    }

    function test_time_decay_pays_challenger_after_grace() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        address alice = address(0xA11CE);
        uint256 aliceBefore = alice.balance;
        // Default grace is 14 days; warp past it.
        vm.warp(block.timestamp + 15 days);
        // Anyone (here: a random EOA) can call.
        vm.prank(address(0xCAFEC0DE));
        ch.resolveByTimeDecay(digest);
        assertEq(alice.balance - aliceBefore, 1.5 ether);
    }

    function test_time_decay_rejects_before_grace() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        vm.warp(block.timestamp + 13 days); // < 14 day default
        vm.prank(address(0xCAFEC0DE));
        // ResolutionGraceNotElapsed is a parameterized custom error
        // (uint256 readyAt, uint256 nowAt) so the full revert payload is
        // selector + 64 bytes of args. expectRevert(bytes4) strictly
        // matches the length and fails; expectPartialRevert matches the
        // selector prefix which is the assertion we actually want.
        vm.expectPartialRevert(OptimisticBridgeChallenge.ResolutionGraceNotElapsed.selector);
        ch.resolveByTimeDecay(digest);
    }

    function test_time_decay_grace_floor_enforced() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, 1 hours, 1 wei, 1 wei);
        vm.prank(admin);
        // GracePeriodBelowFloor(uint256 proposed, uint256 floor) — same
        // selector-vs-encoded-args length issue as
        // test_time_decay_rejects_before_grace; use expectPartialRevert.
        vm.expectPartialRevert(OptimisticBridgeChallenge.GracePeriodBelowFloor.selector);
        ch.setResolutionGracePeriod(23 hours); // below 24h floor
    }

    function test_first_resolution_wins_admin_then_arbiter_rejected() public {
        (OptimisticBridgeChallenge ch, bytes32 digest) = _openChallengeWithArbiter();
        // Admin resolves first.
        vm.prank(admin);
        ch.resolveChallenge(digest, false);
        // Arbiter cannot override.
        vm.prank(ARBITER);
        vm.expectRevert(OptimisticBridgeChallenge.WindowNotChallenged.selector);
        ch.resolveChallengeByArbiter(digest, true);
    }

    // -----------------------------------------------------------------------
    // LTP-A-005 Option C-3: owner-signed binding statement + dispute
    // -----------------------------------------------------------------------

    address constant BINDING_VERIFIER = address(0xB1ED181E);

    function _deployRegistry() internal returns (LTPAnchorRegistry reg) {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));
    }

    function _anchorWithBinding(
        LTPAnchorRegistry reg,
        bytes32 entityId,
        bytes32 vkHash,
        bytes32 stmtHash,
        bytes32 sigHash
    ) internal {
        vm.prank(admin);
        reg.registerSigner(vkHash);
        reg.anchorWithBinding(
            keccak256(abi.encode(entityId, vkHash, uint64(1))),
            entityId,
            keccak256("merkle"),
            keccak256("policy"),
            vkHash,
            uint64(1),
            uint64(block.timestamp + 365 days),
            uint8(0),
            stmtHash,
            sigHash
        );
    }

    function test_anchor_with_binding_records_statement() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-1");
        bytes32 vkHash = keccak256("legit-signer");
        bytes32 stmtHash = keccak256("owner-signed-statement");
        bytes32 sigHash = keccak256("ml-dsa-signature");

        _anchorWithBinding(reg, entityId, vkHash, stmtHash, sigHash);

        (bytes32 boundVk, bytes32 stored_stmt, bytes32 stored_sig, uint64 ts, bool disputed)
            = reg.bindingStatements(entityId);
        assertEq(boundVk, vkHash);
        assertEq(stored_stmt, stmtHash);
        assertEq(stored_sig, sigHash);
        assertGt(ts, 0);
        assertFalse(disputed);
        // Entity-signer binding established.
        assertEq(reg.entitySigners(entityId), vkHash);
    }

    function test_anchor_with_zero_binding_hashes_is_legacy_anchor() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-legacy");
        bytes32 vkHash = keccak256("legit-signer");

        _anchorWithBinding(reg, entityId, vkHash, bytes32(0), bytes32(0));

        // Binding still established; statement hashes empty.
        (, bytes32 stored_stmt, bytes32 stored_sig, uint64 ts,) = reg.bindingStatements(entityId);
        assertEq(stored_stmt, bytes32(0));
        assertEq(stored_sig, bytes32(0));
        assertEq(ts, 0); // not recorded when hashes are zero
        assertEq(reg.entitySigners(entityId), vkHash);
    }

    function test_dispute_binding_clears_entity_and_marks_disputed() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-2");
        bytes32 vkHash = keccak256("attacker-signer");
        bytes32 stmtHash = keccak256("forged-statement");
        bytes32 sigHash = keccak256("forged-sig");

        _anchorWithBinding(reg, entityId, vkHash, stmtHash, sigHash);

        vm.prank(admin);
        reg.setBindingDisputeVerifier(BINDING_VERIFIER);

        bytes32 fraudProofHash = keccak256("snark-of-forgery");
        vm.prank(BINDING_VERIFIER);
        reg.disputeBinding(entityId, fraudProofHash);

        (,,,, bool disputed) = reg.bindingStatements(entityId);
        assertTrue(disputed);
        // Entity binding cleared.
        assertEq(reg.entitySigners(entityId), bytes32(0));
    }

    function test_dispute_binding_admin_cannot_call() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-3");
        bytes32 vkHash = keccak256("vk-3");
        _anchorWithBinding(reg, entityId, vkHash, keccak256("s"), keccak256("g"));

        vm.prank(admin);
        reg.setBindingDisputeVerifier(BINDING_VERIFIER);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("NotBindingDisputeVerifier(address)", admin));
        reg.disputeBinding(entityId, keccak256("proof"));
    }

    function test_dispute_binding_rejects_unrecorded_entity() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("never-bound");
        vm.prank(admin);
        reg.setBindingDisputeVerifier(BINDING_VERIFIER);
        vm.prank(BINDING_VERIFIER);
        vm.expectRevert(abi.encodeWithSignature("NoBindingRecorded(bytes32)", entityId));
        reg.disputeBinding(entityId, keccak256("proof"));
    }

    function test_dispute_binding_one_shot() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-4");
        bytes32 vkHash = keccak256("vk-4");
        _anchorWithBinding(reg, entityId, vkHash, keccak256("s"), keccak256("g"));

        vm.prank(admin);
        reg.setBindingDisputeVerifier(BINDING_VERIFIER);

        vm.prank(BINDING_VERIFIER);
        reg.disputeBinding(entityId, keccak256("p1"));

        // Second call must revert.
        vm.prank(BINDING_VERIFIER);
        vm.expectRevert(abi.encodeWithSignature("BindingAlreadyDisputed(bytes32)", entityId));
        reg.disputeBinding(entityId, keccak256("p2"));
    }

    function test_dispute_allows_legitimate_owner_to_rebind() public {
        LTPAnchorRegistry reg = _deployRegistry();
        bytes32 entityId = keccak256("entity-5");
        bytes32 attackerVk = keccak256("attacker-vk");
        bytes32 ownerVk = keccak256("legit-owner-vk");

        // Attacker squats first.
        _anchorWithBinding(reg, entityId, attackerVk, keccak256("forged-s"), keccak256("forged-g"));
        assertEq(reg.entitySigners(entityId), attackerVk);

        // Legitimate owner produces SNARK proof of forgery; verifier acts.
        vm.prank(admin);
        reg.setBindingDisputeVerifier(BINDING_VERIFIER);
        vm.prank(BINDING_VERIFIER);
        reg.disputeBinding(entityId, keccak256("snark-of-forgery"));

        // Owner re-binds with the correct signer + statement.
        _anchorWithBinding(reg, entityId, ownerVk, keccak256("real-statement"), keccak256("real-sig"));
        assertEq(reg.entitySigners(entityId), ownerVk);
    }
}
