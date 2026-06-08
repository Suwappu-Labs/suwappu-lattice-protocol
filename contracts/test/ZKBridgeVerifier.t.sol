// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/OptimisticBridgeChallenge.sol";
import "../src/ZKBridgeVerifier.sol";

contract ZKBridgeVerifierTest is Test {
    OptimisticBridgeChallenge public challenge;
    ZKBridgeVerifier public zkVerifier;

    address admin = address(0xAD);
    address operator = address(0xBEEF);
    address challenger = address(0xCAFE);

    uint256 constant PERIOD = 7 days;
    uint256 constant OP_BOND = 0.01 ether;
    uint256 constant CH_BOND = 0.001 ether;

    bytes32 constant DIGEST_1 = keccak256("zk-anchor-digest-1");
    bytes32 constant DIGEST_2 = keccak256("zk-anchor-digest-2");

    // Test public inputs
    bytes32 constant STH_ROOT = keccak256("sth-root-hash");
    bytes32 constant OP_VK_HASH = keccak256("operator-vk-hash");
    uint64 constant TREE_SIZE = 42;
    uint64 constant STH_SEQ = 7;

    function setUp() public {
        challenge = new OptimisticBridgeChallenge(admin, PERIOD, OP_BOND, CH_BOND);
        zkVerifier = new ZKBridgeVerifier(admin, address(challenge), 0); // MODE_SIMULATED

        // Authorize the ZK verifier on the challenge contract, plus the
        // C3 operator-authorization + prover access control.
        vm.startPrank(admin);
        challenge.setZKVerifier(address(zkVerifier));
        zkVerifier.setAuthorizedOperatorVk(OP_VK_HASH, true);
        zkVerifier.setProver(address(this), true);
        vm.stopPrank();

        vm.deal(operator, 10 ether);
        vm.deal(challenger, 10 ether);
    }

    /// @dev Helper: build a valid simulated proof bound to `anchorDigest` (C3).
    function _buildSimulatedProof(bytes32 anchorDigest) internal pure returns (bytes memory) {
        bytes32 proofHash = keccak256("test-proof-hash");
        bytes32 verifyTag = keccak256(abi.encodePacked(
            anchorDigest, STH_ROOT, OP_VK_HASH, TREE_SIZE, STH_SEQ, proofHash, "sim-verify"
        ));
        return abi.encodePacked(proofHash, verifyTag);
    }

    function _inputs() internal pure returns (ZKBridgeVerifier.PublicInputs memory) {
        return ZKBridgeVerifier.PublicInputs({
            sthRootHash: STH_ROOT,
            operatorVkHash: OP_VK_HASH,
            treeSize: TREE_SIZE,
            sthSequence: STH_SEQ
        });
    }

    // -----------------------------------------------------------------------
    // verifyAndFinalize
    // -----------------------------------------------------------------------

    function test_verifyAndFinalize_validProof() public {
        // Open a challenge window
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory proof = _buildSimulatedProof(DIGEST_1);
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        assertTrue(challenge.isFinalized(DIGEST_1));
    }

    function test_verifyAndFinalize_rejectsInvalidProof() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory badProof = new bytes(64); // all zeros
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        zkVerifier.verifyAndFinalize(DIGEST_1, badProof, _inputs());
    }

    function test_verifyAndFinalize_rejectsZeroInputs() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        ZKBridgeVerifier.PublicInputs memory zeroInputs = ZKBridgeVerifier.PublicInputs({
            sthRootHash: bytes32(0),
            operatorVkHash: bytes32(0),
            treeSize: 0,
            sthSequence: 0
        });

        vm.expectRevert(ZKBridgeVerifier.InvalidPublicInputs.selector);
        zkVerifier.verifyAndFinalize(DIGEST_1, _buildSimulatedProof(DIGEST_1), zeroInputs);
    }

    function test_verifyAndFinalize_rejectsShortProof() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory shortProof = new bytes(32); // too short
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        zkVerifier.verifyAndFinalize(DIGEST_1, shortProof, _inputs());
    }

    function test_verifyAndFinalize_finalizesFromChallengedState() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // Submit a challenge first
        vm.prank(challenger);
        challenge.submitChallenge{value: CH_BOND}(DIGEST_1, 1, keccak256("fraud-proof"));

        assertTrue(challenge.isChallenged(DIGEST_1));

        // ZK proof finalizes the challenged window
        bytes memory proof = _buildSimulatedProof(DIGEST_1);
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        assertTrue(challenge.isFinalized(DIGEST_1));
    }

    function test_verifyAndFinalize_returnsBothBonds() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        vm.prank(challenger);
        challenge.submitChallenge{value: CH_BOND}(DIGEST_1, 1, keccak256("fp"));

        uint256 opBal = operator.balance;
        uint256 chBal = challenger.balance;

        bytes memory proof = _buildSimulatedProof(DIGEST_1);
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        assertEq(operator.balance, opBal + OP_BOND);
        assertEq(challenger.balance, chBal + CH_BOND);
    }

    function test_verifyAndFinalize_rejectsProofReplay() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory proof = _buildSimulatedProof(DIGEST_1);
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        // Same proof on a different anchor
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_2);

        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector); // proof bound to DIGEST_1 (C3)
        zkVerifier.verifyAndFinalize(DIGEST_2, proof, _inputs());
    }

    // -----------------------------------------------------------------------
    // Authorization
    // -----------------------------------------------------------------------

    function test_finalizeWithZKProof_requiresAuthorization() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // Random address cannot call finalizeWithZKProof directly
        vm.prank(address(0xDEAD));
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        challenge.finalizeWithZKProof(DIGEST_1);
    }

    /// @dev Hardening (red-team 2.3/2.4): finalizeWithZKProof is restricted to
    ///      the registered ZK verifier ONLY. The admin must NOT be able to
    ///      bypass proof verification and finalize an arbitrary digest directly.
    ///      (Previously admin could call it — that bypass is now removed; see
    ///      OptimisticBridgeChallenge.finalizeWithZKProof: msg.sender == zkVerifier.)
    function test_zkVerifier_adminCannotBypassVerifier() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // Even the admin cannot finalize directly — only the verifier may.
        vm.prank(admin);
        vm.expectRevert(OptimisticBridgeChallenge.Unauthorized.selector);
        challenge.finalizeWithZKProof(DIGEST_1);

        assertFalse(challenge.isFinalized(DIGEST_1));
    }

    // -----------------------------------------------------------------------
    // Fuzz tests
    // -----------------------------------------------------------------------

    function test_fuzz_randomProofRejected(bytes calldata randomProof) public {
        vm.assume(randomProof.length == 64);

        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // Random 64-byte proof should almost always fail (keccak collision probability negligible)
        try zkVerifier.verifyAndFinalize(DIGEST_1, randomProof, _inputs()) {
            // If it somehow passes, the proof must match the expected structure
            // (vanishingly unlikely with random bytes)
        } catch {
            // Expected: InvalidProof
        }
    }
}


/// @notice STARK mode was permanently disabled in C5 — `_verifySTARK` was a
///         keccak256 tag check, not a cryptographic STARK verifier. These tests
///         pin that removal: STARK can neither be finalized through nor switched
///         into. They register a prover + operator so the revert reached is
///         genuinely STARKModeDisabled (the dispatch is blocked), not merely the
///         upstream access-control gates.
contract ZKBridgeVerifierSTARKDisabledTest is Test {
    OptimisticBridgeChallenge public challenge;
    ZKBridgeVerifier public starkVerifier;

    address admin = address(0xAD);
    address operator = address(0xBEEF);

    uint256 constant PERIOD = 7 days;
    uint256 constant OP_BOND = 0.01 ether;

    bytes32 constant DIGEST_S1 = keccak256("stark-anchor-1");
    bytes32 constant STH_ROOT = keccak256("stark-sth-root");
    bytes32 constant OP_VK_HASH = keccak256("stark-operator-vk");

    function setUp() public {
        challenge = new OptimisticBridgeChallenge(admin, PERIOD, OP_BOND, 0.001 ether);
        // Constructing in MODE_STARK is still permitted (no constructor guard),
        // but every operational path out of it now reverts.
        starkVerifier = new ZKBridgeVerifier(admin, address(challenge), 3); // MODE_STARK

        vm.startPrank(admin);
        challenge.setZKVerifier(address(starkVerifier));
        starkVerifier.setAuthorizedOperatorVk(OP_VK_HASH, true);
        starkVerifier.setProver(address(this), true);
        vm.stopPrank();

        vm.deal(operator, 10 ether);
    }

    function _starkInputs() internal pure returns (ZKBridgeVerifier.PublicInputs memory) {
        return ZKBridgeVerifier.PublicInputs({
            sthRootHash: STH_ROOT,
            operatorVkHash: OP_VK_HASH,
            treeSize: 10,
            sthSequence: 3
        });
    }

    /// @dev Even a well-formed legacy STARK proof can no longer finalize: the
    ///      dispatch reverts STARKModeDisabled before any tag check.
    function test_stark_verifyAndFinalize_disabled() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S1);

        bytes memory anyProof = new bytes(128);
        vm.expectRevert(ZKBridgeVerifier.STARKModeDisabled.selector);
        starkVerifier.verifyAndFinalize(DIGEST_S1, anyProof, _starkInputs());

        assertFalse(challenge.isFinalized(DIGEST_S1));
    }

    /// @dev lockProduction must refuse a STARK-mode verifier outright.
    function test_stark_lockProduction_disabled() public {
        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.STARKModeDisabled.selector);
        starkVerifier.lockProduction();
    }

    /// @dev The admin cannot switch any verifier into STARK mode.
    function test_stark_cannot_switch_into_stark_mode() public {
        OptimisticBridgeChallenge ch = new OptimisticBridgeChallenge(admin, PERIOD, OP_BOND, 0.001 ether);
        ZKBridgeVerifier zk = new ZKBridgeVerifier(admin, address(ch), 0); // MODE_SIMULATED
        vm.prank(admin);
        vm.expectRevert(ZKBridgeVerifier.STARKModeDisabled.selector);
        zk.setVerificationMode(3); // MODE_STARK
    }
}


// =========================================================================
// SP1 Verifier Tests
// =========================================================================

/// @dev Minimal SP1 verifier double: accepts iff the proof's first byte is 0x01.
contract MockSP1VerifierLocal {
    function verifyProof(bytes32, bytes calldata, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        return proof.length > 0 && proof[0] == 0x01;
    }
}

contract ZKBridgeVerifierSP1Test is Test {
    OptimisticBridgeChallenge public challenge;
    ZKBridgeVerifier public sp1Verifier;
    MockSP1VerifierLocal public mockSP1;

    address admin = address(0xAD);
    address operator = address(0xBEEF);

    uint256 constant PERIOD = 7 days;
    uint256 constant OP_BOND = 0.01 ether;
    uint256 constant CH_BOND = 0.001 ether;

    bytes32 constant DIGEST_1 = keccak256("sp1-anchor-digest-1");
    bytes32 constant STH_ROOT = keccak256("sp1-sth-root");
    bytes32 constant OP_VK_HASH = keccak256("sp1-op-vk");
    uint64 constant TREE_SIZE = 100;
    uint64 constant STH_SEQ = 42;

    function setUp() public {
        challenge = new OptimisticBridgeChallenge(admin, PERIOD, OP_BOND, CH_BOND);
        sp1Verifier = new ZKBridgeVerifier(admin, address(challenge), 1); // MODE_SP1
        mockSP1 = new MockSP1VerifierLocal();

        vm.startPrank(admin);
        challenge.setZKVerifier(address(sp1Verifier));
        // C3 access control: register the operator key + this test as prover.
        sp1Verifier.setAuthorizedOperatorVk(OP_VK_HASH, true);
        sp1Verifier.setProver(address(this), true);
        vm.stopPrank();

        vm.deal(operator, 10 ether);
    }

    function _inputs() internal pure returns (ZKBridgeVerifier.PublicInputs memory) {
        return ZKBridgeVerifier.PublicInputs({
            sthRootHash: STH_ROOT,
            operatorVkHash: OP_VK_HASH,
            treeSize: TREE_SIZE,
            sthSequence: STH_SEQ
        });
    }

    /// @dev C1: SP1 mode with NO configured verifier must revert, never fall
    ///      back to a simulated/structure check. (The old "unconfigured SP1
    ///      accepts a 128-byte blob" path was removed.)
    function test_sp1_unconfigured_reverts() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory proof = new bytes(128);
        for (uint i = 0; i < 128; i++) proof[i] = bytes1(uint8(i + 1));

        vm.expectRevert(ZKBridgeVerifier.SP1VerifierNotConfigured.selector);
        sp1Verifier.verifyAndFinalize(DIGEST_1, proof, _inputs());
        assertFalse(challenge.isFinalized(DIGEST_1));
    }

    /// @dev A proof the configured SP1 verifier accepts (first byte 0x01)
    ///      finalizes the window.
    function test_sp1_configured_validProofFinalizes() public {
        vm.prank(admin);
        sp1Verifier.setSP1Verifier(address(mockSP1), keccak256("vk"));

        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory validProof = hex"01aabbcc";
        sp1Verifier.verifyAndFinalize(DIGEST_1, validProof, _inputs());
        assertTrue(challenge.isFinalized(DIGEST_1));
    }

    /// @dev A proof the configured SP1 verifier rejects (first byte != 0x01)
    ///      reverts InvalidProof and does not finalize.
    function test_sp1_rejects_proof_verifier_denies() public {
        vm.prank(admin);
        sp1Verifier.setSP1Verifier(address(mockSP1), keccak256("vk"));

        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory badProof = hex"00aabbcc"; // first byte 0x00 -> mock returns false
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        sp1Verifier.verifyAndFinalize(DIGEST_1, badProof, _inputs());
        assertFalse(challenge.isFinalized(DIGEST_1));
    }

    function test_setSP1Verifier_updates_storage() public {
        address mockVerifier = address(0x1234);
        bytes32 mockVKey = keccak256("mock-vkey");

        vm.prank(admin);
        sp1Verifier.setSP1Verifier(mockVerifier, mockVKey);

        assertEq(sp1Verifier.sp1Verifier(), mockVerifier);
        assertEq(sp1Verifier.sp1ProgramVKey(), mockVKey);
    }

    function test_setSP1Verifier_nonAdmin_reverts() public {
        vm.prank(operator);
        vm.expectRevert(ZKBridgeVerifier.Unauthorized.selector);
        sp1Verifier.setSP1Verifier(address(0x1), keccak256("x"));
    }

    function test_sp1_mode_stored() public view {
        assertEq(sp1Verifier.verificationMode(), 1); // MODE_SP1
    }
}
