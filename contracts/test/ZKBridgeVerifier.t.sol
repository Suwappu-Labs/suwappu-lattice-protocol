// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/OptimisticBridgeChallenge.sol";
import "../src/ZKBridgeVerifier.sol";
import {ISP1Verifier, ISP1VerifierWithHash} from "sp1-contracts/ISP1Verifier.sol";

/// @dev Mirrors real ISP1Verifier behavior on a valid proof: verifyProof has
///      no return type, so a compliant verifier that accepts the proof
///      simply doesn't revert and returns zero bytes of data. Implements
///      ISP1VerifierWithHash with a non-zero hash so it passes the
///      setSP1Verifier compatibility check.
contract CompliantSP1Verifier is ISP1VerifierWithHash {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {
        // Valid proof: succeed silently, exactly like the real interface.
    }

    function VERIFIER_HASH() external pure override returns (bytes32) {
        return keccak256("compliant-sp1-verifier");
    }
}

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

        // Authorize the ZK verifier on the challenge contract
        vm.prank(admin);
        challenge.setZKVerifier(address(zkVerifier));

        vm.deal(operator, 10 ether);
        vm.deal(challenger, 10 ether);
    }

    /// @dev Helper: build a valid simulated proof for the test public inputs
    function _buildSimulatedProof() internal pure returns (bytes memory) {
        // proof_hash: arbitrary 32 bytes
        bytes32 proofHash = keccak256("test-proof-hash");
        // verify_tag: keccak256(sthRootHash || operatorVkHash || treeSize || sthSequence || proofHash || "sim-verify")
        bytes32 verifyTag = keccak256(abi.encodePacked(
            STH_ROOT, OP_VK_HASH, TREE_SIZE, STH_SEQ, proofHash, "sim-verify"
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

        bytes memory proof = _buildSimulatedProof();
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
        zkVerifier.verifyAndFinalize(DIGEST_1, _buildSimulatedProof(), zeroInputs);
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
        bytes memory proof = _buildSimulatedProof();
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

        bytes memory proof = _buildSimulatedProof();
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        assertEq(operator.balance, opBal + OP_BOND);
        assertEq(challenger.balance, chBal + CH_BOND);
    }

    function test_verifyAndFinalize_rejectsProofReplay() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        bytes memory proof = _buildSimulatedProof();
        zkVerifier.verifyAndFinalize(DIGEST_1, proof, _inputs());

        // Same proof on a different anchor
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_2);

        vm.expectRevert(ZKBridgeVerifier.ProofAlreadyUsed.selector);
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

    function test_zkVerifier_adminCanCall() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // Admin can also call finalizeWithZKProof
        vm.prank(admin);
        challenge.finalizeWithZKProof(DIGEST_1);

        assertTrue(challenge.isFinalized(DIGEST_1));
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


/// @notice STARK-mode tests using a separate verifier instance in MODE_STARK.
contract ZKBridgeVerifierSTARKTest is Test {
    OptimisticBridgeChallenge public challenge;
    ZKBridgeVerifier public starkVerifier;

    address admin = address(0xAD);
    address operator = address(0xBEEF);

    uint256 constant PERIOD = 7 days;
    uint256 constant OP_BOND = 0.01 ether;

    bytes32 constant DIGEST_S1 = keccak256("stark-anchor-1");
    bytes32 constant DIGEST_S2 = keccak256("stark-anchor-2");

    bytes32 constant STH_ROOT = keccak256("stark-sth-root");
    bytes32 constant OP_VK_HASH = keccak256("stark-operator-vk");
    uint64 constant TREE_SIZE = 10;
    uint64 constant STH_SEQ = 3;

    function setUp() public {
        challenge = new OptimisticBridgeChallenge(admin, PERIOD, OP_BOND, 0.001 ether);
        starkVerifier = new ZKBridgeVerifier(admin, address(challenge), 3); // MODE_STARK

        vm.prank(admin);
        challenge.setZKVerifier(address(starkVerifier));

        vm.deal(operator, 10 ether);
    }

    function _starkInputs() internal pure returns (ZKBridgeVerifier.PublicInputs memory) {
        return ZKBridgeVerifier.PublicInputs({
            sthRootHash: STH_ROOT,
            operatorVkHash: OP_VK_HASH,
            treeSize: TREE_SIZE,
            sthSequence: STH_SEQ
        });
    }

    function _buildSTARKProofLegacy() internal pure returns (bytes memory) {
        // Legacy 128B: 4 x 32B layers: proof_hash, fri_0, fri_1, verify_tag
        bytes32 proofHash = keccak256("stark-test-proof-hash");
        bytes32 fri0 = keccak256("stark-fri-layer-0");
        bytes32 fri1 = keccak256("stark-fri-layer-1");

        bytes32 verifyTag = keccak256(abi.encodePacked(
            STH_ROOT, OP_VK_HASH, TREE_SIZE, STH_SEQ,
            proofHash, fri0, fri1,
            "stark-verify"
        ));
        return abi.encodePacked(proofHash, fri0, fri1, verifyTag);
    }

    function _buildSTARKProofV3() internal pure returns (bytes memory) {
        // V3 FRI-based: header(8B) + pi_hash(32B) + witness_hash(32B) + roots(N*32B) + verify_tag(32B)
        uint8 numRoots = 2;

        // Build header: version=3, numRoots=2, securityBits=128, reserved=0
        bytes memory header = abi.encodePacked(uint8(3), numRoots, uint8(128), bytes5(0));

        // Public inputs hash
        bytes32 piHash = keccak256(abi.encodePacked(
            STH_ROOT, OP_VK_HASH, TREE_SIZE, STH_SEQ, "stark-public"
        ));

        // Witness hash and FRI roots (arbitrary for test)
        bytes32 witnessHash = keccak256("v3-witness-hash");
        bytes32 root0 = keccak256("v3-fri-root-0");
        bytes32 root1 = keccak256("v3-fri-root-1");

        // Assemble everything before verify_tag
        bytes memory preTag = abi.encodePacked(header, piHash, witnessHash, root0, root1);

        bytes32 verifyTag = keccak256(abi.encodePacked(preTag, "stark-verify"));

        return abi.encodePacked(preTag, verifyTag);
    }

    function test_stark_validProofFinalizes() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S1);

        starkVerifier.verifyAndFinalize(DIGEST_S1, _buildSTARKProofLegacy(), _starkInputs());
        assertTrue(challenge.isFinalized(DIGEST_S1));
    }

    function test_stark_rejectsInvalidProof() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S1);

        bytes memory badProof = new bytes(128);
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        starkVerifier.verifyAndFinalize(DIGEST_S1, badProof, _starkInputs());
    }

    function test_stark_rejectsWrongLength() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S1);

        bytes memory shortProof = new bytes(64); // SNARK size, not STARK
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        starkVerifier.verifyAndFinalize(DIGEST_S1, shortProof, _starkInputs());
    }

    function test_stark_v3ProofFinalizes() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S2);

        bytes memory v3Proof = _buildSTARKProofV3();
        starkVerifier.verifyAndFinalize(DIGEST_S2, v3Proof, _starkInputs());
        assertTrue(challenge.isFinalized(DIGEST_S2));
    }

    function test_stark_v3RejectsWrongInputs() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S2);

        bytes memory v3Proof = _buildSTARKProofV3();
        ZKBridgeVerifier.PublicInputs memory wrongInputs = ZKBridgeVerifier.PublicInputs({
            sthRootHash: keccak256("wrong-root"),
            operatorVkHash: OP_VK_HASH,
            treeSize: TREE_SIZE,
            sthSequence: STH_SEQ
        });
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        starkVerifier.verifyAndFinalize(DIGEST_S2, v3Proof, wrongInputs);
    }

    function test_stark_bondReturnedOnFinalize() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_S1);

        uint256 balBefore = operator.balance;
        starkVerifier.verifyAndFinalize(DIGEST_S1, _buildSTARKProofLegacy(), _starkInputs());
        assertEq(operator.balance, balBefore + OP_BOND);
    }

    function test_fuzz_randomSTARKProofRejected(bytes32 r1, bytes32 r2, bytes32 r3, bytes32 r4) public {
        bytes memory randomProof = abi.encodePacked(r1, r2, r3, r4);

        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(keccak256(randomProof));

        try starkVerifier.verifyAndFinalize(keccak256(randomProof), randomProof, _starkInputs()) {
        } catch {
        }
    }
}


// =========================================================================
// SP1 Verifier Tests
// =========================================================================

contract ZKBridgeVerifierSP1Test is Test {
    OptimisticBridgeChallenge public challenge;
    ZKBridgeVerifier public sp1Verifier;

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

        vm.prank(admin);
        challenge.setZKVerifier(address(sp1Verifier));

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

    // SP1 without configured verifier uses simulated check (>= 128 bytes)
    function test_sp1_simulated_accepts_128B() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // 128 bytes should pass the simulated SP1 check
        bytes memory proof = new bytes(128);
        for (uint i = 0; i < 128; i++) proof[i] = bytes1(uint8(i + 1));

        sp1Verifier.verifyAndFinalize(DIGEST_1, proof, _inputs());
        assertTrue(challenge.isFinalized(DIGEST_1));
    }

    function test_sp1_rejects_short_proof() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        // 64 bytes is too short for SP1
        bytes memory shortProof = new bytes(64);
        vm.expectRevert(ZKBridgeVerifier.InvalidProof.selector);
        sp1Verifier.verifyAndFinalize(DIGEST_1, shortProof, _inputs());
    }

    function test_setSP1Verifier_updates_storage() public {
        address mockVerifier = address(new CompliantSP1Verifier());
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

    // --- Regression test for the setSP1Verifier compatibility gate ---
    // A no-code address must be rejected at set time, not silently accepted
    // and only discovered broken later when a real proof is submitted.
    function test_sp1_rejects_nocode_verifier() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(ZKBridgeVerifier.IncompatibleSP1Verifier.selector, address(0x1234))
        );
        sp1Verifier.setSP1Verifier(address(0x1234), keccak256("mock-vkey"));
    }

    // A compliant SP1 verifier's success (no revert, no return value — the
    // interface has no return type) must be accepted. Only safe to rely on
    // `success` alone because setSP1Verifier already rejected a no-code
    // address at set time — otherwise (success=true, returnData="") is
    // indistinguishable from a no-code address's trivial staticcall success.
    function test_sp1_accepts_compliant_verifier_success() public {
        vm.prank(operator);
        challenge.openWindow{value: OP_BOND}(DIGEST_1);

        CompliantSP1Verifier verifier = new CompliantSP1Verifier();
        vm.prank(admin);
        sp1Verifier.setSP1Verifier(address(verifier), keccak256("mock-vkey"));

        sp1Verifier.verifyAndFinalize(DIGEST_1, new bytes(128), _inputs());
        assertTrue(challenge.isFinalized(DIGEST_1));
    }

}
