// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuThresholdMintVerifier} from "../src/verifiers/SuwappuThresholdMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice Unit suite for the k-of-N ECDSA threshold mint verifier.
///         Covers quorum acceptance, every rejection path (below-threshold,
///         duplicate signer, out-of-order, unauthorized signer, wrong digest),
///         malformed-input no-revert parity (mirrors SuwappuMlDsaMintVerifierTest),
///         and the governance invariants (K != 0, K <= N, fail-closed removal).
contract SuwappuThresholdMintVerifierTest is Test {
    SuwappuThresholdMintVerifier internal verifier;

    address internal admin = makeAddr("admin");
    bytes32 internal constant DIGEST = keccak256("mint-digest");

    // Three operator keys. Addresses are derived in setUp and used to authorize.
    uint256 internal pk1 = 0xA11CE;
    uint256 internal pk2 = 0xB0B;
    uint256 internal pk3 = 0xCA710;
    // A fourth, unauthorized key (valid sig, not in the operator set).
    uint256 internal pkRogue = 0xBADBAD;

    function setUp() public {
        verifier = new SuwappuThresholdMintVerifier(admin, 2); // K = 2

        vm.startPrank(admin);
        verifier.setOperator(vm.addr(pk1), true);
        verifier.setOperator(vm.addr(pk2), true);
        verifier.setOperator(vm.addr(pk3), true); // N = 3
        vm.stopPrank();
    }

    // ---- sig helpers ----

    /// @dev One 65-byte ECDSA sig over the EIP-191 hash of `digest`.
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev In-place ascending sort of pks by resulting signer address.
    function _sortByAddress(uint256[] memory pks) internal pure {
        for (uint256 i = 0; i < pks.length; i++) {
            for (uint256 j = i + 1; j < pks.length; j++) {
                if (vm.addr(pks[j]) < vm.addr(pks[i])) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
    }

    /// @dev Build abi.encode(bytes[] sigs) with sigs in strictly increasing
    ///      signer-address order over `digest`.
    function _attestation(uint256[] memory pks, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        _sortByAddress(pks);
        bytes[] memory sigs = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sigs[i] = _sign(pks[i], digest);
        }
        return abi.encode(sigs);
    }

    // ---- acceptance ----

    function test_Happy_2of3() public view {
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
        assertTrue(verifier.verifyMintAttestation(DIGEST, _attestation(pks, DIGEST)));
    }

    function test_Happy_3of3() public view {
        uint256[] memory pks = new uint256[](3);
        pks[0] = pk1;
        pks[1] = pk2;
        pks[2] = pk3;
        assertTrue(verifier.verifyMintAttestation(DIGEST, _attestation(pks, DIGEST)));
    }

    // ---- rejection paths ----

    function test_BelowThreshold_False() public view {
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk1; // only 1 sig, K = 2
        assertFalse(verifier.verifyMintAttestation(DIGEST, _attestation(pks, DIGEST)));
    }

    function test_DuplicateSigner_False() public view {
        // Same signer twice: violates strictly-increasing order (equal address).
        bytes memory s = _sign(pk1, DIGEST);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = s;
        sigs[1] = s;
        assertFalse(verifier.verifyMintAttestation(DIGEST, abi.encode(sigs)));
    }

    function test_OutOfOrder_False() public view {
        // Two valid authorized sigs in DESCENDING address order → rejected on
        // the second element before the quorum is reached.
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
        _sortByAddress(pks); // ascending
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(pks[1], DIGEST); // higher address first → descending
        sigs[1] = _sign(pks[0], DIGEST);
        assertFalse(verifier.verifyMintAttestation(DIGEST, abi.encode(sigs)));
    }

    function test_UnauthorizedDoesNotCount_False() public view {
        // One authorized + one unauthorized (rogue) signer, ordered correctly:
        // decode/order pass but only 1 counts toward K = 2 → false.
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pkRogue;
        assertFalse(verifier.verifyMintAttestation(DIGEST, _attestation(pks, DIGEST)));
    }

    function test_WrongDigest_False() public view {
        // Sigs are over a DIFFERENT digest than the one being verified: the
        // recovered addresses won't match the operator set → false.
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
        bytes memory att = _attestation(pks, keccak256("other-digest"));
        assertFalse(verifier.verifyMintAttestation(DIGEST, att));
    }

    // ---- malformed input returns false with NO revert (ML-DSA parity) ----

    function test_ReturnsFalse_OnRandomBytes() public view {
        assertFalse(verifier.verifyMintAttestation(DIGEST, hex"deadbeef"));
    }

    function test_ReturnsFalse_OnEmptyAttestation() public view {
        assertFalse(verifier.verifyMintAttestation(DIGEST, ""));
    }

    function test_ReturnsFalse_OnShortElement() public view {
        // Well-formed bytes[] but one element is 10 bytes (not 65) → false in
        // the loop, no revert.
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(pk1, DIGEST);
        sigs[1] = new bytes(10);
        assertFalse(verifier.verifyMintAttestation(DIGEST, abi.encode(sigs)));
    }

    // ---- constructor / threshold governance ----

    function test_Constructor_ZeroThreshold_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuThresholdMintVerifier.InvalidThreshold.selector, 0, 0)
        );
        new SuwappuThresholdMintVerifier(admin, 0);
    }

    function test_Constructor_ZeroAdmin_Reverts() public {
        vm.expectRevert(SuwappuThresholdMintVerifier.ZeroAddress.selector);
        new SuwappuThresholdMintVerifier(address(0), 1);
    }

    function test_SetThreshold_Zero_Reverts() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuThresholdMintVerifier.InvalidThreshold.selector, 0, 3)
        );
        verifier.setThreshold(0);
    }

    function test_SetThreshold_GreaterThanN_Reverts() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuThresholdMintVerifier.InvalidThreshold.selector, 4, 3)
        );
        verifier.setThreshold(4); // N = 3
    }

    function test_SetThreshold_Valid() public {
        vm.prank(admin);
        verifier.setThreshold(3);
        assertEq(verifier.threshold(), 3);
    }

    // ---- operator removal fail-closed ----

    function test_RemovalDroppingBelowThreshold_Reverts() public {
        // N = 3, K = 2. Removing one operator leaves N = 2 (ok). Removing a
        // second would leave N = 1 < K = 2 → revert.
        vm.startPrank(admin);
        verifier.setOperator(vm.addr(pk3), false); // N = 2, still >= K
        assertEq(verifier.operatorCount(), 2);

        vm.expectRevert(
            abi.encodeWithSelector(SuwappuThresholdMintVerifier.InvalidThreshold.selector, 2, 1)
        );
        verifier.setOperator(vm.addr(pk2), false); // would make N = 1 < K = 2
        vm.stopPrank();

        // Count is unchanged by the reverted call.
        assertEq(verifier.operatorCount(), 2);
    }

    // ---- governance rotate keeps operatorCount exact ----

    function test_Rotate_KeepsOperatorCountExact() public {
        // N = 3, K = 2. Rotate pk3 -> pkRogue's address: remove one (N=2, ok),
        // add a fresh one (N=3). Count must be exact and idempotent no-ops
        // must not perturb it.
        address opA = vm.addr(pk3);
        address opNew = vm.addr(pkRogue);

        vm.startPrank(admin);
        assertEq(verifier.operatorCount(), 3);

        verifier.setOperator(opA, false); // N = 2
        assertEq(verifier.operatorCount(), 2);

        verifier.setOperator(opNew, true); // N = 3
        assertEq(verifier.operatorCount(), 3);

        // Idempotent no-ops: count unchanged.
        verifier.setOperator(opNew, true); // already authorized
        assertEq(verifier.operatorCount(), 3);
        verifier.setOperator(opA, false); // already removed
        assertEq(verifier.operatorCount(), 3);
        vm.stopPrank();

        assertTrue(verifier.isOperator(opNew));
        assertFalse(verifier.isOperator(opA));
    }

    function test_SetOperator_OnlyAdmin() public {
        vm.expectRevert(SuwappuThresholdMintVerifier.Unauthorized.selector);
        verifier.setOperator(makeAddr("intruder"), true);
    }
}
