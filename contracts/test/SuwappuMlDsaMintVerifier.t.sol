// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuMlDsaMintVerifier} from "../src/verifiers/SuwappuMlDsaMintVerifier.sol";

/// @notice Parity hygiene (P9): the ML-DSA verifier must RETURN FALSE on a
///         malformed attestation encoding rather than revert — matching the
///         ECDSA verifier — so a bad attestation fails the mint cleanly.
contract SuwappuMlDsaMintVerifierTest is Test {
    SuwappuMlDsaMintVerifier verifier;
    address admin = makeAddr("admin");
    bytes32 constant DIGEST = keccak256("digest");

    function setUp() public {
        verifier = new SuwappuMlDsaMintVerifier(admin);
    }

    function test_ReturnsFalse_OnUndecodableAttestation() public view {
        // Not a valid abi.encode(bytes,bytes): would revert a raw abi.decode.
        bool ok = verifier.verifyMintAttestation(DIGEST, hex"deadbeef");
        assertFalse(ok);
    }

    function test_ReturnsFalse_OnEmptyAttestation() public view {
        assertFalse(verifier.verifyMintAttestation(DIGEST, ""));
    }

    function test_ReturnsFalse_OnWrongLengthFields() public view {
        // Well-formed (bytes,bytes) but wrong ML-DSA sizes → false (not revert).
        bytes memory att = abi.encode(bytes("short-pubkey"), bytes("short-sig"));
        assertFalse(verifier.verifyMintAttestation(DIGEST, att));
    }

    function test_ReturnsFalse_OnUnauthorizedKey_CorrectSizes() public view {
        // Correct sizes but the key is not authorized → false before precompile.
        bytes memory pk = new bytes(verifier.PK_LEN());
        bytes memory sig = new bytes(verifier.SIG_LEN());
        assertFalse(verifier.verifyMintAttestation(DIGEST, abi.encode(pk, sig)));
    }
}
