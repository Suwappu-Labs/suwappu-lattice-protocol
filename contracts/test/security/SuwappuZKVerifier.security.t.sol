// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKBridgeVerifier} from "../../src/ZKBridgeVerifier.sol";
import {OptimisticBridgeChallenge} from "../../src/OptimisticBridgeChallenge.sol";

/// @title SuwappuZKVerifier.security.t.sol
/// @notice Deterministic regression proofs for ZKBridgeVerifier findings C3/C4
///         (audit program P1/P3). Secure-property tests: RED on current code,
///         GREEN only after the P7 fixes land.
///
///   C3 INV-ZK-BIND  — verifyAndFinalize has no access control AND never binds
///                     anchorDigest to the proof's public inputs, so any caller
///                     finalizes any digest with a proof attesting to something else.
///   C4 INV-SP1-CODE — _verifySP1 staticcall to a code-less verifier returns
///                     (true, "") so every proof is accepted.

/// @dev A "real" SP1 verifier that only accepts proofs whose first byte is 0x01.
///      Used to show C3 is independent of the simulated-mode forgery (LTP-A-007):
///      even a genuinely-verified proof finalizes an unrelated, attacker-named digest.
contract MockSP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        return proof.length > 0 && proof[0] == 0x01;
    }
}

contract SuwappuZKVerifierSecurityTest is Test {
    uint8 internal constant MODE_SP1 = 1;
    address internal constant ADMIN = address(0xA1);
    address internal operator = makeAddr("operator");
    address internal attacker = makeAddr("attacker");

    OptimisticBridgeChallenge internal challenge;
    ZKBridgeVerifier internal verifier;

    function _setup(address sp1Verifier) internal {
        challenge = new OptimisticBridgeChallenge(ADMIN, 1 hours, 1 ether, 0.5 ether);
        verifier = new ZKBridgeVerifier(ADMIN, address(challenge), MODE_SP1);
        vm.startPrank(ADMIN);
        challenge.setZKVerifier(address(verifier));
        verifier.setSP1Verifier(sp1Verifier, keccak256("vk"));
        vm.stopPrank();
        vm.deal(operator, 10 ether);
    }

    function _validInputs() internal pure returns (ZKBridgeVerifier.PublicInputs memory) {
        return ZKBridgeVerifier.PublicInputs({
            sthRootHash:   keccak256("sth-root"),
            operatorVkHash: keccak256("op-vk"),
            treeSize:      1,
            sthSequence:   1
        });
    }

    // ----- C4: code-less SP1 verifier silently accepts every proof -----
    function test_C4_codeless_sp1_verifier_rejected() public {
        // sp1Verifier points at an address with NO contract code.
        _setup(address(0xC0DE1E55));

        bytes32 digest = keccak256("anchor-A");
        vm.prank(operator);
        challenge.openWindow{value: 1 ether}(digest);

        bytes memory junkProof = hex"deadbeef"; // not a real proof at all
        // Anyone submits; staticcall to the code-less verifier returns (true,"").
        try verifier.verifyAndFinalize(digest, junkProof, _validInputs()) {} catch {}

        // SECURE PROPERTY: a code-less verifier must never finalize a window.
        assertFalse(
            challenge.isFinalized(digest),
            "C4: window finalized through a code-less SP1 verifier (staticcall-to-EOA bypass)"
        );
    }

    // ----- C3: no access control + anchorDigest not bound to the proof -----
    function test_C3_finalize_requires_bound_authorized_proof() public {
        // Use a *genuine* verifier so this is distinct from simulated-mode forgery.
        MockSP1Verifier sp1 = new MockSP1Verifier();
        _setup(address(sp1));

        // Operator opens a window for digestB.
        bytes32 digestB = keccak256("anchor-B");
        vm.prank(operator);
        challenge.openWindow{value: 1 ether}(digestB);

        // A valid proof (first byte 0x01) attesting to some STH inputs — these
        // inputs have NO cryptographic relationship to digestB.
        bytes memory validProof = hex"01aabbcc";

        // An unprivileged attacker names digestB and finalizes it.
        vm.prank(attacker);
        try verifier.verifyAndFinalize(digestB, validProof, _validInputs()) {} catch {}

        // SECURE PROPERTY: finalizing digestB must require a proof whose public
        // inputs bind to digestB AND an authorized caller. Today neither holds.
        assertFalse(
            challenge.isFinalized(digestB),
            "C3: arbitrary caller finalized an arbitrary digest with an unbound proof"
        );
    }
}
