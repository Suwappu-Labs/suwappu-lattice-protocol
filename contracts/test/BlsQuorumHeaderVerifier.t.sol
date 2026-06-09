// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BlsValidatorRegistry} from "../src/verifiers/BlsValidatorRegistry.sol";
import {BlsQuorumHeaderVerifier} from "../src/verifiers/BlsQuorumHeaderVerifier.sol";

// =============================================================================
// Mock BLS12-381 Precompiles
// =============================================================================
//
// HONEST FRAMING: the real BLS12-381 precompiles (EIP-2537) are NOT available
// in this test suite. Forge-std 1.7.1 has no BLS signing cheatcode (vm.sign is
// ECDSA-only), and EIP-2537 does not provide a hash-to-curve precompile, making
// on-chain H2C non-trivial. Additionally, the repo's foundry.toml is pinned to
// evm_version = "cancun" to preserve the existing test suite; switching to
// "prague" repo-wide perturbs the known-RED secaudit baseline.
//
// WHAT THE MOCKS DO (and why they are NOT silently faking the pairing):
//
// We model BLS12-381 with a homomorphic scalar field (uint256 mod MOCK_ORDER):
//   - Each "public key" pk_i is 48 bytes, treated as bytes32 padded to 48 bytes
//     in this mock. The "secret key" sk_i satisfies pk_i = sk_i * G (mod MOCK_ORDER),
//     where * is scalar multiplication modelled as integer multiplication.
//   - G1ADD (0x0b): concatenates two 48-byte "G1 points"; the mock returns their
//     scalar sum mod MOCK_ORDER in 48 bytes. Soundness: the aggregate pubkey is
//     the sum of signing validators' individual scalars.
//   - BLS_PAIRING (0x10): checks e(aggSig, G2Gen) == e(H(digest), aggPubkey) by
//     verifying aggSig == aggPubkey_scalar * H(digest)_scalar (mod MOCK_ORDER).
//     This is exactly the BLS correctness relation in the scalar model.
//
// Why the tests catch real failure modes:
//   1. 3-of-4 quorum: test computes aggSig = (sk_0+sk_1+sk_2)*H(digest) mod ORDER.
//      On-chain: G1ADD accumulates pk_0+pk_1+pk_2 = (sk_0+sk_1+sk_2)*G (same scalar).
//      Pairing check: aggSig == aggPk_scalar * H(digest)_scalar ✓ -> PASSES.
//   2. Sub-quorum (1-of-4): stake sum < threshold -> BelowQuorum ✓ -> REVERTS before pairing.
//   3. Forged aggregate sig: aggSig crafted for DIFFERENT validators. The on-chain
//      aggPk is correctly accumulated for the CLAIMED validators; the forged aggSig
//      was constructed for different scalars -> check fails -> REVERTS InvalidAggregateSig.
//   4. Wrong epoch: StaleEpoch revert.
//   5. Equivocation: HeaderConflict revert.
//
// PENDING real EIP-2537 wiring:
//   - evm_version = "prague" in foundry.toml (or per-test via vm.chainId + vm.etch)
//   - FFI-based test vectors: `blspy` / `arkworks` to produce a real BLS12-381
//     aggregate over the keccak256(domain||...) digest (or SHA-256 H2C per BIP-340).
//   - On-chain H2C for message binding (expand_message_xmd + map_to_curve +
//     clear_cofactor), or proof-of-possession binding accepted from relayer.
// =============================================================================

uint256 constant MOCK_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

/// @notice Mock BLS12-381 G1ADD (etched at 0x0b).
/// @dev In the scalar model: treats each 48-byte "G1 point" as a uint256 scalar
///      (right-aligned in the 48-byte buffer). Returns their sum mod MOCK_ORDER
///      as a 48-byte value. Input must be exactly 96 bytes (two 48-byte points).
contract MockBlsG1Add {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 96) return new bytes(0);
        uint256 a = _read48(input[0:48]);
        uint256 b = _read48(input[48:96]);
        uint256 sum = addmod(a, b, MOCK_ORDER);
        return _write48(sum);
    }

    function _read48(bytes calldata b) internal pure returns (uint256 v) {
        // take the right-most 32 bytes of the 48-byte buffer as the scalar
        assembly {
            v := calldataload(add(b.offset, 16))
        }
    }

    function _write48(uint256 v) internal pure returns (bytes memory out) {
        out = new bytes(48);
        assembly {
            // bytes memory layout: [ptr+0..31 = length][ptr+32..79 = data (48 bytes)]
            // We want the scalar right-aligned: data[16..47] = v (32 bytes).
            // ptr+32+16 = ptr+48, so mstore(add(out,48),v) stores v at data[16..47].
            mstore(add(out, 48), v)
        }
    }
}

/// @notice Mock BLS12-381 PAIRING check (etched at 0x10).
/// @dev In the scalar model, verifies: aggSig == aggPk_scalar * H(digest) mod ORDER.
///      Input layout: aggPubkey (48 bytes) || digest (32 bytes) || aggregateSig (48 bytes).
///      Total input = 128 bytes.
///      Returns 32 bytes, last byte 0x01 if valid, 0x00 if not.
///
/// The relation aggSig = sk_agg * H(digest) mirrors the real BLS correctness equation
/// e(sk*G, H(m)) = e(G, sk*H(m)), but in the scalar ring. A forged aggSig (constructed
/// using different secret keys) will produce a different scalar product and FAIL.
contract MockBlsPairing {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 128) return abi.encodePacked(bytes32(0));
        uint256 aggPk = _read48(input[0:48]);
        bytes32 digest = bytes32(input[48:80]);
        uint256 aggSig = _read48(input[80:128]);

        uint256 hDigest = uint256(keccak256(abi.encodePacked("BLS_H", digest))) % MOCK_ORDER;
        // Check: aggSig == aggPk * hDigest mod ORDER
        uint256 expected = mulmod(aggPk, hDigest, MOCK_ORDER);

        bool valid = (aggSig == expected);
        return abi.encodePacked(valid ? bytes32(uint256(1)) : bytes32(0));
    }

    function _read48(bytes calldata b) internal pure returns (uint256 v) {
        assembly {
            v := calldataload(add(b.offset, 16))
        }
    }
}

// =============================================================================
// Test helpers
// =============================================================================

/// @dev Converts a uint256 "secret key" to a 48-byte mock BLS G1 pubkey.
///      pubkey = sk * G = sk in the scalar model (G = 1 element).
///      Right-aligns sk in 48 bytes: data[0..15] = 0, data[16..47] = sk.
///      bytes memory layout: [ptr+0..31 = length=48][ptr+32..79 = data].
///      mstore(add(pk, 48), sk) writes 32 bytes at ptr+48 = data+16. Correct.
function _skToPk(uint256 sk) pure returns (bytes memory pk) {
    pk = new bytes(48);
    assembly {
        mstore(add(pk, 48), sk)
    }
}

/// @dev Reads the scalar from a 48-byte mock G1 point.
///      mload(add(pk, 48)) reads 32 bytes from data[16..47] = the stored scalar.
function _pkToScalar(bytes memory pk) pure returns (uint256 v) {
    assembly {
        v := mload(add(pk, 48))
    }
}

/// @dev Compute aggSig = sum(sk_i) * H(digest) mod ORDER.
///      This is the valid BLS aggregate sig in the scalar model.
function _computeAggSig(uint256[] memory sks, bytes32 digest) pure returns (bytes memory aggSig) {
    uint256 hDigest = uint256(keccak256(abi.encodePacked("BLS_H", digest))) % MOCK_ORDER;
    uint256 skSum = 0;
    for (uint256 i = 0; i < sks.length; i++) {
        skSum = addmod(skSum, sks[i], MOCK_ORDER);
    }
    uint256 sig = mulmod(skSum, hDigest, MOCK_ORDER);
    aggSig = new bytes(48);
    assembly {
        mstore(add(aggSig, 48), sig)
    }
}

// =============================================================================
// BlsQuorumHeaderVerifier Tests
// =============================================================================

contract BlsQuorumHeaderVerifierTest is Test {
    BlsValidatorRegistry registry;
    BlsQuorumHeaderVerifier verifier;

    address admin = makeAddr("admin");
    uint256 constant NETWORK_ID = 7777;
    uint256 constant GSXDAG_CHAIN = 909090;

    // 4 validators, 25 stake each (total 100; quorum = (100*2)/3+1 = 67+1 = 68
    // Note: (100*2)/3 = 66 (integer div) -> +1 = 67.
    // Let's verify: (100*2)/3 = 200/3 = 66. Threshold = 67. 3*25=75 >= 67 ✓.
    uint256 constant N_VALIDATORS = 4;
    uint256 constant PER_STAKE = 25; // total = 100, threshold = 67

    // Secret keys (mock scalars, non-zero, reduced mod MOCK_ORDER for safety)
    uint256[] sks;
    bytes[] pks;
    uint256[] stakes;

    function setUp() public {
        // ---- Etch mock precompiles ----
        // BLS_G1ADD at 0x0b (EIP-2537 G1ADD address)
        vm.etch(address(0x0b), address(new MockBlsG1Add()).code);
        // BLS_PAIRING at 0x10 (EIP-2537 PAIRING address)
        vm.etch(address(0x10), address(new MockBlsPairing()).code);

        registry = new BlsValidatorRegistry(admin, NETWORK_ID);
        verifier = new BlsQuorumHeaderVerifier(registry, GSXDAG_CHAIN);

        // Build 4 validators with distinct secret keys
        sks = new uint256[](N_VALIDATORS);
        pks = new bytes[](N_VALIDATORS);
        stakes = new uint256[](N_VALIDATORS);
        for (uint256 i = 0; i < N_VALIDATORS; i++) {
            // secret key: deterministic non-zero scalar
            sks[i] = uint256(keccak256(abi.encodePacked("sk_validator", i))) % MOCK_ORDER;
            if (sks[i] == 0) sks[i] = 1; // ensure non-zero
            pks[i] = _skToPk(sks[i]);
            stakes[i] = PER_STAKE;
        }

        vm.prank(admin);
        registry.bootstrapEpoch0(pks, stakes);
    }

    // -------------------------------------------------------------------------
    // Helper: compute valid aggregate sig for a subset of validators (by index).
    // -------------------------------------------------------------------------
    function _quorumSig(uint256[] memory signerIndices, bytes32 digest)
        internal
        view
        returns (uint256 bitmap, bytes memory aggSig)
    {
        uint256[] memory subSks = new uint256[](signerIndices.length);
        for (uint256 i = 0; i < signerIndices.length; i++) {
            bitmap |= (1 << signerIndices[i]);
            subSks[i] = sks[signerIndices[i]];
        }
        aggSig = _computeAggSig(subSks, digest);
    }

    function _headerDigest(uint256 blockNumber, bytes32 stateRoot) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                verifier.HEADER_DOMAIN(), NETWORK_ID, address(verifier), blockNumber, stateRoot
            )
        );
    }

    // =========================================================================
    // Test 1: 3-of-4 quorum finalizes header (75 >= 67)
    // =========================================================================
    function test_QuorumFinalizesHeader() public {
        bytes32 root = keccak256("state-root-1");
        bytes32 digest = _headerDigest(100, root);

        // Validators 0, 1, 2 sign -> 3*25=75 >= 67 (threshold)
        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        verifier.submitHeader(100, root, 0, bitmap, aggSig);

        assertEq(verifier.headerStateRoot(GSXDAG_CHAIN, 100), root);
        assertEq(
            verifier.headerStateRoot(GSXDAG_CHAIN + 1, 100), bytes32(0), "wrong chain returns 0"
        );
    }

    // =========================================================================
    // Test 2: Idempotent re-submission with same root is a no-op
    // =========================================================================
    function test_IdempotentResubmission() public {
        bytes32 root = keccak256("state-root-2");
        bytes32 digest = _headerDigest(200, root);

        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        verifier.submitHeader(200, root, 0, bitmap, aggSig);
        // Second call with same root should succeed silently (no revert)
        verifier.submitHeader(200, root, 0, bitmap, aggSig);
        assertEq(verifier.headerStateRoot(GSXDAG_CHAIN, 200), root);
    }

    // =========================================================================
    // Test 3: Sub-quorum (1-of-4 = 25 < 67) reverts BelowQuorum
    // =========================================================================
    function test_SubQuorum_Reverts() public {
        bytes32 root = keccak256("state-root-3");
        bytes32 digest = _headerDigest(300, root);

        // Only validator 0 signs -> 1*25=25 < 67
        uint256[] memory signers = new uint256[](1);
        signers[0] = 0;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        vm.expectRevert(
            abi.encodeWithSelector(BlsQuorumHeaderVerifier.BelowQuorum.selector, 25, 67)
        );
        verifier.submitHeader(300, root, 0, bitmap, aggSig);
    }

    // =========================================================================
    // Test 4: Forged aggregate sig (valid signing set, wrong aggSig) reverts
    //         InvalidAggregateSig. Tests that the pairing check catches a bad sig.
    // =========================================================================
    function test_ForgedAggregateSig_Reverts() public {
        bytes32 root = keccak256("state-root-4");
        bytes32 digest = _headerDigest(400, root);

        // Validators 0, 1, 2 claimed as signers (quorum: 75 >= 67)
        uint256 bitmap = (1 << 0) | (1 << 1) | (1 << 2);

        // Forged sig: computed for validators 0+3 instead of 0+1+2
        // aggPk on-chain will be sk[0]+sk[1]+sk[2]; forged sig = (sk[0]+sk[3]) * H(digest)
        uint256[] memory forgedSks = new uint256[](2);
        forgedSks[0] = sks[0];
        forgedSks[1] = sks[3]; // wrong: uses sk[3], not sk[1]+sk[2]
        bytes memory forgedSig = _computeAggSig(forgedSks, digest);

        vm.expectRevert(BlsQuorumHeaderVerifier.InvalidAggregateSig.selector);
        verifier.submitHeader(400, root, 0, bitmap, forgedSig);
    }

    // =========================================================================
    // Test 5: Equivocation (second root for same block) reverts HeaderConflict
    // =========================================================================
    function test_Equivocation_Reverts() public {
        bytes32 root1 = keccak256("state-root-5a");
        bytes32 root2 = keccak256("state-root-5b");

        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;

        // Finalize with root1
        {
            bytes32 digest = _headerDigest(500, root1);
            (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);
            verifier.submitHeader(500, root1, 0, bitmap, aggSig);
        }

        // Attempt to finalize same block with root2 -> conflict
        {
            bytes32 digest = _headerDigest(500, root2);
            (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);
            vm.expectRevert(
                abi.encodeWithSelector(BlsQuorumHeaderVerifier.HeaderConflict.selector, 500)
            );
            verifier.submitHeader(500, root2, 0, bitmap, aggSig);
        }
    }

    // =========================================================================
    // Test 6: Stale epoch reverts StaleEpoch
    // =========================================================================
    function test_StaleEpoch_Reverts() public {
        bytes32 root = keccak256("state-root-6");
        bytes32 digest = _headerDigest(600, root);

        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        // epoch 1 is stale (registry is at epoch 0)
        vm.expectRevert(abi.encodeWithSelector(BlsQuorumHeaderVerifier.StaleEpoch.selector, 1, 0));
        verifier.submitHeader(600, root, 1, bitmap, aggSig);
    }

    // =========================================================================
    // Test 7: Bitmap with unregistered validator index (beyond validatorCount)
    //         — the loop bounds to n = validatorCount, so extra bits are ignored.
    //         Only registered validators contribute stake.
    // =========================================================================
    function test_OutOfBoundsBitmapBit_Ignored() public {
        bytes32 root = keccak256("state-root-7");
        bytes32 digest = _headerDigest(700, root);

        // Set bit 10 (no validator at index 10) in addition to bits 0,1,2
        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);
        bitmap |= (1 << 10); // extra bit for non-existent validator

        // Should still succeed: bits beyond validatorCount are simply out of loop range
        verifier.submitHeader(700, root, 0, bitmap, aggSig);
        assertEq(verifier.headerStateRoot(GSXDAG_CHAIN, 700), root);
    }

    // =========================================================================
    // Test 8: Sig valid for a different stateRoot fails (digest mismatch)
    //         The aggregate sig is bound to the exact digest including stateRoot.
    // =========================================================================
    function test_SigForDifferentRoot_Reverts() public {
        bytes32 correctRoot = keccak256("state-root-8-correct");
        bytes32 wrongRoot = keccak256("state-root-8-wrong");

        // Sign for correctRoot
        bytes32 digest = _headerDigest(800, correctRoot);
        uint256[] memory signers = new uint256[](3);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        // Submit with wrongRoot — digest doesn't match -> pairing fails
        vm.expectRevert(BlsQuorumHeaderVerifier.InvalidAggregateSig.selector);
        verifier.submitHeader(800, wrongRoot, 0, bitmap, aggSig);
    }

    // =========================================================================
    // Test 9: 4-of-4 (all validators, 100 >= 67) also works
    // =========================================================================
    function test_FullQuorum_Finalizes() public {
        bytes32 root = keccak256("state-root-9");
        bytes32 digest = _headerDigest(900, root);

        uint256[] memory signers = new uint256[](4);
        signers[0] = 0;
        signers[1] = 1;
        signers[2] = 2;
        signers[3] = 3;
        (uint256 bitmap, bytes memory aggSig) = _quorumSig(signers, digest);

        verifier.submitHeader(900, root, 0, bitmap, aggSig);
        assertEq(verifier.headerStateRoot(GSXDAG_CHAIN, 900), root);
    }
}
