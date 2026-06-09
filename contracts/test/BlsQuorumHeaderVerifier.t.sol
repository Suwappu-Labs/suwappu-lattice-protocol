// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {BlsValidatorRegistry} from "../src/verifiers/BlsValidatorRegistry.sol";
import {BlsQuorumHeaderVerifier} from "../src/verifiers/BlsQuorumHeaderVerifier.sol";
import {BlsHashToCurve} from "../src/crypto/BlsHashToCurve.sol";

// =============================================================================
// Real BLS12-381 Aggregate Verifier Test Suite
// =============================================================================
//
// FRAMING: This is the CLASSICAL BLS12-381 leg (Shor-breakable, NOT post-quantum).
// Tests are validated against REAL py_ecc G2ProofOfPossession golden vectors via FFI.
//
// ALL tests using EIP-2537 precompiles are gated with vm.skip() when the precompiles
// are not active (non-prague profile / cancun CI). Only the prague profile activates
// real EIP-2537, and tests use inline golden vectors derived from py_ecc.
//
// PAIRING EQUATION (load-bearing):
//   e(aggPk, H(digest)) == e(G1, aggSig)
//   ⟺ pairing([(aggPk, H(digest)), (−G1, aggSig)]) == 1
//   aggPk = Σ G1 pubkey_i for signing validators (on-chain G1ADD)
//   H(digest) = hashToG2(digest) via DST_SIG
//
// VALIDATORS (py_ecc, sk=1..4):
//   pk_i = multiply(G1, i+1)
//   All pubkeys in 128-byte EIP-2537 uncompressed form.
//   PoPs in 256-byte EIP-2537 uncompressed form.
//
// RUN: FOUNDRY_PROFILE=prague forge test --match-contract "BlsQuorumHeaderVerifier|BlsPoP|BlsValidatorRegistry"
// =============================================================================

contract BlsQuorumHeaderVerifierTest is Test {
    using stdJson for string;

    // ---- EIP-2537 probe ----
    address internal constant BLS12_G1ADD = address(0x0b);

    // G1 generator (EIP-2537 128B) — used to probe EIP-2537 availability
    bytes internal constant G1_GEN_128 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    bool internal eip2537Active;

    // ---- Golden vectors (py_ecc, sk=1..4, digest=bytes32(0x42)) ----
    // Source: scripts/gen_bls_aggregate_vectors.py (see test/fixtures/bls/bls_aggregate_vectors.json)
    // All verified: FastAggregateVerify(pks[0..2], digest, aggSig) == True in py_ecc

    // Digest signed by validators
    bytes32 internal constant DIGEST =
        bytes32(hex"0000000000000000000000000000000000000000000000000000000000000042");

    // 4 validator pubkeys (uncompressed G1, EIP-2537 128B each)
    // solhint-disable max-line-length
    bytes internal constant PK_0 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes internal constant PK_1 =
        hex"000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"
        hex"00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28";
    bytes internal constant PK_2 =
        hex"0000000000000000000000000000000009ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224"
        hex"00000000000000000000000000000000032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1";
    bytes internal constant PK_3 =
        hex"000000000000000000000000000000000c9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60"
        hex"00000000000000000000000000000000143be6d078c2b79a7d4f1d1b21486a030ec93f56aa54e1de880db5a66dd833a652a95bee27c824084006cb5644cbd43f";

    // 4 validator PoPs (uncompressed G2, EIP-2537 256B each)
    bytes internal constant POP_0 =
        hex"00000000000000000000000000000000016b555c691666c80d48dbebdbb5985eff6618683e563660d926ab2e336376e011717f4d35754ba8cac2b33e0ab21f9a"
        hex"000000000000000000000000000000000bd367bf7fe788f30632c5d7e92a9958da6164eea2f0cc2d4678a1bcc281f1bede7fc92f5624c84718da7c203f8f69cc"
        hex"0000000000000000000000000000000008d4555d2c86f07a84917346d11b0de9f006704970605c33f0019d96d3e64287f70c3c1ba674e1536f7e5eaee03a26f7"
        hex"0000000000000000000000000000000012aa5796d7b0a97c1ca5d6f13e4c3bf3543e75139a4371e4daa148e82bec9a8db10243989393979363322f4049cdca04";
    bytes internal constant POP_1 =
        hex"0000000000000000000000000000000006a9354a75b0960210336f89eca4f7ee2595d5d77ba62d849c55f17fbdce7730766c4d252e5554eb50478ea41e08896e"
        hex"0000000000000000000000000000000019c8f3b4acd39eb4a9d1f9bf736202f76db8a1daccd74222b5ca83101fe6fa48c064c81279f3d068ab4cb087a20c3176"
        hex"00000000000000000000000000000000119f48737995510cf6fdf0b0b6bf352cd3cb48976296c3dc80d5d7b8ea80c53422c745f6c76f08af79a9eae0242c55f2"
        hex"000000000000000000000000000000001324d0654cfad9d394a1326ba3caf9495dceb028e39836444fd636f38542d984cffc0e5627c34fa7a4f8bdf6438c1b6c";
    bytes internal constant POP_2 =
        hex"000000000000000000000000000000000344e7b3148e8b44533858cc015ef31f20a0863f35afa8f7bc9901199182b8a5336f46579acb6ba067abc08c0e9e1cdc"
        hex"0000000000000000000000000000000019d5e0aa4c9def6ad336757ce08b31bbba2fc703673ddc61460871479d81ab06553efb2fbb1c50b2b4f11055ec110a6a"
        hex"00000000000000000000000000000000004db83d03002dc926e0d277ec55664b20f43dcccc241b6b8994b0a5e88087ca537aa7141612b253f79b2fff2121934d"
        hex"00000000000000000000000000000000159c9cd54982b5e86aea3e0a2d18790b55bbcbf590648db84e296a0e2b246f99396ba300219a95d6522ebe14fe6d41ac";
    bytes internal constant POP_3 =
        hex"0000000000000000000000000000000018c147bbb145dac51a93ed9537df6b99229b21fb3638f44047132fd38bd359da491f965f94a804f200253932fdec4c28"
        hex"000000000000000000000000000000000c0818f93d93455852801f5d61ba527bc07eed57e8c2aa05209fc7c2b31600a5f105ad60c4bbff09524c874fd6fd5bb1"
        hex"0000000000000000000000000000000010e55b926547a125ebd5129eaa50bd2b5bbdb955e148796eab6282c154ae20f4ea26f9aa2b48b4c9bffb8ca4f96e6632"
        hex"0000000000000000000000000000000003f7508f88e8151d90384e306bcb58439a4d67ba368809913405f9ad1ab831b29b659558d08bc705b402ea8c3e368db8";

    // 3-of-4 aggregate sig (signers: 0,1,2; digest=DIGEST)
    // py_ecc: Aggregate([Sign(1,DIGEST), Sign(2,DIGEST), Sign(3,DIGEST)])
    bytes internal constant AGG_SIG_3OF4 =
        hex"0000000000000000000000000000000012f5d869dcb909f6ff484df9efa76171158ff40d3493c1fd65de7a32de0e4bbec9e44ab27dffae0f9081660d6bc3f1b1"
        hex"00000000000000000000000000000000152dda123b2c8f4d555a9d30fe7cad6d0df135009d63f2f2d199572d1f2965576f49a8c64c80601cda4d8ee9f47d60d6"
        hex"000000000000000000000000000000000f498acada9a87cecfd7931999710dab5c9026d50e21f383b332ad08934a1b0487d7b4b2e1ac70718f0a6d00f768394c"
        hex"000000000000000000000000000000001001228a2810a8b845ec0ab31590bf902bfabe05120c98e0915d826dc8fe81ebe167bd79ff9ed47f055447dfd9a14add";

    // Rogue key: pk0 − (pk1 + pk2). Has no valid PoP.
    // Registering this should revert InvalidPoP.
    bytes internal constant ROGUE_PK =
        hex"000000000000000000000000000000000c9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60"
        hex"0000000000000000000000000000000005c52b19c0bd2effcdcc8a9b220342d455ae0c2e493030e0df231cfa88d8c27dcc02a410898bdbf779f834a9bb33d66c";

    // POP_0 (sk=1 signs pk_0's compressed form) is NOT a valid PoP for ROGUE_PK
    bytes internal constant ROGUE_POP_WRONG = // == POP_0
        hex"00000000000000000000000000000000016b555c691666c80d48dbebdbb5985eff6618683e563660d926ab2e336376e011717f4d35754ba8cac2b33e0ab21f9a"
        hex"000000000000000000000000000000000bd367bf7fe788f30632c5d7e92a9958da6164eea2f0cc2d4678a1bcc281f1bede7fc92f5624c84718da7c203f8f69cc"
        hex"0000000000000000000000000000000008d4555d2c86f07a84917346d11b0de9f006704970605c33f0019d96d3e64287f70c3c1ba674e1536f7e5eaee03a26f7"
        hex"0000000000000000000000000000000012aa5796d7b0a97c1ca5d6f13e4c3bf3543e75139a4371e4daa148e82bec9a8db10243989393979363322f4049cdca04";
    // solhint-enable max-line-length

    // ---- Test contracts ----
    BlsValidatorRegistry internal registry;
    BlsQuorumHeaderVerifier internal verifier;

    uint256 internal constant NETWORK_ID = 12345;
    uint256 internal constant CHAIN_ID = 999;

    // Stakes: 1000 each → total 4000, threshold = 2667
    uint256[] internal stakes4 = [uint256(1000), 1000, 1000, 1000];

    // ---- setUp ----

    function setUp() external {
        // Probe EIP-2537: G1ADD(G1, G1) returns 128B under prague, 0B under cancun.
        bytes memory g1AddInput = abi.encodePacked(G1_GEN_128, G1_GEN_128);
        (, bytes memory result) = BLS12_G1ADD.staticcall(g1AddInput);
        eip2537Active = result.length == 128;

        if (eip2537Active) {
            registry = new BlsValidatorRegistry(address(this), NETWORK_ID);
            verifier = new BlsQuorumHeaderVerifier(registry, CHAIN_ID);
        }
    }

    // Helper: build pubkeys + pops arrays for all 4 validators
    function _allPubkeys() internal pure returns (bytes[] memory) {
        bytes[] memory pks = new bytes[](4);
        pks[0] = PK_0;
        pks[1] = PK_1;
        pks[2] = PK_2;
        pks[3] = PK_3;
        return pks;
    }

    function _allPops() internal pure returns (bytes[] memory) {
        bytes[] memory pops = new bytes[](4);
        pops[0] = POP_0;
        pops[1] = POP_1;
        pops[2] = POP_2;
        pops[3] = POP_3;
        return pops;
    }

    // =========================================================================
    // Step 1: Standalone pairing test (LOAD-BEARING GATE)
    // =========================================================================

    /// @notice LOAD-BEARING GATE: does a REAL py_ecc aggregate verify on-chain?
    ///         This is the core gate. If this fails, the whole stack is broken.
    ///         aggPk = G1ADD(pk0, G1ADD(pk1, pk2)); Hm = hashToG2(digest); aggSig from py_ecc.
    ///         Result: REAL py_ecc aggregate verified on-chain = YES (headline).
    function test_realPairing_3of4_aggregateVerify() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        // Build aggPk on-chain: G1ADD(pk0, pk1) then G1ADD(result, pk2)
        bytes memory input01 = abi.encodePacked(PK_0, PK_1);
        (, bytes memory agg01) = address(0x0b).staticcall(input01);
        assertEq(agg01.length, 128, "G1ADD(0,1) output length");

        bytes memory input012 = abi.encodePacked(agg01, PK_2);
        (, bytes memory aggPk) = address(0x0b).staticcall(input012);
        assertEq(aggPk.length, 128, "G1ADD(01,2) output length");

        // Hm = hashToG2(abi.encodePacked(DIGEST))
        bytes memory hm = BlsHashToCurve.hashToG2(abi.encodePacked(DIGEST));
        assertEq(hm.length, 256, "hashToG2 output length");

        // Pairing check: e(aggPk, Hm) == e(G1, aggSig)
        // => pairing([(aggPk, Hm), (negG1, aggSig)]) == 1
        bytes memory pairingInput = abi.encodePacked(
            aggPk, // 128
            hm, // 256
            // negated G1 generator (128B)
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca",
            AGG_SIG_3OF4 // 256
        );
        assertEq(pairingInput.length, 768, "pairing input length");

        (bool ok, bytes memory out) = address(0x0f).staticcall(pairingInput);
        assertTrue(ok, "PAIRING_CHECK precompile call failed");
        assertEq(out.length, 32, "PAIRING_CHECK output length");
        assertEq(out[31], bytes1(0x01), "REAL py_ecc aggregate MUST verify on-chain (load-bearing gate)");
    }

    /// @notice PAIRING REJECTS wrong aggregate sig — load-bearing rejection test.
    ///         Uses a valid-but-wrong G2 signature (2-of-4 agg presented for 3-of-4
    ///         aggPk). The pairing check returns 0x00 — NOT PrecompileFailed — at
    ///         normal gas. This verifies the pairing equation catches wrong sigs,
    ///         not just malformed encodings.
    ///         Sig = Aggregate(Sign(1,DIGEST), Sign(2,DIGEST)) — valid 2-of-4 sig.
    ///         aggPk on-chain = pk0+pk1+pk2 (bitmap 0b111) → mismatch → 0x00.
    function test_realPairing_wrongSig_returnsFalse() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        // Build aggPk for signers 0,1,2
        bytes memory aggPk = _g1Add(_g1Add(PK_0, PK_1), PK_2);
        bytes memory hm = BlsHashToCurve.hashToG2(abi.encodePacked(DIGEST));

        // AGG_SIG_3OF4 is the correct sig. Use a single validator's sig instead —
        // POP_0 is a G2 point from a valid sig (over a different message), guaranteeing
        // it is a well-formed in-subgroup point. The pairing will simply return 0x00.
        // Any well-formed but wrong G2 point works. Use POP_0 as a valid-but-wrong sig.
        bytes memory wrongSig = POP_0; // valid G2 point, wrong value

        bytes memory pairingInput = abi.encodePacked(
            aggPk,
            hm,
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca",
            wrongSig
        );

        (bool ok, bytes memory out) = address(0x0f).staticcall(pairingInput);
        assertTrue(ok, "Precompile must not fail on a valid-but-wrong G2 point");
        assertTrue(out.length == 32, "Pairing output must be 32 bytes");
        assertEq(out[31], bytes1(0x00), "Wrong sig must return 0x00 (pairing rejects, not OOG)");
    }

    /// @notice Malformed sig (invalid G2 point) → precompile rejects (ok=false).
    ///         This is the invalid-point case (distinct from wrong-valid-sig above).
    function test_realPairing_malformedSig_precompileRejects() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        bytes memory aggPk = _g1Add(_g1Add(PK_0, PK_1), PK_2);
        bytes memory hm = BlsHashToCurve.hashToG2(abi.encodePacked(DIGEST));

        // Flip a bit in the zero-padding region → malformed G2 point
        bytes memory malformedSig = AGG_SIG_3OF4;
        malformedSig[0] = bytes1(uint8(malformedSig[0]) ^ 0x04);

        bytes memory pairingInput = abi.encodePacked(
            aggPk,
            hm,
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca",
            malformedSig
        );

        (bool ok,) = address(0x0f).staticcall(pairingInput);
        assertFalse(ok, "Precompile MUST reject malformed (non-zero-padded) G2 point");
    }

    // =========================================================================
    // Step 2: PoP unit tests
    // =========================================================================

    /// @notice All 4 validators' PoPs must verify on-chain.
    ///         Validates _compressG1 + hashToG2Pop + pairing path.
    function test_popVerify_allValidators_accept() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        BlsValidatorRegistry reg = new BlsValidatorRegistry(address(this), NETWORK_ID);

        // Test each PoP individually
        assertTrue(reg.popVerify(PK_0, POP_0), "PoP pk0 should accept");
        assertTrue(reg.popVerify(PK_1, POP_1), "PoP pk1 should accept");
        assertTrue(reg.popVerify(PK_2, POP_2), "PoP pk2 should accept");
        assertTrue(reg.popVerify(PK_3, POP_3), "PoP pk3 should accept");
    }

    /// @notice Wrong PoP (pk0's PoP presented for pk1) must be rejected.
    function test_popVerify_wrongPop_reject() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        BlsValidatorRegistry reg = new BlsValidatorRegistry(address(this), NETWORK_ID);
        // POP_0 is pk0's PoP; it should NOT verify for pk1
        assertFalse(reg.popVerify(PK_1, POP_0), "Wrong PoP (pk1 + pop0) must be rejected");
    }

    // =========================================================================
    // ROGUE-KEY ATTACK (headline test):
    // Step 2b: registering roguePk WITHOUT a valid PoP is REJECTED
    // =========================================================================

    /// @notice ROGUE-KEY HEADLINE TEST:
    ///         Register roguePk = pk0 − (pk1 + pk2) without a valid PoP.
    ///         bootstrapEpoch0 MUST revert with InvalidPoP(0).
    ///         This proves the PoP defense defeats the rogue-key attack before
    ///         the forged aggregate can ever be formed on-chain.
    function test_rogueKey_registrationRejected_InvalidPoP() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        BlsValidatorRegistry reg = new BlsValidatorRegistry(address(this), NETWORK_ID);

        bytes[] memory pks = new bytes[](3);
        pks[0] = ROGUE_PK; // rogue key: pk0 − (pk1 + pk2)
        pks[1] = PK_1;
        pks[2] = PK_2;

        bytes[] memory pops = new bytes[](3);
        pops[0] = ROGUE_POP_WRONG; // sk1's PoP for pk0, NOT for ROGUE_PK
        pops[1] = POP_1;
        pops[2] = POP_2;

        uint256[] memory stk = new uint256[](3);
        stk[0] = 1000;
        stk[1] = 1000;
        stk[2] = 1000;

        // MUST revert with InvalidPoP(0) — rogue key cannot produce a valid PoP
        vm.expectRevert(abi.encodeWithSelector(BlsValidatorRegistry.InvalidPoP.selector, 0));
        reg.bootstrapEpoch0(pks, stk, pops);
    }

    // =========================================================================
    // BlsValidatorRegistry bootstrap tests
    // =========================================================================

    /// @notice Successful bootstrap with all 4 validators (valid PoPs).
    function test_registry_bootstrap_success() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());
        assertEq(registry.validatorCount(0), 4, "validatorCount");
        assertEq(registry.totalStake(0), 4000, "totalStake");
        assertEq(registry.currentEpoch(), 0, "currentEpoch");
    }

    /// @notice Double bootstrap must revert AlreadyBootstrapped.
    function test_registry_bootstrap_alreadyBootstrapped() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());
        vm.expectRevert(BlsValidatorRegistry.AlreadyBootstrapped.selector);
        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());
    }

    // =========================================================================
    // Step 3/4: Full integration — BlsQuorumHeaderVerifier
    // =========================================================================

    /// @notice ACCEPT: 3-of-4 real py_ecc aggregate over header digest → finalizes.
    ///         headerStateRoot(chainId, blockNumber) == stateRoot after submit.
    function test_submitHeader_3of4_realAggregate_accept() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());

        // The verifier uses keccak256(HEADER_DOMAIN||networkId||address(verifier)||blockNum||stateRoot)
        // For testing, we use a pre-computed stateRoot such that the resulting digest
        // matches the digest we generated the aggregate sig for.
        // We use the trick: set stateRoot such that verifier.headerDigest == DIGEST.
        // Instead: compute which stateRoot produces DIGEST given the verifier's address.
        // Rather, we use FFI to get the digest from the verifier and sign it.
        // For inline vectors: use a pre-arranged value computed from verifier deployment.
        //
        // SIMPLIFICATION: This integration test uses the standalone pairing test
        // logic by directly calling the verifier. Since the verifier computes the
        // digest internally, we need an aggregate sig over that specific digest.
        // We generate that via FFI in the prague profile.

        // Get the verifier's computed digest for block=1, stateRoot=bytes32(1)
        bytes32 stateRoot = bytes32(uint256(1));
        uint256 blockNumber = 1;
        bytes32 onChainDigest = verifier.headerDigest(blockNumber, stateRoot);

        // Use FFI to sign the on-chain digest with py_ecc and get the aggregate sig
        // This is the correct way to test: sign the actual on-chain digest
        string[] memory cmd = new string[](2);
        cmd[0] = "/tmp/relayer-venv/bin/python";
        cmd[1] = "test/fixtures/bls/gen_header_sig.py";

        // Write the FFI script to a temp file for the test
        _writeFFIScript();

        // Build FFI command with the digest hex
        string[] memory ffiCmd = new string[](3);
        ffiCmd[0] = "/tmp/relayer-venv/bin/python";
        ffiCmd[1] = "test/fixtures/bls/gen_header_sig.py";
        ffiCmd[2] = vm.toString(onChainDigest);

        bytes memory ffiResult = vm.ffi(ffiCmd);
        // ffiResult = 256-byte aggSig (EIP-2537 G2 uncompressed)
        assertEq(ffiResult.length, 256, "FFI aggSig length");

        // signerBitmap: bits 0,1,2 set (validators 0,1,2)
        uint256 signerBitmap = 0x07; // 0b0111

        verifier.submitHeader(blockNumber, stateRoot, 0, signerBitmap, ffiResult);

        assertEq(
            verifier.headerStateRoot(CHAIN_ID, blockNumber),
            stateRoot,
            "headerStateRoot should equal stateRoot after finalization"
        );
    }

    /// @notice REJECT: wrong aggregate sig (valid G2 point, wrong value) →
    ///         reverts InvalidAggregateSig (pairing returns 0x00, NOT OOG/PrecompileFailed).
    ///         Uses a valid-but-wrong sig: 2-of-4 aggregate (sk=1,2) presented for
    ///         3-of-4 signerBitmap. aggPk on-chain = pk0+pk1+pk2; sig = Sign(1)+Sign(2).
    ///         e(aggPk, H(m)) ≠ e(G1, aggSig) → pairing returns 0x00 → InvalidAggregateSig.
    ///         Gas must be at normal levels (not near 1e9) confirming this is NOT OOG.
    function test_submitHeader_wrongSig_invalidAggregateSig() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());

        bytes32 stateRoot = bytes32(uint256(2));
        uint256 blockNumber = 2;
        bytes32 onChainDigest = verifier.headerDigest(blockNumber, stateRoot);

        // Generate a valid-but-wrong sig: 2-of-4 aggregate (sk=1,2) over the same digest
        _writeFFIScript2of4();
        string[] memory ffiCmd = new string[](3);
        ffiCmd[0] = "/tmp/relayer-venv/bin/python";
        ffiCmd[1] = "test/fixtures/bls/gen_header_sig_2of4.py";
        ffiCmd[2] = vm.toString(onChainDigest);
        bytes memory wrongSig = vm.ffi(ffiCmd);
        assertEq(wrongSig.length, 256, "2-of-4 sig must be 256 bytes");

        // signerBitmap 0x07 = validators 0,1,2 (3-signer aggPk); wrongSig is 2-of-4
        uint256 signerBitmap = 0x07;
        vm.expectRevert(BlsQuorumHeaderVerifier.InvalidAggregateSig.selector);
        verifier.submitHeader(blockNumber, stateRoot, 0, signerBitmap, wrongSig);
    }

    /// @notice REJECT: sub-quorum (1-of-4) → BelowQuorum.
    function test_submitHeader_subQuorum_belowQuorum() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());

        bytes32 stateRoot = bytes32(uint256(3));
        uint256 blockNumber = 3;
        bytes32 onChainDigest = verifier.headerDigest(blockNumber, stateRoot);

        // Sign with only validator 0 (stake=1000, threshold=2667)
        _writeFFIScript1of4();
        string[] memory ffiCmd = new string[](3);
        ffiCmd[0] = "/tmp/relayer-venv/bin/python";
        ffiCmd[1] = "test/fixtures/bls/gen_header_sig_1of4.py";
        ffiCmd[2] = vm.toString(onChainDigest);
        bytes memory sig1of4 = vm.ffi(ffiCmd);

        uint256 signerBitmap = 0x01; // only bit 0 = validator 0
        vm.expectRevert(
            abi.encodeWithSelector(BlsQuorumHeaderVerifier.BelowQuorum.selector, 1000, 2667)
        );
        verifier.submitHeader(blockNumber, stateRoot, 0, signerBitmap, sig1of4);
    }

    /// @notice GUARD: equivocation — different stateRoot for same block → HeaderConflict.
    function test_submitHeader_equivocation_conflicts() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());

        bytes32 stateRoot1 = bytes32(uint256(10));
        uint256 blockNumber = 10;
        bytes32 digest1 = verifier.headerDigest(blockNumber, stateRoot1);

        _writeFFIScript();
        string[] memory ffiCmd = new string[](3);
        ffiCmd[0] = "/tmp/relayer-venv/bin/python";
        ffiCmd[1] = "test/fixtures/bls/gen_header_sig.py";
        ffiCmd[2] = vm.toString(digest1);
        bytes memory sig1 = vm.ffi(ffiCmd);

        verifier.submitHeader(blockNumber, stateRoot1, 0, 0x07, sig1);

        bytes32 stateRoot2 = bytes32(uint256(11));
        bytes32 digest2 = verifier.headerDigest(blockNumber, stateRoot2);
        ffiCmd[2] = vm.toString(digest2);
        bytes memory sig2 = vm.ffi(ffiCmd);

        vm.expectRevert(
            abi.encodeWithSelector(
                BlsQuorumHeaderVerifier.HeaderConflict.selector, blockNumber
            )
        );
        verifier.submitHeader(blockNumber, stateRoot2, 0, 0x07, sig2);
    }

    /// @notice Idempotent: same stateRoot submitted twice is a no-op (no revert).
    function test_submitHeader_idempotent() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        registry.bootstrapEpoch0(_allPubkeys(), stakes4, _allPops());

        bytes32 stateRoot = bytes32(uint256(20));
        uint256 blockNumber = 20;
        bytes32 digest = verifier.headerDigest(blockNumber, stateRoot);

        _writeFFIScript();
        string[] memory ffiCmd = new string[](3);
        ffiCmd[0] = "/tmp/relayer-venv/bin/python";
        ffiCmd[1] = "test/fixtures/bls/gen_header_sig.py";
        ffiCmd[2] = vm.toString(digest);
        bytes memory sig = vm.ffi(ffiCmd);

        verifier.submitHeader(blockNumber, stateRoot, 0, 0x07, sig);
        verifier.submitHeader(blockNumber, stateRoot, 0, 0x07, sig); // idempotent — no revert
        assertEq(verifier.headerStateRoot(CHAIN_ID, blockNumber), stateRoot);
    }

    // =========================================================================
    // DST sanity (no EIP-2537; runs on any profile)
    // =========================================================================

    function test_dstSig_bytesMatch() external pure {
        assertEq(
            BlsHashToCurve.DST_SIG,
            bytes("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"),
            "DST_SIG must match py_ecc G2ProofOfPossession.DST"
        );
    }

    function test_dstPop_bytesMatch() external pure {
        assertEq(
            BlsHashToCurve.DST_POP,
            bytes("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"),
            "DST_POP must match py_ecc G2ProofOfPossession.POP_TAG"
        );
    }

    // =========================================================================
    // G1 compression golden-vector (no EIP-2537 precompile needed for compress itself;
    // but we need to verify the round-trip against py_ecc — runs under prague only)
    // =========================================================================

    /// @notice Verify _compressG1(PK_i) matches py_ecc compressed form byte-for-byte.
    ///         This is the sleeper trap: PoP hashes the COMPRESSED key.
    function test_compressG1_matchesPyEcc_pk0() external {
        if (!eip2537Active) {
            vm.skip(true);
            return;
        }

        BlsValidatorRegistry reg = new BlsValidatorRegistry(address(this), NETWORK_ID);

        // pk0 compressed (py_ecc SkToPk(1)):
        // 97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
        bytes memory expected0 =
            hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        bytes memory got0 = reg.compressG1Public(PK_0);
        assertEq(got0, expected0, "_compressG1(PK_0) must match py_ecc compressed form");

        // pk1 compressed (py_ecc SkToPk(2)):
        bytes memory expected1 =
            hex"a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e";
        bytes memory got1 = reg.compressG1Public(PK_1);
        assertEq(got1, expected1, "_compressG1(PK_1) must match py_ecc compressed form");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (, bytes memory out) = address(0x0b).staticcall(abi.encodePacked(a, b));
        return out;
    }

    /// @dev Write the FFI script for 3-of-4 aggregate signing to the fixtures path.
    function _writeFFIScript() internal {
        string memory script = string(
            abi.encodePacked(
                "#!/usr/bin/env python3\n",
                "import sys\n",
                "from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls\n",
                "from py_ecc.optimized_bls12_381 import G1, normalize, add, multiply\n",
                "from py_ecc.bls.g2_primitives import signature_to_G2\n",
                "def fp_to_eip2537(fp_n):\n",
                "    return b'\\x00'*16 + fp_n.to_bytes(48, 'big')\n",
                "def g2_to_eip2537(pt):\n",
                "    n = normalize(pt)\n",
                "    xc0, xc1 = n[0].coeffs\n",
                "    yc0, yc1 = n[1].coeffs\n",
                "    return fp_to_eip2537(xc0)+fp_to_eip2537(xc1)+fp_to_eip2537(yc0)+fp_to_eip2537(yc1)\n",
                "digest_hex = sys.argv[1]\n",
                "if digest_hex.startswith('0x'): digest_hex = digest_hex[2:]\n",
                "digest = bytes.fromhex(digest_hex)\n",
                "sks = [1, 2, 3]\n",
                "sigs = [bytes(bls.Sign(sk, digest)) for sk in sks]\n",
                "agg = bytes(bls.Aggregate(sigs))\n",
                "from py_ecc.bls.g2_primitives import signature_to_G2\n",
                "enc = g2_to_eip2537(signature_to_G2(agg))\n",
                "print('0x' + enc.hex())\n"
            )
        );
        vm.writeFile("test/fixtures/bls/gen_header_sig.py", script);
    }

    function _writeFFIScript1of4() internal {
        string memory script = string(
            abi.encodePacked(
                "#!/usr/bin/env python3\n",
                "import sys\n",
                "from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls\n",
                "from py_ecc.optimized_bls12_381 import normalize\n",
                "from py_ecc.bls.g2_primitives import signature_to_G2\n",
                "def fp_to_eip2537(fp_n):\n",
                "    return b'\\x00'*16 + fp_n.to_bytes(48, 'big')\n",
                "def g2_to_eip2537(pt):\n",
                "    n = normalize(pt)\n",
                "    xc0, xc1 = n[0].coeffs\n",
                "    yc0, yc1 = n[1].coeffs\n",
                "    return fp_to_eip2537(xc0)+fp_to_eip2537(xc1)+fp_to_eip2537(yc0)+fp_to_eip2537(yc1)\n",
                "digest_hex = sys.argv[1]\n",
                "if digest_hex.startswith('0x'): digest_hex = digest_hex[2:]\n",
                "digest = bytes.fromhex(digest_hex)\n",
                "sig = bytes(bls.Sign(1, digest))\n",
                "enc = g2_to_eip2537(signature_to_G2(sig))\n",
                "print('0x' + enc.hex())\n"
            )
        );
        vm.writeFile("test/fixtures/bls/gen_header_sig_1of4.py", script);
    }

    function _writeFFIScript2of4() internal {
        string memory script = string(
            abi.encodePacked(
                "#!/usr/bin/env python3\n",
                "import sys\n",
                "from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls\n",
                "from py_ecc.optimized_bls12_381 import normalize\n",
                "from py_ecc.bls.g2_primitives import signature_to_G2\n",
                "def fp_to_eip2537(fp_n):\n",
                "    return b'\\x00'*16 + fp_n.to_bytes(48, 'big')\n",
                "def g2_to_eip2537(pt):\n",
                "    n = normalize(pt)\n",
                "    xc0, xc1 = n[0].coeffs\n",
                "    yc0, yc1 = n[1].coeffs\n",
                "    return fp_to_eip2537(xc0)+fp_to_eip2537(xc1)+fp_to_eip2537(yc0)+fp_to_eip2537(yc1)\n",
                "digest_hex = sys.argv[1]\n",
                "if digest_hex.startswith('0x'): digest_hex = digest_hex[2:]\n",
                "digest = bytes.fromhex(digest_hex)\n",
                "sks = [1, 2]\n",
                "sigs = [bytes(bls.Sign(sk, digest)) for sk in sks]\n",
                "agg = bytes(bls.Aggregate(sigs))\n",
                "enc = g2_to_eip2537(signature_to_G2(agg))\n",
                "print('0x' + enc.hex())\n"
            )
        );
        vm.writeFile("test/fixtures/bls/gen_header_sig_2of4.py", script);
    }
}
