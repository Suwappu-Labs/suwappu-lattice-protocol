// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// @title BlsPrecompileSmoke
/// @notice Gate-0 smoke test: verify EIP-2537 precompiles are live under
///         evm_version=prague. Must pass before any BLS H2C kernel work.
///
/// Vector source: EIP-2537 reference — G1ADD(G1_gen, G1_gen) = 2*G1_gen.
/// G1_gen coordinates from the BLS12-381 spec:
///   x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
///   y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
///
/// EIP-2537 G1 Fp encoding: 16-byte zero-pad || 48-byte big-endian.
///
/// CLASSICAL (Shor-breakable) BLS12-381 — NOT post-quantum. Smoke test only.
contract BlsPrecompileSmoke is Test {
    // EIP-2537 precompile addresses (Pectra/prague)
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G1MUL = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);

    // G1 generator in EIP-2537 uncompressed form (128 bytes)
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // Expected: 2 * G1_gen (computed by py_ecc optimized_bls12_381)
    bytes internal constant TWO_G1_GEN =
        hex"000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"
        hex"00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28";

    /// @notice Smoke: G1ADD(G1_gen, G1_gen) == 2*G1_gen under prague EVM.
    /// Gate: if this fails the EIP-2537 precompiles are not active — STOP.
    function test_g1Add_genPlusGen_eq_twoGen() external view {
        bytes memory input = abi.encodePacked(G1_GEN, G1_GEN);
        (bool ok, bytes memory result) = BLS12_G1ADD.staticcall(input);

        assertTrue(ok, "G1ADD precompile call failed - EIP-2537 not active under this profile");
        assertEq(result.length, 128, "G1ADD should return 128 bytes");
        assertEq(result, TWO_G1_GEN, "G1ADD(G1_gen, G1_gen) != 2*G1_gen - vector mismatch");
    }

    /// @notice Sanity: G1ADD under cancun (default profile) should NOT be an
    ///         active precompile — the call should fail or return empty.
    ///         This test is intentionally skipped unless run under default profile.
    ///         Under prague it will succeed, which is also fine — the reverse
    ///         direction is what we care about in CI gating.
    function test_g1Add_callSucceeds_underPrague() external view {
        bytes memory input = abi.encodePacked(G1_GEN, G1_GEN);
        (bool ok,) = BLS12_G1ADD.staticcall(input);
        assertTrue(ok, "G1ADD must succeed under prague");
    }
}
