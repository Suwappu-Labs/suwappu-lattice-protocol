// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlsHashToCurve
/// @notice Hash-to-G2 kernel for BLS12-381 (suite G2_XMD:SHA-256_SSWU_RO_).
///
/// @dev =====================================================================
///      CLASSICAL BLS12-381 -- NOT POST-QUANTUM.
///      BLS12-381 is Shor-breakable on a cryptographically-relevant quantum
///      computer. This library is the Track-A CLASSICAL LEG only. The
///      post-quantum (ML-DSA) leg uses the GSX-DAG 0x0101 precompile.
///      =====================================================================
///
///      SCOPE: standalone H2C kernel (Gate 0 load-bearing piece).
///      NOT integrated into BlsQuorumHeaderVerifier or BlsValidatorRegistry --
///      that wiring (PoP-on-register, aggregate pairing, uncompressed-key
///      storage layout) is flagged for Jacob-Strokus and must be coordinated
///      with the storage-layout change to uncompressed keys.
///
///      ALGORITHM: hash_to_G2 per RFC 9380 §3 + §5:
///        1. expand_message_xmd(msg, DST, 256) -- RFC 9380 §5.3.1, SHA-256
///        2. 4x Fp element extraction with modexp mod-p reduction (MANDATORY:
///           each 64-byte chunk is 512-bit, which is > p(381-bit); EIP-2537
///           MAP_FP2_TO_G2 (0x11) reverts on non-canonical input >= p)
///        3. Two MAP_FP2_TO_G2 (0x11) calls -- one per Fp2 element u0, u1
///           (EIP-2537 includes cofactor clearing in this precompile)
///        4. G2ADD (0x0d) of the two mapped G2 points
///
///      EIP-2537 precompile addresses (Pectra / evm_version=prague):
///        0x0b  BLS12_G1ADD
///        0x0c  BLS12_G1MUL
///        0x0d  BLS12_G2ADD
///        0x0e  BLS12_G2MUL
///        0x0f  BLS12_PAIRING_CHECK
///        0x10  BLS12_MAP_FP_TO_G1
///        0x11  BLS12_MAP_FP2_TO_G2
///
///      ENCODING: EIP-2537 G2 uncompressed (256 bytes):
///        x.c0(64B) || x.c1(64B) || y.c0(64B) || y.c1(64B)
///        Each Fp = 16-zero-pad || 48-byte big-endian value.
///        c0-first matches py_ecc FQ2.coeffs[0]=c0, coeffs[1]=c1.
///
///      DST SOURCE: py_ecc.bls.ciphersuites.G2ProofOfPossession (confirmed
///        from installed package at /tmp/relayer-venv, 2026-06-09).
///        File: py_ecc/bls/ciphersuites.py
///        The trailing underscore is part of the DST per the IRTF spec.
///
///      Gas estimate (rough):
///        expand_message_xmd: ~60k (8x SHA-256 calls via 0x02)
///        8x modexp for mod-p: ~3k each = ~24k
///        2x MAP_FP2_TO_G2: ~23k each = ~46k
///        1x G2ADD: ~4.5k
///        Total: ~135k gas
library BlsHashToCurve {
    // -------------------------------------------------------------------------
    // Precompile addresses (EIP-2537, Pectra/prague)
    // -------------------------------------------------------------------------
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);

    // SHA-256 precompile (EIP-7 / Frontier)
    address internal constant SHA256_PRECOMPILE = address(0x02);

    // MODEXP precompile (EIP-198)
    address internal constant MODEXP_PRECOMPILE = address(0x05);

    // -------------------------------------------------------------------------
    // BLS12-381 field modulus p (381-bit, 48 bytes big-endian)
    // 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    // Source: https://github.com/zcash/librustzcash/blob/main/pairing/src/bls12_381/fq.rs
    // -------------------------------------------------------------------------
    bytes internal constant BLS12_FIELD_MODULUS_P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    // -------------------------------------------------------------------------
    // DST constants (byte-exact from py_ecc.bls.ciphersuites.G2ProofOfPossession)
    // -------------------------------------------------------------------------

    /// @dev Signing DST used by G2ProofOfPossession.Sign / hash_to_G2.
    ///      Source: py_ecc/bls/ciphersuites.py, G2ProofOfPossession.DST
    ///      ASCII: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_  (43 bytes)
    ///      The trailing underscore is part of the ciphersuite identifier.
    bytes internal constant DST_SIG =
        hex"424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f";

    /// @dev PoP DST used by G2ProofOfPossession.PopProve only (out of scope).
    ///      Source: py_ecc/bls/ciphersuites.py, G2ProofOfPossession.POP_TAG
    ///      ASCII: BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_  (43 bytes)
    bytes internal constant DST_POP =
        hex"424c535f504f505f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f";

    // -------------------------------------------------------------------------
    // Public entry point
    // -------------------------------------------------------------------------

    /// @notice Hash arbitrary bytes to a G2 point using the BLS_SIG DST.
    ///         Implements RFC 9380 hash_to_curve suite
    ///         G2_XMD:SHA-256_SSWU_RO_ (used by py_ecc G2ProofOfPossession.Sign).
    ///
    /// @param  msg  The message to hash. Any length; typically a 32-byte digest.
    /// @return      256-byte EIP-2537 uncompressed G2 point:
    ///              x.c0(64B) || x.c1(64B) || y.c0(64B) || y.c1(64B).
    ///
    /// IMPORTANT: requires evm_version = "prague" (EIP-2537 precompiles active).
    ///            Reverts if any precompile call fails.
    function hashToG2(bytes memory msg) internal view returns (bytes memory) {
        return _hashToG2WithDst(msg, DST_SIG);
    }

    // -------------------------------------------------------------------------
    // Internal implementation
    // -------------------------------------------------------------------------

    function _hashToG2WithDst(bytes memory msg, bytes memory dst)
        internal
        view
        returns (bytes memory)
    {
        // Step 1: expand_message_xmd(msg, DST, 256) -- RFC 9380 §5.3.1
        bytes memory uniform = _expandMessageXmd(msg, dst, 256);

        // Step 2: extract 4 Fp elements (64 bytes each) and reduce mod p.
        // Each chunk is 512-bit; BLS12-381 p is 381-bit. Reduction is MANDATORY:
        // EIP-2537 MAP_FP2_TO_G2 (0x11) reverts if any Fp element >= p.
        // Returns EIP-2537 Fp format: 16-zero-pad || 48-byte big-endian.
        bytes memory e0 = _reduceFpFromUniform(uniform, 0);   // u[0].c0
        bytes memory e1 = _reduceFpFromUniform(uniform, 64);  // u[0].c1
        bytes memory e2 = _reduceFpFromUniform(uniform, 128); // u[1].c0
        bytes memory e3 = _reduceFpFromUniform(uniform, 192); // u[1].c1

        // Step 3: MAP_FP2_TO_G2 for each Fp2 element.
        // Input: c0(64B) || c1(64B) = 128 bytes.
        // EIP-2537 includes cofactor clearing inside this precompile.
        bytes memory q0 = _mapFp2ToG2(e0, e1);
        bytes memory q1 = _mapFp2ToG2(e2, e3);

        // Step 4: G2ADD the two mapped points.
        // clear_cofactor(Q0) + clear_cofactor(Q1) = result H.
        return _g2Add(q0, q1);
    }

    // -------------------------------------------------------------------------
    // expand_message_xmd -- RFC 9380 §5.3.1
    //   H = SHA-256, b_in_bytes = 32, r_in_bytes = 64 (SHA-256 block size)
    //   ell = ceil(len_in_bytes / b_in_bytes) = ceil(256 / 32) = 8
    //
    //   DST_prime = DST || I2OSP(len(DST), 1)
    //   msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
    //   b_0 = H(msg_prime)
    //   b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    //   b_i = H((b_0 XOR b_{i-1}) || I2OSP(i, 1) || DST_prime)  for i in 2..ell
    // -------------------------------------------------------------------------
    function _expandMessageXmd(bytes memory msg, bytes memory dst, uint256 lenInBytes)
        internal
        view
        returns (bytes memory)
    {
        uint256 bInBytes = 32; // SHA-256 output block length
        uint256 rInBytes = 64; // SHA-256 input block size (Z_pad length)
        uint256 ell = (lenInBytes + bInBytes - 1) / bInBytes; // 8 for lenInBytes=256

        // DST_prime = DST || I2OSP(len(DST), 1)
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));

        // msg_prime = Z_pad(64) || msg || I2OSP(lenInBytes, 2) || I2OSP(0, 1) || DST_prime
        bytes memory msgPrime = abi.encodePacked(
            new bytes(rInBytes), // Z_pad: 64 zero bytes
            msg,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint16(lenInBytes), // I2OSP(256, 2) -- safe: lenInBytes=256 fits uint16
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(0), // I2OSP(0, 1) -- constant 0, always safe
            dstPrime
        );

        // b_0 = H(msg_prime)
        bytes32 b0 = _sha256(msgPrime);

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 bPrev = _sha256(abi.encodePacked(b0, uint8(1), dstPrime)); // uint8(1): constant, safe

        bytes memory out = new bytes(lenInBytes);

        // Write b_1 into out[0..31]
        assembly {
            mstore(add(out, 32), bPrev)
        }

        // b_i for i = 2 .. ell: write into out[(i-1)*32..(i-1)*32+31]
        for (uint256 i = 2; i <= ell; i++) {
            bytes32 xored = b0 ^ bPrev;
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes32 bI = _sha256(abi.encodePacked(xored, uint8(i), dstPrime)); // i<=8, safe
            uint256 wordOffset = (i - 1) * bInBytes; // byte offset from out[0]
            assembly {
                mstore(add(add(out, 32), wordOffset), bI)
            }
            bPrev = bI;
        }

        return out;
    }

    // -------------------------------------------------------------------------
    // Fp mod-p reduction via MODEXP (0x05)
    //
    // EIP-198 call format:
    //   I2OSP(Bsize, 32) || I2OSP(Esize, 32) || I2OSP(Msize, 32) || B || E || M
    // We compute: base^1 mod p  (i.e., base mod p) where base is 64 bytes.
    // Output is 48 bytes (right-justified to mod length).
    // We then left-pad to 64 bytes for EIP-2537 Fp format.
    // -------------------------------------------------------------------------

    /// @dev Extract a 64-byte chunk from `uniform` at `byteOffset`, reduce mod p,
    ///      and return the result as a 64-byte EIP-2537 Fp: 16-zero-pad || 48-byte value.
    function _reduceFpFromUniform(bytes memory uniform, uint256 byteOffset)
        internal
        view
        returns (bytes memory)
    {
        // Extract 64-byte chunk into a bytes memory for the modexp base.
        bytes memory chunk = new bytes(64);
        assembly {
            let src := add(add(uniform, 32), byteOffset)
            mstore(add(chunk, 32), mload(src))
            mstore(add(chunk, 64), mload(add(src, 32)))
        }

        // MODEXP: base^1 mod p
        // base=64B, exp=1B (value 0x01), mod=48B (p)
        bytes memory modExpInput = abi.encodePacked(
            uint256(64), // Bsize
            uint256(1), // Esize
            uint256(48), // Msize
            chunk, // B: 64 bytes
            uint8(1), // E: 1 byte, value = 1
            BLS12_FIELD_MODULUS_P // M: 48 bytes
        );

        (bool ok, bytes memory reduced) = MODEXP_PRECOMPILE.staticcall(modExpInput);
        require(ok, "BlsHashToCurve: modexp failed");
        // MODEXP returns exactly Msize=48 bytes (right-justified, zero-padded if needed)
        require(reduced.length == 48, "BlsHashToCurve: modexp bad length");

        // Build EIP-2537 Fp: 16 zero bytes || 48-byte reduced value
        bytes memory fp = new bytes(64);
        // fp is zero-initialised; copy reduced into fp[16..63]
        for (uint256 i = 0; i < 48; i++) {
            fp[16 + i] = reduced[i];
        }
        return fp;
    }

    // -------------------------------------------------------------------------
    // EIP-2537 precompile wrappers
    // -------------------------------------------------------------------------

    /// @dev MAP_FP2_TO_G2 (0x11): map an Fp2 element to a G2 point.
    ///      Input: c0(64B) || c1(64B) = 128 bytes.  Output: 256-byte G2 point.
    ///      Cofactor clearing is performed inside the precompile.
    function _mapFp2ToG2(bytes memory c0, bytes memory c1) internal view returns (bytes memory) {
        bytes memory input = abi.encodePacked(c0, c1);
        require(input.length == 128, "BlsHashToCurve: MAP_FP2_TO_G2 bad input");
        (bool ok, bytes memory result) = BLS12_MAP_FP2_TO_G2.staticcall(input);
        require(ok, "BlsHashToCurve: MAP_FP2_TO_G2 failed");
        require(result.length == 256, "BlsHashToCurve: MAP_FP2_TO_G2 bad output");
        return result;
    }

    /// @dev G2ADD (0x0d): add two G2 points.
    ///      Input: p0(256B) || p1(256B) = 512 bytes.  Output: 256-byte G2 point.
    function _g2Add(bytes memory p0, bytes memory p1) internal view returns (bytes memory) {
        bytes memory input = abi.encodePacked(p0, p1);
        require(input.length == 512, "BlsHashToCurve: G2ADD bad input");
        (bool ok, bytes memory result) = BLS12_G2ADD.staticcall(input);
        require(ok, "BlsHashToCurve: G2ADD failed");
        require(result.length == 256, "BlsHashToCurve: G2ADD bad output");
        return result;
    }

    /// @dev SHA-256 hash via precompile 0x02.
    function _sha256(bytes memory data) internal view returns (bytes32) {
        (bool ok, bytes memory result) = SHA256_PRECOMPILE.staticcall(data);
        require(ok, "BlsHashToCurve: SHA256 failed");
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes32(result); // result is SHA-256 output: always 32 bytes
    }
}
