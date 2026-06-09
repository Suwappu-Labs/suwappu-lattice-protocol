// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BlsHashToCurve} from "../crypto/BlsHashToCurve.sol";

/// @title BlsValidatorRegistry
/// @author Suwappu Labs
/// @notice On-chain GSX-DAG validator set (BLS12-381 public keys + stakes) for the
///         classical BLS aggregate quorum leg, with proof-of-possession (PoP)
///         enforcement at registration to defeat rogue-key attacks.
///
/// @dev =====================================================================
///      CLASSICAL BLS12-381 -- NOT POST-QUANTUM.
///      BLS12-381 is Shor-breakable on a cryptographically-relevant quantum
///      computer. This is the Track-A CLASSICAL LEG for stock EVMs that lack
///      the GSX-DAG ML-DSA precompile (0x0101). The post-quantum (ML-DSA) leg
///      uses GsxDagValidatorRegistry.
///      =====================================================================
///
///      STORAGE LAYOUT: 128-byte UNCOMPRESSED G1 pubkeys in EIP-2537 format.
///        x(64B) || y(64B), each Fp = 16-zero-pad || 48-byte big-endian.
///        (Previous draft used 48-byte compressed; changed because EIP-2537 G1ADD
///        requires 128-byte uncompressed input — no on-chain decompression exists.)
///
///      ROGUE-KEY DEFENSE — PoP:
///        A bare-aggregate BLS verify e(aggPk,H(m))==e(g,aggSig) is forgeable via
///        the rogue-key attack: register roguePk = targetPk − Σ(otherPks). The fix
///        is proof-of-possession: each validator must supply a G2 signature over
///        their own (compressed) G1 pubkey under DST_POP at registration time.
///        The contract verifies this via EIP-2537 PAIRING_CHECK (0x0f).
///        NOTE: requires evm_version = "prague" (EIP-2537 precompiles active).
///
///      KEY FORMAT:
///        G1 pubkey (uncompressed, 128 bytes): x(64) || y(64)
///          each Fp: 16 zero bytes || 48-byte big-endian value.
///        G2 pop (uncompressed, 256 bytes): x.c0(64)||x.c1(64)||y.c0(64)||y.c1(64)
///          same Fp encoding, c0-first = py_ecc FQ2.coeffs[0].
///
///      Why compressed-key hashing for PoP?
///        py_ecc PopProve signs the COMPRESSED (48-byte) G1 pubkey. The contract
///        reconstructs the compressed form on-chain using the sign-bit rule from
///        py_ecc (a_flag = (y * 2) / q), then calls hashToG2WithDst(compressed, DST_POP).
contract BlsValidatorRegistry {
    /// @notice EIP-2537 G1ADD precompile (used to aggregate pubkeys).
    address public constant BLS_G1ADD = address(0x0b);
    /// @notice EIP-2537 PAIRING_CHECK precompile (used in PoP verify).
    address public constant BLS_PAIRING = address(0x0f);

    // BLS12-381 field modulus p (381-bit; used for a_flag sign bit in compression)
    bytes internal constant BLS12_FIELD_MODULUS_P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    // negated G1 generator for pairing check: neg(G1) has same x, y = p − y.
    // pairing([(pubkey, Hpk), (negG1, pop)]) == 1  ⟺  e(pubkey,Hpk)==e(G1,pop)
    // Source: py_ecc neg(G1) normalized → EIP-2537 128B.
    bytes internal constant NEG_G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// @notice Registry administrator (Timelock in production).
    address public admin;
    /// @notice Network ID binding digests to this GSX-DAG deployment.
    uint256 public immutable networkId;
    /// @notice Current epoch number.
    uint256 public currentEpoch;
    /// @notice Whether epoch 0 has been bootstrapped.
    bool public bootstrapped;

    /// @notice epoch => validator index => uncompressed G1 pubkey (128 bytes, EIP-2537).
    mapping(uint256 => mapping(uint256 => bytes)) public blsPubkey;
    /// @notice epoch => keccak256(blsPubkey) => stake (0 = absent).
    mapping(uint256 => mapping(bytes32 => uint256)) public stakeOf;
    /// @notice epoch => total number of validators in that epoch.
    mapping(uint256 => uint256) public validatorCount;
    /// @notice epoch => total stake for that epoch.
    mapping(uint256 => uint256) public totalStake;

    /// @notice Emitted when epoch 0 is governance-bootstrapped.
    /// @param epoch Always 0.
    /// @param validatorCount Number of validators installed.
    /// @param totalStake_ Sum of all validator stakes.
    event EpochBootstrapped(
        uint256 indexed epoch,
        uint256 indexed validatorCount,
        uint256 indexed totalStake_
    );

    /// @notice Emitted when a new epoch is installed by the admin.
    /// @param epoch The new epoch number.
    /// @param validatorCount Number of validators installed.
    /// @param totalStake_ Sum of all validator stakes.
    event EpochInstalled(
        uint256 indexed epoch,
        uint256 indexed validatorCount,
        uint256 indexed totalStake_
    );

    error Unauthorized();
    error AlreadyBootstrapped();
    error NotBootstrapped();
    error LengthMismatch();
    error EmptySet();
    error ZeroStake();
    error BadEpoch(uint256 expected, uint256 got);
    error InvalidPubkeyLength(uint256 index, uint256 len);
    error InvalidPubkey(uint256 index);
    error InvalidPopLength(uint256 index, uint256 len);
    error DuplicatePubkey(uint256 index);
    error SetTooLarge();
    error InvalidPoP(uint256 index);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    /// @notice Deploy the registry.
    /// @param admin_     Admin address (Timelock in production).
    /// @param networkId_ GSX-DAG network ID (binds digests to this deployment).
    constructor(address admin_, uint256 networkId_) {
        require(admin_ != address(0), "BVR: zero admin");
        admin = admin_;
        networkId = networkId_;
    }

    /// @notice Governance-bootstrap epoch 0. The unavoidable trust root.
    ///         Each pubkey must be 128 bytes (BLS12-381 G1 uncompressed, EIP-2537).
    ///         Each pop must be 256 bytes (BLS12-381 G2 uncompressed, EIP-2537).
    ///         Proof-of-possession is verified for every validator; reverts with
    ///         InvalidPoP(i) if PoP for validator i fails.
    ///         REQUIRES evm_version=prague (EIP-2537 precompiles for PoP verification).
    /// @param pubkeys 128-byte uncompressed G1 pubkeys, one per validator.
    /// @param stakes  Stake amounts, one per validator.
    /// @param pops    256-byte uncompressed G2 PoP signatures, one per validator.
    function bootstrapEpoch0(
        bytes[] calldata pubkeys,
        uint256[] calldata stakes,
        bytes[] calldata pops
    ) external onlyAdmin {
        if (bootstrapped) revert AlreadyBootstrapped();
        _installSet(0, pubkeys, stakes, pops);
        bootstrapped = true;
        emit EpochBootstrapped(0, pubkeys.length, totalStake[0]);
    }

    /// @notice Admin-controlled epoch transition. Installs `newEpoch`'s validator set.
    ///         PoP is verified for every validator; reverts InvalidPoP(i) if it fails.
    /// @param newEpoch Must be currentEpoch + 1.
    /// @param pubkeys  128-byte uncompressed G1 pubkeys, one per validator.
    /// @param stakes   Stake amounts, one per validator.
    /// @param pops     256-byte uncompressed G2 PoP signatures, one per validator.
    function installEpoch(
        uint256 newEpoch,
        bytes[] calldata pubkeys,
        uint256[] calldata stakes,
        bytes[] calldata pops
    ) external onlyAdmin {
        if (!bootstrapped) revert NotBootstrapped();
        if (newEpoch != currentEpoch + 1) revert BadEpoch(currentEpoch + 1, newEpoch);
        _installSet(newEpoch, pubkeys, stakes, pops);
        currentEpoch = newEpoch;
        emit EpochInstalled(newEpoch, pubkeys.length, totalStake[newEpoch]);
    }

    /// @notice >2/3-stake quorum threshold for `epoch`.
    /// @param epoch Epoch to query.
    function quorumThreshold(uint256 epoch) external view returns (uint256) {
        return (totalStake[epoch] * 2) / 3 + 1;
    }

    /// @notice Stake of a validator identified by pubkey hash, in `epoch`.
    /// @param epoch   Epoch to query.
    /// @param pkHash  keccak256 of the validator's 128-byte uncompressed pubkey.
    function stakeByHash(uint256 epoch, bytes32 pkHash) external view returns (uint256) {
        return stakeOf[epoch][pkHash];
    }

    /// @notice Expose G1 compression for golden-vector testing.
    ///         Compresses a 128-byte EIP-2537 uncompressed G1 pubkey to 48-byte form.
    ///         This is the same function used internally to compute PoP input.
    /// @param pk128 128-byte uncompressed G1 pubkey (EIP-2537 format).
    function compressG1Public(bytes calldata pk128) external pure returns (bytes memory) {
        return _compressG1(pk128);
    }

    // ---- internals ----

    function _installSet(
        uint256 epoch,
        bytes[] calldata pubkeys,
        uint256[] calldata stakes,
        bytes[] calldata pops
    ) internal {
        uint256 n = pubkeys.length;
        if (n != stakes.length) revert LengthMismatch();
        if (n != pops.length) revert LengthMismatch();
        if (n == 0) revert EmptySet();
        // signerBitmap in BlsQuorumHeaderVerifier is uint256 — cap at 256.
        if (n > 256) revert SetTooLarge();
        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            // Uncompressed G1: 128 bytes (EIP-2537)
            if (pubkeys[i].length != 128) revert InvalidPubkeyLength(i, pubkeys[i].length);
            // Uncompressed G2 PoP: 256 bytes (EIP-2537)
            if (pops[i].length != 256) revert InvalidPopLength(i, pops[i].length);
            // KeyValidate (defense-in-depth, adversarial-review note): reject the
            // point at infinity (all-zero G1). An infinity key + infinity PoP both
            // pairings == 1 so it would pass _popCheck; it contributes the identity
            // to the aggregate (zero signing power) so it's not exploitable under
            // onlyAdmin registration, but reject it explicitly.
            if (_isZero(pubkeys[i])) revert InvalidPubkey(i);
            if (stakes[i] == 0) revert ZeroStake();
            bytes32 pkHash = keccak256(pubkeys[i]);
            if (stakeOf[epoch][pkHash] != 0) revert DuplicatePubkey(i);

            // Rogue-key defense: verify proof-of-possession BEFORE recording stake.
            // PoP signs the COMPRESSED (48-byte) key under DST_POP.
            // Compressed form is derived on-chain from the uncompressed key.
            if (!_popCheck(pubkeys[i], pops[i])) revert InvalidPoP(i);

            stakeOf[epoch][pkHash] = stakes[i];
            blsPubkey[epoch][i] = pubkeys[i];
            total += stakes[i];
        }
        validatorCount[epoch] = n;
        totalStake[epoch] = total;
    }

    /// @notice Verify a single PoP: e(pubkey, H(compress(pubkey), DST_POP)) == e(G1, pop).
    ///         Pairing check: pairing([(pubkey, Hpk), (negG1, pop)]) == 1.
    ///
    /// @dev Requires prague EIP-2537. Returns false if precompile absent.
    ///      Uses DST_POP (BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_).
    ///
    ///      py_ecc PopProve(sk): sign COMPRESSED key under DST_POP.
    ///      On-chain: compress pubkey → 48 bytes, hash to G2 with DST_POP.
    /// @param pubkey128 128-byte uncompressed G1 pubkey.
    /// @param pop256    256-byte uncompressed G2 PoP signature.
    function popVerify(bytes memory pubkey128, bytes memory pop256) public view returns (bool) {
        return _popCheck(pubkey128, pop256);
    }

    /// @dev True iff every byte of `b` is zero (the EIP-2537 G1 point at infinity).
    function _isZero(bytes memory b) internal pure returns (bool) {
        for (uint256 i = 0; i < b.length; ++i) {
            if (b[i] != 0) return false;
        }
        return true;
    }

    function _popCheck(bytes memory pubkey128, bytes memory pop256)
        internal
        view
        returns (bool)
    {
        bytes memory compressedPk = _compressG1(pubkey128);
        bytes memory hPk = BlsHashToCurve._hashToG2WithDst(compressedPk, BlsHashToCurve.DST_POP);

        // pairing([(pubkey, hPk), (negG1, pop)]) == 1
        bytes memory pairingInput = abi.encodePacked(pubkey128, hPk, NEG_G1_GEN, pop256);
        require(pairingInput.length == 768, "BVR: bad pairing input");

        (bool ok, bytes memory result) = BLS_PAIRING.staticcall(pairingInput);
        if (!ok || result.length == 0) return false;
        return result[result.length - 1] == 0x01;
    }

    /// @notice Compress an uncompressed G1 point (128 bytes, EIP-2537) to 48 bytes.
    ///         Encoding matches py_ecc compress_G1 / blst point compression.
    ///
    /// @dev G1 compressed: c_flag=1 (bit 383) | a_flag=sign(y) (bit 381) | x (381 bits).
    ///      a_flag = 1 iff y > (q-1)/2  (py_ecc: a_flag = (y.n * 2) // q).
    ///      Fp layout (EIP-2537): 64 bytes = 16 zero-pad || 48-byte big-endian.
    ///      x is at pk128[0..63], y is at pk128[64..127].
    /// @param pk128 128-byte uncompressed G1 pubkey (EIP-2537 format).
    function _compressG1(bytes memory pk128) internal pure returns (bytes memory) {
        bytes memory compressed = new bytes(48);

        // Copy x value (bytes 16..63 of the x field) into compressed[0..47]
        for (uint256 i = 0; i < 48; ++i) {
            compressed[i] = pk128[16 + i];
        }

        // a_flag = 1 iff y > (q-1)/2.
        // y Fp value is at pk128[80..127] (skip 16 zero-pad bytes in the y slot).
        // (q-1)/2 = 0x0d0088f51cbff34d...fd555 (48 bytes)
        bytes memory halfQ =
            hex"0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555";

        bool aFlag = false;
        for (uint256 i = 0; i < 48; ++i) {
            uint8 yByte = uint8(pk128[80 + i]);
            uint8 hByte = uint8(halfQ[i]);
            if (yByte > hByte) {
                aFlag = true;
                break;
            } else if (yByte < hByte) {
                break;
            }
        }

        // Set c_flag (bit 383 = bit 7 of byte 0) and a_flag (bit 381 = bit 5 of byte 0)
        compressed[0] = bytes1(uint8(compressed[0]) | 0x80);
        if (aFlag) {
            compressed[0] = bytes1(uint8(compressed[0]) | 0x20);
        }

        return compressed;
    }
}
