// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";
import {BlsValidatorRegistry} from "./BlsValidatorRegistry.sol";
import {BlsHashToCurve} from "../crypto/BlsHashToCurve.sol";

/// @title BlsQuorumHeaderVerifier
/// @author Suwappu Labs
/// @notice Track-A classical BLS leg: finalizes a GSX-DAG block's EVM state root
///         once a >2/3-stake quorum of the registered validator set provides a valid
///         BLS12-381 aggregate signature, verified via real EIP-2537 precompiles.
///
/// @dev ======================================================================
///      SECURITY FRAMING — read before any audit, integration or deployment:
///      ======================================================================
///
///      CLASSICAL BLS12-381 — NOT POST-QUANTUM.
///      BLS12-381 aggregate signatures are Shor-breakable on a cryptographically-
///      relevant quantum computer. This contract is the TRACK-A EXCEPTION ZONE:
///      trust-minimized bridge finality on STOCK EVMs (Ethereum, Base) where the
///      GSX-DAG ML-DSA precompile (0x0101) does not exist.
///
///      REAL EIP-2537 WIRING (not a mock):
///        This contract uses the real EIP-2537 precompiles active in Ethereum Pectra
///        (evm_version=prague). It requires deployment on a prague-compatible chain.
///        Test suite is validated against real py_ecc golden vectors via FFI.
///
///      ROGUE-KEY DEFENSE:
///        Rogue-key attacks are blocked at the REGISTRY level: BlsValidatorRegistry
///        requires a proof-of-possession (PoP) for every registered key. A rogue key
///        roguePk = targetPk − Σ(otherPks) cannot be registered without a valid PoP,
///        which requires knowledge of the corresponding secret key.
///
///      PAIRING EQUATION:
///        e(aggPk, H(digest)) == e(G1, aggSig)
///        Implemented as: pairing([(aggPk, H(digest)), (−G1, aggSig)]) == 1
///        where H(digest) = BlsHashToCurve.hashToG2(digest) under DST_SIG.
///        aggPk = Σ of registry G1 pubkeys for flagged signers (on-chain G1ADD).
///
///      TRUST MODEL (sync-committee style):
///        Correctness rests on an honest >2/3-stake quorum of the tracked set.
///        Equivocation guard: a conflicting root for a finalized block reverts.
///        Digest binding: keccak256(HEADER_DOMAIN || networkId || this || blockNumber
///                                   || stateRoot) prevents cross-deployment replay.
///
///      STORAGE:
///        Registry stores 128-byte uncompressed G1 pubkeys. G1ADD takes 256 bytes
///        (two 128-byte uncompressed points). No on-chain decompression needed.
///      ======================================================================
contract BlsQuorumHeaderVerifier is ISourceHeaderOracle {
    /// @notice EIP-2537 G1ADD precompile (BLS12_G1ADD, 0x0b).
    address public constant BLS_G1ADD = address(0x0b);
    /// @notice EIP-2537 PAIRING_CHECK precompile (0x0f).
    address public constant BLS_PAIRING = address(0x0f);

    /// @notice Domain separator for header attestation digests.
    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1");

    // negated G1 generator (py_ecc neg(G1) uncompressed, EIP-2537 128B)
    // used in the two-pair pairing check: pairing([(aggPk,Hm),(negG1,aggSig)])==1
    bytes internal constant NEG_G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    /// @notice Validator registry supplying pubkeys and stakes.
    BlsValidatorRegistry public immutable registry;
    /// @notice The GSX-DAG source chain ID this oracle serves.
    uint256 public immutable gsxDagChainId;

    /// blockNumber => finalized EVM state root
    mapping(uint256 => bytes32) private _stateRoots;

    /// @notice Emitted when a block's state root is finalized.
    /// @param blockNumber The finalized GSX-DAG block.
    /// @param stateRoot   The accepted EVM state root.
    /// @param epoch       The signing epoch.
    /// @param sigStake    Aggregate stake of the signing validators.
    event HeaderFinalized(
        uint256 indexed blockNumber,
        bytes32 stateRoot,
        uint256 indexed epoch,
        uint256 indexed sigStake
    );

    error ZeroStateRoot();
    error HeaderConflict(uint256 blockNumber);
    error StaleEpoch(uint256 epoch, uint256 currentEpoch);
    error BelowQuorum(uint256 sigStake, uint256 needed);
    error InvalidAggregateSig();
    error PrecompileFailed(address precompile);
    error EmptySignerSet();

    /// @notice Deploy the verifier.
    /// @param registry_      Address of the BlsValidatorRegistry.
    /// @param gsxDagChainId_ GSX-DAG source chain ID.
    constructor(BlsValidatorRegistry registry_, uint256 gsxDagChainId_) {
        require(address(registry_) != address(0), "BQHV: zero registry");
        require(gsxDagChainId_ != 0, "BQHV: zero chainId");
        registry = registry_;
        gsxDagChainId = gsxDagChainId_;
    }

    /// @notice Finalize `stateRoot` for `blockNumber`, proven by a >2/3-stake quorum
    ///         of the BLS validator set at `epoch` providing a valid BLS12-381
    ///         aggregate signature.
    ///
    /// @dev The aggregate pubkey is derived ENTIRELY ON-CHAIN from the registry.
    ///      The caller supplies ONLY the signer bitmap and the aggregate signature.
    ///      No pubkey material is caller-trusted.
    ///
    /// @param blockNumber   The GSX-DAG block being attested.
    /// @param stateRoot     The EVM state root at that block.
    /// @param epoch         Signing epoch (must equal registry.currentEpoch()).
    /// @param signerBitmap  Bitmask over epoch's validator indices (bit i = signer i signed).
    /// @param aggregateSig  BLS12-381 aggregate G2 signature (256 bytes, EIP-2537 uncompressed).
    function submitHeader(
        uint256 blockNumber,
        bytes32 stateRoot,
        uint256 epoch,
        uint256 signerBitmap,
        bytes calldata aggregateSig
    ) external {
        if (stateRoot == bytes32(0)) revert ZeroStateRoot();

        bytes32 existing = _stateRoots[blockNumber];
        if (existing != bytes32(0)) {
            if (existing != stateRoot) revert HeaderConflict(blockNumber);
            return; // idempotent
        }

        uint256 cur = registry.currentEpoch();
        if (epoch != cur) revert StaleEpoch(epoch, cur);

        // Digest binding: keccak256 domain separates networks and deployments.
        bytes32 digest = keccak256(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );

        // ---- Build aggregate pubkey on-chain from registry ----
        uint256 n = registry.validatorCount(epoch);
        uint256 sigStake = 0;
        bytes memory aggPubkey;
        bool first = true;
        uint256 signerCount = 0;

        for (uint256 i = 0; i < n; ++i) {
            if (signerBitmap & (1 << i) == 0) continue;

            bytes memory pubkey = registry.blsPubkey(epoch, i);
            bytes32 pkHash = keccak256(pubkey);
            uint256 stake = registry.stakeOf(epoch, pkHash);
            if (stake == 0) continue;

            sigStake += stake;

            if (first) {
                aggPubkey = pubkey;
                first = false;
            } else {
                aggPubkey = _g1Add(aggPubkey, pubkey);
            }
            ++signerCount;
        }

        if (signerCount == 0) revert EmptySignerSet();

        uint256 needed = registry.quorumThreshold(epoch);
        if (sigStake < needed) revert BelowQuorum(sigStake, needed);

        // ---- Real BLS12-381 aggregate verify via EIP-2537 ----
        // H(m) = hashToG2(digest) using DST_SIG (matches py_ecc G2ProofOfPossession)
        // Check: pairing([(aggPk, H(m)), (−G1, aggSig)]) == 1
        bytes memory hm = BlsHashToCurve.hashToG2(abi.encodePacked(digest));
        bool valid = _blsVerify(aggPubkey, hm, aggregateSig);
        if (!valid) revert InvalidAggregateSig();

        _stateRoots[blockNumber] = stateRoot;
        emit HeaderFinalized(blockNumber, stateRoot, epoch, sigStake);
    }

    /// @inheritdoc ISourceHeaderOracle
    function headerStateRoot(uint256 chainId, uint256 blockNumber)
        external
        view
        override
        returns (bytes32)
    {
        if (chainId != gsxDagChainId) return bytes32(0);
        return _stateRoots[blockNumber];
    }

    /// @notice The header digest validators must BLS-sign.
    /// @param blockNumber The block number being attested.
    /// @param stateRoot   The EVM state root being attested.
    function headerDigest(uint256 blockNumber, bytes32 stateRoot) external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );
    }

    // ---- EIP-2537 precompile wrappers ----

    /// @dev G1ADD (0x0b): aggregate two uncompressed G1 pubkeys (128 bytes each).
    ///      Input: 256 bytes (two 128-byte EIP-2537 G1 points).
    ///      Output: 128-byte G1 point.
    function _g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory result) {
        require(a.length == 128 && b.length == 128, "BQHV: G1ADD bad input");
        bytes memory input = abi.encodePacked(a, b);
        (bool ok, bytes memory out) = BLS_G1ADD.staticcall(input);
        if (!ok || out.length == 0) revert PrecompileFailed(BLS_G1ADD);
        return out;
    }

    /// @notice BLS pairing verify: e(aggPk, H(m)) == e(G1, aggSig).
    ///         Implemented as PAIRING_CHECK([(aggPk, Hm), (−G1, aggSig)]) == 1.
    ///         Input: (G1||G2)*2 = (128+256)*2 = 768 bytes.
    ///
    /// @param aggPk   128-byte G1 aggregate pubkey (EIP-2537 uncompressed).
    /// @param hm      256-byte G2 H(digest) from BlsHashToCurve.hashToG2.
    /// @param aggSig  256-byte G2 aggregate signature (EIP-2537 uncompressed).
    function _blsVerify(bytes memory aggPk, bytes memory hm, bytes calldata aggSig)
        internal
        view
        returns (bool)
    {
        require(aggPk.length == 128, "BQHV: aggPk len");
        require(hm.length == 256, "BQHV: hm len");
        require(aggSig.length == 256, "BQHV: aggSig len");

        // pair 0: (aggPk, H(m))   — 128 + 256 = 384 bytes
        // pair 1: (negG1, aggSig) — 128 + 256 = 384 bytes
        // total: 768 bytes
        bytes memory input = abi.encodePacked(aggPk, hm, NEG_G1_GEN, aggSig);
        require(input.length == 768, "BQHV: pairing input len");

        (bool ok, bytes memory out) = BLS_PAIRING.staticcall(input);
        if (!ok || out.length == 0) revert PrecompileFailed(BLS_PAIRING);
        return out[out.length - 1] == 0x01;
    }
}
