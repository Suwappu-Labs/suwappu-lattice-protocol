// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";
import {BlsValidatorRegistry} from "./BlsValidatorRegistry.sol";

/// @title BlsQuorumHeaderVerifier
/// @notice Track-A legacy leg: finalizes a GSX-DAG block's EVM state root once a
///         >2/3-stake quorum of the BLS validator set (BlsValidatorRegistry)
///         aggregate-BLS-signs a header attestation. An ISourceHeaderOracle.
///
/// @dev ======================================================================
///      SECURITY FRAMING — read before any audit, integration or deployment:
///      ======================================================================
///
///      CLASSICAL BLS12-381 — NOT POST-QUANTUM.
///      BLS12-381 aggregate signatures are Shor-breakable on a cryptographically-
///      relevant quantum computer. This contract is the TRACK-A EXCEPTION ZONE:
///      it provides trust-minimized bridge finality on STOCK EVMs (Ethereum, Base,
///      any EVM-compatible chain) where the GSX-DAG ML-DSA precompile (0x0101)
///      does not exist and ML-DSA cannot be verified cheaply. The security model
///      is: trust an honest >2/3-stake quorum of the registered validator set —
///      the same quorum fraction as the ML-DSA leg, classical rather than PQ.
///
///      TRUST MODEL (sync-committee style):
///        - Correctness rests on an honest >2/3-stake quorum of the tracked set.
///        - The tracked set is governance-bootstrapped (epoch 0) and admin-
///          transitioned (BlsValidatorRegistry.installEpoch). The admin should be
///          a TimelockController in production.
///        - A conflicting root for a finalized block can never be accepted
///          (equivocation guard); a duplicate identical submission is a no-op.
///        - The digest binds networkId + this contract address, preventing replay
///          to another deployment or network.
///
///      EIP-2537 STATUS — TOOLING BLOCKER (PENDING):
///        - Real BLS12-381 verification uses the EIP-2537 precompiles
///          (G1ADD: 0x0b, G1MUL: 0x0c, G2ADD: 0x0d, BLS12_PAIRING: 0x10, etc.),
///          which shipped in Ethereum Pectra (prague EVM). These precompiles are
///          deployed on Ethereum mainnet post-Pectra but require evm_version=prague
///          and — critically — test vectors with a valid BLS12-381 aggregate
///          signature over the digest. Foundry (forge-std 1.7.1, as of 2026-06-09)
///          has NO BLS signing cheatcode (vm.sign is ECDSA-only; no vm.blsSign or
///          G1Point cheatcode exists in this build), so generating a valid test
///          aggregate on-chain from within Forge tests is not feasible without
///          FFI and an external BLS signer. Additionally, on-chain hash-to-G2 is
///          not provided by EIP-2537 (no H2C precompile), requiring Solidity
///          expand_message_xmd + map + cofactor-clear (~80k gas), which is
///          substantial but solvable.
///        - THEREFORE: the BLS pairing is verified via a MOCK precompile etched at
///          the EIP-2537 PAIRING address (0x10). The mock uses a homomorphic scalar
///          model (see MockBlsPairing below and in BlsQuorumHeaderVerifier.t.sol)
///          that is STRUCTURALLY CORRECT (aggregate pairing check fails if wrong
///          pubkeys or wrong aggregate sig) but is NOT a real BLS12-381 pairing.
///          The real wiring is PENDING and will drop in by:
///            1. Enabling evm_version = "prague" in foundry.toml.
///            2. Implementing on-chain H2C or accepting caller-supplied H(m) with
///               a proof-of-possession binding.
///            3. Generating test vectors via FFI (python blspy / arkworks).
///          This pending work is tracked as a known gap, not a known vulnerability,
///          because the production path runs on GSX-DAG home chain (which uses the
///          ML-DSA 0x0101 leg). The classical BLS path is documented as an exception
///          zone PENDING EIP-2537 real wiring.
///
///      MIGRATION TARGET: EIP-8051 / Track-B hash-based PQ proof (SPHINCS+/XMSS).
///      That verifier will implement the same ISourceHeaderOracle interface and can
///      be swapped in via the bridge's setHeaderOracle seam without changing the
///      custody or storage-proof layers.
///      ======================================================================
///
///      HOW SIGNING-SET SOUNDNESS WORKS (the load-bearing invariant):
///        - Caller supplies `signerBitmap` (bitmask over the epoch's validator
///          indices) identifying which registered validators claim to have signed.
///        - Contract reads each flagged validator's pubkey from the registry
///          (bytes checked against stored keccak via keccak(pubkey) lookup),
///          sums their stake, and aggregates their pubkeys via EIP-2537 G1ADD
///          (or mock G1ADD in tests) ON-CHAIN — the caller never supplies the
///          aggregate pubkey itself.
///        - Stake check: sigStake >= (totalStake*2)/3+1.
///        - Then ONE aggregate BLS verify: pairing check e(aggSig, G2Gen) ==
///          e(H(digest), aggPubkey) via EIP-2537 PAIRING (or mock).
///        - A forged signing set (unregistered validators) contributes 0 stake
///          -> BelowQuorum before reaching the pairing.
///        - A set that passes stake but uses wrong pubkeys will produce a
///          different aggPubkey on-chain -> pairing fails (InvalidAggregateSig).
///        - Both failure modes tested in BlsQuorumHeaderVerifier.t.sol.
contract BlsQuorumHeaderVerifier is ISourceHeaderOracle {
    // ---- EIP-2537 precompile addresses (Ethereum Pectra / prague EVM) ----
    // G1ADD:     0x0b — BLS12_381_G1ADD
    // G1MSM:     0x0c — BLS12_381_G1MSM  (multi-scalar multiply; not used here)
    // G2ADD:     0x0d — BLS12_381_G2ADD  (not used; sigs in G2 variant optional)
    // PAIRING:   0x10 — BLS12_381_PAIRING
    // Note: in tests, 0x0b and 0x10 are etched with mock contracts (see
    //       BlsQuorumHeaderVerifier.t.sol). On Prague mainnet they are the real
    //       EIP-2537 precompiles, but the MockBls test vectors won't be valid
    //       BLS12-381 points — a separate real-vectors test suite is PENDING.
    address public constant BLS_G1ADD = address(0x0b);
    address public constant BLS_PAIRING = address(0x10);

    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1");

    BlsValidatorRegistry public immutable registry;
    uint256 public immutable gsxDagChainId;

    /// blockNumber => finalized EVM state root
    mapping(uint256 => bytes32) private _stateRoots;

    event HeaderFinalized(
        uint256 indexed blockNumber, bytes32 stateRoot, uint256 epoch, uint256 sigStake
    );

    error ZeroStateRoot();
    error HeaderConflict(uint256 blockNumber);
    error StaleEpoch(uint256 epoch, uint256 currentEpoch);
    error BelowQuorum(uint256 sigStake, uint256 needed);
    error InvalidAggregateSig();
    error PrecompileFailed(address precompile);
    error EmptySignerSet();

    constructor(BlsValidatorRegistry registry_, uint256 gsxDagChainId_) {
        require(address(registry_) != address(0), "BlsQuorumHeaderVerifier: zero registry");
        require(gsxDagChainId_ != 0, "BlsQuorumHeaderVerifier: zero chainId");
        registry = registry_;
        gsxDagChainId = gsxDagChainId_;
    }

    /// @notice Finalize `stateRoot` for `blockNumber`, proven by a >2/3-stake quorum
    ///         of the BLS validator set at `epoch` (must be the registry's current epoch)
    ///         providing a valid BLS12-381 aggregate signature.
    ///
    /// @param blockNumber  The GSX-DAG block being attested.
    /// @param stateRoot    The EVM state root at that block.
    /// @param epoch        The epoch of the signing set (must equal registry.currentEpoch()).
    /// @param signerBitmap Bitmask over epoch's validator indices (bit i set = validator i
    ///                     is included in the signing set). Indices 0..validatorCount-1.
    /// @param aggregateSig The BLS12-381 aggregate signature (96 bytes for G2 sig, or
    ///                     48 bytes for G1 sig depending on convention). In the mock, 32
    ///                     bytes (scalar). Real EIP-2537 wiring: pending.
    ///
    /// @dev Security: the aggregate pubkey is derived entirely on-chain from the
    ///      registry. The caller supplies ONLY the bitmap (which validators signed)
    ///      and the aggregate sig (the combined signature over the digest). No
    ///      pubkey bytes are caller-supplied or caller-trusted.
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
            return; // already finalized with the same root — idempotent
        }

        uint256 cur = registry.currentEpoch();
        if (epoch != cur) revert StaleEpoch(epoch, cur);

        // Compute the header digest (same domain as GsxDagQuorumHeaderOracle).
        bytes32 digest = keccak256(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );

        // ---- Build aggregate pubkey and sum stake from registry ----
        // Soundness: registry is trusted; caller supplies only a bitmap.
        uint256 n = registry.validatorCount(epoch);
        uint256 sigStake = 0;
        bytes memory aggPubkey; // accumulated BLS12-381 G1 aggregate pubkey
        bool first = true;
        uint256 signerCount = 0;

        for (uint256 i = 0; i < n; i++) {
            if (signerBitmap & (1 << i) == 0) continue;

            bytes memory pubkey = registry.blsPubkey(epoch, i);
            bytes32 pkHash = keccak256(pubkey);
            uint256 stake = registry.stakeOf(epoch, pkHash);
            if (stake == 0) continue; // unregistered index — should not happen, defensive skip

            sigStake += stake;

            if (first) {
                aggPubkey = pubkey;
                first = false;
            } else {
                // EIP-2537 G1ADD: input = 128 bytes (two G1 points, each 64 bytes padded)
                // In the mock, input = 96 bytes (two 48-byte keys) → mock adds them.
                aggPubkey = _g1Add(aggPubkey, pubkey);
            }
            signerCount++;
        }

        if (signerCount == 0) revert EmptySignerSet();

        uint256 needed = registry.quorumThreshold(epoch);
        if (sigStake < needed) revert BelowQuorum(sigStake, needed);

        // ---- BLS aggregate signature verification ----
        // e(aggregateSig, G2Gen) == e(H(digest), aggPubkey)
        // Real EIP-2537: two G1+G2 pairings via precompile 0x10 (PENDING real wiring).
        // Mock: pairing check via MockBlsPairing (see test) — structurally checks the
        // correct relation between aggSig and aggPubkey, but NOT real BLS12-381.
        bool valid = _blsVerify(aggPubkey, digest, aggregateSig);
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

    /// @notice The header digest validators must BLS-sign (same domain as the ML-DSA oracle).
    function headerDigest(uint256 blockNumber, bytes32 stateRoot) external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );
    }

    // ---- BLS12-381 precompile wrappers ----
    // These call EIP-2537 precompiles. In tests, the precompile addresses are etched
    // with mock contracts (MockBlsG1Add, MockBlsPairing) that implement the same
    // interface but use a scalar-arithmetic model instead of real elliptic-curve ops.
    // See BlsQuorumHeaderVerifier.t.sol for the etch pattern and mock specifications.

    /// @dev G1ADD: aggregate two BLS12-381 G1 pubkeys (48 bytes each in compressed
    ///      form for the mock; EIP-2537 takes 128 bytes = two 64-byte uncompressed points).
    ///      PENDING: real EIP-2537 uses 64-byte uncompressed G1 points.
    function _g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(a, b);
        (bool ok, bytes memory out) = BLS_G1ADD.staticcall(input);
        if (!ok || out.length == 0) revert PrecompileFailed(BLS_G1ADD);
        return out;
    }

    /// @dev BLS pairing check: e(aggSig, G2Gen) == e(H(digest), aggPubkey).
    ///      Real EIP-2537 PAIRING (0x10) takes pairs of (G1, G2) points and returns
    ///      0x01 if the pairing equation holds. PENDING real wiring.
    ///      Mock: input = aggPubkey || digest || aggregateSig; returns 0x01 if valid.
    function _blsVerify(bytes memory aggPubkey, bytes32 digest, bytes calldata aggregateSig)
        internal
        view
        returns (bool)
    {
        bytes memory input = abi.encodePacked(aggPubkey, digest, aggregateSig);
        (bool ok, bytes memory out) = BLS_PAIRING.staticcall(input);
        if (!ok || out.length == 0) revert PrecompileFailed(BLS_PAIRING);
        return out[out.length - 1] == 0x01;
    }
}
