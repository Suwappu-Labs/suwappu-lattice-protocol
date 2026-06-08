// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GsxDagValidatorRegistry
/// @notice On-chain GSX-DAG validator set + epoch-transition verification, built on
///         the native 0x0101 (ML-DSA-65) and 0x0102 (BLAKE3) precompiles. The P11
///         prerequisite for a real consensus light client: it tracks the validator
///         set across epochs by verifying that each new set is signed by a >2/3
///         stake quorum of the CURRENT set (a self-signed epoch-transition cert),
///         so the set follows the chain's own rotation instead of being
///         governance-appointed per epoch.
///
/// @dev HONEST SCOPE — read this:
///   - This verifies a VALIDATOR-QUORUM ML-DSA signature over an epoch-transition
///     statement. It does NOT reconstruct GSX-DAG's Mysticeti-C commit rule (the
///     DAG-causality verification is out of scope); this is the sync-committee-style
///     trust model — trust an honest >2/3-stake quorum of the tracked set.
///   - It REQUIRES a gsx-dag-side signing duty that is NOT yet implemented:
///     validators must ML-DSA-sign the epoch-transition statement (and, for the
///     header oracle, the header attestation). Until gsx-dag emits these, this is
///     destination-side machinery waiting on the source side.
///   - Genesis epoch 0 is governance-bootstrapped — the unavoidable trusted root
///     every light client has.
///   - POST-QUANTUM only on a chain that has the 0x0101 precompile (the GSX-DAG
///     home chain). See P11_GSXDAG_CONSENSUS_LIGHT_CLIENT.md.
contract GsxDagValidatorRegistry {
    /// Native precompiles (registered in suwappu-revm).
    address public constant BLAKE3 = address(0x0102);
    address public constant MLDSA = address(0x0101);

    bytes32 public constant EPOCH_DOMAIN = keccak256("SUWAPPU_GSXDAG_EPOCH_V1");

    address public admin; // genesis bootstrap + emergency only (Timelock in prod)
    uint256 public immutable networkId; // binds digests to this GSX-DAG network
    uint256 public currentEpoch;
    bool public bootstrapped;

    /// epoch => keccak256(ml-dsa pubkey) => stake (0 = not a validator that epoch)
    mapping(uint256 => mapping(bytes32 => uint256)) public stakeOf;
    /// epoch => total stake of that epoch's set
    mapping(uint256 => uint256) public totalStake;

    event EpochBootstrapped(uint256 indexed epoch, uint256 validatorCount, uint256 totalStake);
    event EpochTransitioned(uint256 indexed fromEpoch, uint256 indexed toEpoch, uint256 sigStake);

    error Unauthorized();
    error AlreadyBootstrapped();
    error NotBootstrapped();
    error LengthMismatch();
    error EmptySet();
    error ZeroStake();
    error BadEpoch(uint256 expected, uint256 got);
    error QuorumNotMet(uint256 sigStake, uint256 needed);
    error UnsortedOrDuplicate();
    error PrecompileFailed();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    constructor(address admin_, uint256 networkId_) {
        require(admin_ != address(0), "GsxDagValidatorRegistry: zero admin");
        admin = admin_;
        networkId = networkId_;
    }

    /// @notice Genesis: trusted bootstrap of epoch 0's validator set. The
    ///         unavoidable trust root (every light client bootstraps a genesis set).
    ///         `pkHashes` MUST be strictly increasing (sorted, distinct).
    function bootstrapEpoch0(bytes32[] calldata pkHashes, uint256[] calldata stakes)
        external
        onlyAdmin
    {
        if (bootstrapped) revert AlreadyBootstrapped();
        _installSet(0, pkHashes, stakes);
        bootstrapped = true;
        emit EpochBootstrapped(0, pkHashes.length, totalStake[0]);
    }

    /// @notice Adopt `newEpoch`'s (== currentEpoch+1) validator set, proven by a
    ///         >2/3-stake quorum of the CURRENT epoch's validators ML-DSA-signing the
    ///         transition statement. Signers ordered by strictly-increasing
    ///         keccak(pubkey) (dedup + gas bound).
    function transitionEpoch(
        uint256 newEpoch,
        bytes32[] calldata newPkHashes,
        uint256[] calldata newStakes,
        bytes[] calldata pubkeys,
        bytes[] calldata sigs
    ) external {
        if (!bootstrapped) revert NotBootstrapped();
        if (newEpoch != currentEpoch + 1) revert BadEpoch(currentEpoch + 1, newEpoch);
        if (pubkeys.length != sigs.length) revert LengthMismatch();

        bytes32 setHash = keccak256(abi.encode(newEpoch, newPkHashes, newStakes));
        bytes32 digest =
            _blake3(abi.encodePacked(EPOCH_DOMAIN, networkId, address(this), newEpoch, setHash));

        uint256 sigStake = _verifyQuorum(currentEpoch, digest, pubkeys, sigs);
        uint256 needed = (totalStake[currentEpoch] * 2) / 3 + 1; // strictly > 2/3
        if (sigStake < needed) revert QuorumNotMet(sigStake, needed);

        _installSet(newEpoch, newPkHashes, newStakes);
        currentEpoch = newEpoch;
        emit EpochTransitioned(newEpoch - 1, newEpoch, sigStake);
    }

    /// @notice Stake of valid, authorized, DISTINCT signers over `digest` in `epoch`.
    ///         Signers must be ordered by strictly-increasing keccak(pubkey).
    function verifyQuorum(
        uint256 epoch,
        bytes32 digest,
        bytes[] calldata pubkeys,
        bytes[] calldata sigs
    ) external view returns (uint256 sigStake) {
        if (pubkeys.length != sigs.length) revert LengthMismatch();
        return _verifyQuorum(epoch, digest, pubkeys, sigs);
    }

    function _verifyQuorum(
        uint256 epoch,
        bytes32 digest,
        bytes[] calldata pubkeys,
        bytes[] calldata sigs
    ) internal view returns (uint256 sigStake) {
        bytes32 last = bytes32(0);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            bytes32 pkHash = keccak256(pubkeys[i]);
            if (pkHash <= last) revert UnsortedOrDuplicate();
            last = pkHash;
            uint256 stake = stakeOf[epoch][pkHash];
            if (stake == 0) continue; // not a validator this epoch
            if (_mldsaValid(pubkeys[i], sigs[i], digest)) {
                sigStake += stake;
            }
        }
    }

    function quorumThreshold(uint256 epoch) external view returns (uint256) {
        return (totalStake[epoch] * 2) / 3 + 1;
    }

    function isValidator(uint256 epoch, bytes32 pkHash) external view returns (bool) {
        return stakeOf[epoch][pkHash] != 0;
    }

    // ---- internals ----

    function _installSet(uint256 epoch, bytes32[] calldata pkHashes, uint256[] calldata stakes)
        internal
    {
        if (pkHashes.length != stakes.length) revert LengthMismatch();
        if (pkHashes.length == 0) revert EmptySet();
        uint256 total;
        bytes32 last = bytes32(0);
        for (uint256 i = 0; i < pkHashes.length; i++) {
            if (pkHashes[i] <= last) revert UnsortedOrDuplicate(); // sorted + distinct
            last = pkHashes[i];
            if (stakes[i] == 0) revert ZeroStake();
            stakeOf[epoch][pkHashes[i]] = stakes[i];
            total += stakes[i];
        }
        totalStake[epoch] = total;
    }

    /// @dev BLAKE3 of `data` via the 0x0102 precompile. A precompile has no code, so
    ///      a contract etched in tests AND the native precompile both return 32
    ///      bytes; a chain WITHOUT 0x0102 returns empty -> PrecompileFailed.
    function _blake3(bytes memory data) internal view returns (bytes32) {
        (bool ok, bytes memory out) = BLAKE3.staticcall(data);
        if (!ok || out.length != 32) revert PrecompileFailed();
        return bytes32(out);
    }

    /// @dev ML-DSA-65 verify via 0x0101: input = pubkey || sig || digest; the word's
    ///      last byte is 1 iff valid. Returns false (not revert) on absent precompile
    ///      / malformed, so one bad signer doesn't brick a quorum check.
    function _mldsaValid(bytes calldata pubkey, bytes calldata sig, bytes32 digest)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory out) = MLDSA.staticcall(abi.encodePacked(pubkey, sig, digest));
        if (!ok || out.length != 32) return false;
        return out[31] == 0x01;
    }
}
