// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlsValidatorRegistry
/// @notice On-chain GSX-DAG validator set (BLS12-381 public keys + stakes) for the
///         classical BLS aggregate quorum leg. Minimal parallel to
///         GsxDagValidatorRegistry: same epoch / threshold / stake semantics, but
///         stores full BLS12-381 G1 pubkeys (48 bytes each) so the verifier can
///         aggregate them on-chain.
///
/// @dev HONEST FRAMING — read before deploying:
///   - This registry backs a CLASSICAL BLS12-381 quorum, NOT post-quantum. BLS12-381
///     is Shor-breakable on a cryptographically-relevant quantum computer. This is the
///     Track-A "exception zone": trust-minimized >2/3 quorum on STOCK EVMs (Ethereum/
///     Base) where the GSX-DAG ML-DSA precompile (0x0101) does not exist.
///   - Genesis epoch 0 is governance-bootstrapped — the unavoidable trust root.
///   - Epoch transitions require an admin call (unlike the ML-DSA registry which
///     verifies an ML-DSA quorum over the transition statement). This is a deliberate
///     scope reduction: a full self-rotating BLS transition would require an on-chain
///     BLS quorum verify for epoch transitions too, which is the same machinery as
///     header finalization. For now, the admin (Timelock in prod) controls rotation.
///     This is an honest reduction vs the ML-DSA registry — document and improve later.
///   - Migration target: EIP-8051 / Track-B hash-based PQ proof via the same
///     ISourceHeaderOracle seam (setHeaderOracle-style swap). Drops in without
///     changing the storage-proof or custody layers.
///
/// Key layout (soundness — read this):
///   epoch => keccak256(rawBlsPubkey) => stake (0 = not a validator that epoch)
///   epoch => index => rawBlsPubkey (48 bytes, BLS12-381 G1 compressed)
///   epoch => validatorCount
///
/// A caller supplies a signer bitmap (bit i = 1 means validator index i signed).
/// The verifier looks up each flagged validator, verifies their pubkey bytes against
/// the stored keccak, sums stake, aggregates pubkeys on-chain via EIP-2537 G1ADD.
/// A forged set (unregistered pubkeys) has no stake -> BelowQuorum.
/// A set that passes stake but uses wrong pubkeys fails the aggregate pairing.
contract BlsValidatorRegistry {
    address public admin;
    uint256 public immutable networkId;
    uint256 public currentEpoch;
    bool public bootstrapped;

    /// epoch => validator index => raw BLS12-381 G1 compressed pubkey (48 bytes)
    mapping(uint256 => mapping(uint256 => bytes)) public blsPubkey;
    /// epoch => keccak256(blsPubkey) => stake (0 = absent)
    mapping(uint256 => mapping(bytes32 => uint256)) public stakeOf;
    /// epoch => total number of validators
    mapping(uint256 => uint256) public validatorCount;
    /// epoch => total stake
    mapping(uint256 => uint256) public totalStake;

    event EpochBootstrapped(uint256 indexed epoch, uint256 validatorCount, uint256 totalStake_);
    event EpochInstalled(uint256 indexed epoch, uint256 validatorCount, uint256 totalStake_);

    error Unauthorized();
    error AlreadyBootstrapped();
    error NotBootstrapped();
    error LengthMismatch();
    error EmptySet();
    error ZeroStake();
    error BadEpoch(uint256 expected, uint256 got);
    error InvalidPubkeyLength(uint256 index, uint256 len);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    constructor(address admin_, uint256 networkId_) {
        require(admin_ != address(0), "BlsValidatorRegistry: zero admin");
        admin = admin_;
        networkId = networkId_;
    }

    /// @notice Governance-bootstrap epoch 0. The unavoidable trust root.
    ///         Each pubkey must be 48 bytes (BLS12-381 G1 compressed).
    ///         Pubkeys need not be sorted; they are accessed by index.
    function bootstrapEpoch0(bytes[] calldata pubkeys, uint256[] calldata stakes)
        external
        onlyAdmin
    {
        if (bootstrapped) revert AlreadyBootstrapped();
        _installSet(0, pubkeys, stakes);
        bootstrapped = true;
        emit EpochBootstrapped(0, pubkeys.length, totalStake[0]);
    }

    /// @notice Admin-controlled epoch transition. Installs `newEpoch`'s validator set.
    ///         Admin is the Timelock in production; the trust assumption is the same
    ///         governance trust as genesis. Future work: make this self-rotating by
    ///         requiring a BLS aggregate quorum over the transition statement
    ///         (same machinery as BlsQuorumHeaderVerifier.submitHeader).
    function installEpoch(uint256 newEpoch, bytes[] calldata pubkeys, uint256[] calldata stakes)
        external
        onlyAdmin
    {
        if (!bootstrapped) revert NotBootstrapped();
        if (newEpoch != currentEpoch + 1) revert BadEpoch(currentEpoch + 1, newEpoch);
        _installSet(newEpoch, pubkeys, stakes);
        currentEpoch = newEpoch;
        emit EpochInstalled(newEpoch, pubkeys.length, totalStake[newEpoch]);
    }

    /// @notice >2/3-stake quorum threshold for `epoch`.
    function quorumThreshold(uint256 epoch) external view returns (uint256) {
        return (totalStake[epoch] * 2) / 3 + 1;
    }

    /// @notice Stake of a validator identified by pubkey hash, in `epoch`.
    function stakeByHash(uint256 epoch, bytes32 pkHash) external view returns (uint256) {
        return stakeOf[epoch][pkHash];
    }

    // ---- internals ----

    function _installSet(uint256 epoch, bytes[] calldata pubkeys, uint256[] calldata stakes)
        internal
    {
        if (pubkeys.length != stakes.length) revert LengthMismatch();
        if (pubkeys.length == 0) revert EmptySet();
        uint256 total;
        for (uint256 i = 0; i < pubkeys.length; i++) {
            if (pubkeys[i].length != 48) revert InvalidPubkeyLength(i, pubkeys[i].length);
            if (stakes[i] == 0) revert ZeroStake();
            bytes32 pkHash = keccak256(pubkeys[i]);
            // allow re-installation at same epoch only for genesis path
            stakeOf[epoch][pkHash] = stakes[i];
            blsPubkey[epoch][i] = pubkeys[i];
            total += stakes[i];
        }
        validatorCount[epoch] = pubkeys.length;
        totalStake[epoch] = total;
    }
}
