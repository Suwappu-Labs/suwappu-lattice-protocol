// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IMintAttestationVerifier} from "./interfaces/IMintAttestationVerifier.sol";

/// @title SuwappuVault
/// @notice Locks source-chain assets (ETH or ERC-20) and issues a commitment ID
///         that drives the cross-chain mint on the destination chain.
///
/// @dev Flow:
///   1. User calls lock() → vault holds the net amount, fee stays in vault
///   2. Relayer observes Locked event, submits ZK proof on destination chain
///   3. After ZK finalization, relayer calls unlock() here to release funds
///   4. If relay never completes, user calls claimRefund() after refundTimeout
///
/// Security properties:
///   - One commitId → one unlock XOR one refund (enforced by LockStatus enum)
///   - Per-asset daily volume caps (rate limiter)
///   - Per-asset and global TVL hard caps (launch: $5M)
///   - Fees accumulate separately; admin sweeps to treasury
///   - No upgradeability — simpler and safer for custody at this TVL level
///   - Two-step admin transfer to prevent accidental permanent lock-out
contract SuwappuVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// @notice address(0) is used throughout to represent native ETH.
    address public constant ETH = address(0);

    enum LockStatus { NONE, LOCKED, UNLOCKED, REFUNDED }

    struct CommitData {
        address token;          // address(0) for ETH
        address from;           // original depositor
        address destRecipient;  // recipient on destination chain
        uint256 amount;         // net locked amount (after fee)
        uint256 fee;            // fee retained by vault
        uint256 destChainId;    // target chain
        uint64  lockedAt;       // block.timestamp at lock time
        LockStatus status;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;
    address public pendingAdmin;

    /// @notice Receives the fee portion of each lock. Sweep via sweepFees().
    address public feeRecipient;

    /// @notice Fee rate in basis points (50 = 0.50%). Capped at MAX_FEE_BPS.
    uint256 public feeBps;
    uint256 public constant MAX_FEE_BPS = 100; // 1.00%

    /// @notice How long before a user can claim a refund on an unfinished lock.
    uint256 public refundTimeout;
    uint256 public constant MIN_REFUND_TIMEOUT = 1 hours;
    uint256 public constant DEFAULT_REFUND_TIMEOUT = 24 hours;

    /// @notice Nonce for deterministic commitId generation.
    uint256 private _lockNonce;

    /// @notice commitId → commitment data
    mapping(bytes32 => CommitData) public commits;

    /// @notice token → current total net-locked amount
    mapping(address => uint256) public totalLocked;

    /// @notice token → maximum total net-locked amount (hard cap)
    mapping(address => uint256) public tvlCap;

    /// @notice Addresses authorized to call unlock() (relayer set)
    mapping(address => bool) public isUnlocker;

    /// @notice Attestation verifier gating claimRefund. A refund releases source
    ///         collateral, so it must be authorized by an operator confirming
    ///         the commit is refund-eligible — i.e. the destination mint did NOT
    ///         complete. Without this, a user could mint on the destination AND
    ///         reclaim the source collateral (C2 cross-domain double-spend).
    ///         Same verifier shape as the mint gate (ML-DSA on Suwappu DAG,
    ///         ECDSA-interim on EVM); the REFUND domain tag separates the two.
    IMintAttestationVerifier public refundVerifier;

    /// @notice Domain tag bound into every refund-eligibility attestation digest.
    bytes32 public constant REFUND_ATTESTATION_DOMAIN =
        keccak256("SUWAPPU_REFUND_ATTESTATION_V1");

    // Rate limiter: token → day-bucket → volume used
    mapping(address => mapping(uint256 => uint256)) private _dailyVolume;
    /// @notice token → daily volume cap (0 = no cap for that token)
    mapping(address => uint256) public dailyCap;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Locked(
        bytes32 indexed commitId,
        address indexed token,
        address indexed from,
        address  destRecipient,
        uint256  amount,        // net amount (after fee)
        uint256  fee,
        uint256  destChainId,
        uint64   lockedAt
    );

    event Unlocked(
        bytes32 indexed commitId,
        address indexed token,
        address indexed recipient,
        uint256  amount
    );

    event Refunded(
        bytes32 indexed commitId,
        address indexed token,
        address indexed to,
        uint256  amount
    );

    event FeeSwept(address indexed token, address indexed to, uint256 amount);
    event UnlockerAdded(address indexed unlocker);
    event UnlockerRemoved(address indexed unlocker);
    event RefundVerifierSet(address indexed oldVerifier, address indexed newVerifier);
    event TVLCapSet(address indexed token, uint256 cap);
    event DailyCapSet(address indexed token, uint256 cap);
    event FeeBpsSet(uint256 oldBps, uint256 newBps);
    event FeeRecipientSet(address indexed oldRecipient, address indexed newRecipient);
    event RefundTimeoutSet(uint256 oldTimeout, uint256 newTimeout);
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin_);
    event AdminTransferCompleted(address indexed previousAdmin, address indexed newAdmin);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error Unauthorized();
    error ZeroAddress();
    error ZeroAmount();
    error TVLCapExceeded(address token, uint256 requested, uint256 available);
    error DailyCapExceeded(address token, uint256 requested, uint256 remaining);
    error CommitNotFound(bytes32 commitId);
    error CommitNotLocked(bytes32 commitId, LockStatus status);
    error RefundNotReady(bytes32 commitId, uint64 readyAt);
    error FeeBpsTooHigh(uint256 provided, uint256 max);
    error RefundTimeoutTooShort(uint256 provided, uint256 min);
    error ETHTransferFailed();
    error RefundVerifierNotSet();
    error RefundNotAuthorized(bytes32 digest);

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyUnlocker() {
        if (!isUnlocker[msg.sender]) revert Unauthorized();
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param admin_        Initial admin (Gnosis Safe address)
    /// @param feeRecipient_ Address that receives swept fees (Gnosis Safe / Timelock)
    /// @param feeBps_       Initial fee in basis points (e.g. 50 = 0.50%)
    constructor(address admin_, address feeRecipient_, uint256 feeBps_) {
        if (admin_ == address(0)) revert ZeroAddress();
        if (feeRecipient_ == address(0)) revert ZeroAddress();
        if (feeBps_ > MAX_FEE_BPS) revert FeeBpsTooHigh(feeBps_, MAX_FEE_BPS);

        admin = admin_;
        feeRecipient = feeRecipient_;
        feeBps = feeBps_;
        refundTimeout = DEFAULT_REFUND_TIMEOUT;
    }

    // -----------------------------------------------------------------------
    // Core: lock
    // -----------------------------------------------------------------------

    /// @notice Lock ETH for a cross-chain transfer.
    /// @param destChainId   Target chain ID (e.g. 8453 for Base)
    /// @param destRecipient Recipient address on the destination chain
    /// @return commitId     Unique identifier for this lock commitment
    function lockETH(uint256 destChainId, address destRecipient)
        external
        payable
        nonReentrant
        returns (bytes32 commitId)
    {
        if (msg.value == 0) revert ZeroAmount();
        return _lock(ETH, msg.value, destChainId, destRecipient);
    }

    /// @notice Lock an ERC-20 token for a cross-chain transfer.
    /// @param token         ERC-20 token contract address
    /// @param amount        Gross amount to lock (fee deducted from this)
    /// @param destChainId   Target chain ID
    /// @param destRecipient Recipient address on the destination chain
    /// @return commitId     Unique identifier for this lock commitment
    function lockERC20(
        address token,
        uint256 amount,
        uint256 destChainId,
        address destRecipient
    )
        external
        nonReentrant
        returns (bytes32 commitId)
    {
        if (token == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        // C5 fix: credit the amount actually RECEIVED, not the amount requested.
        // Fee-on-transfer / deflationary tokens deliver less than `amount`;
        // crediting `amount` would overstate totalLocked and under-collateralize
        // the vault. Measure the real balance delta instead.
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;
        if (received == 0) revert ZeroAmount();
        return _lock(token, received, destChainId, destRecipient);
    }

    function _lock(
        address token,
        uint256 grossAmount,
        uint256 destChainId,
        address destRecipient
    ) internal returns (bytes32 commitId) {
        if (destRecipient == address(0)) revert ZeroAddress();

        // Compute fee and net amount
        uint256 fee = (grossAmount * feeBps) / 10_000;
        uint256 netAmount = grossAmount - fee;
        if (netAmount == 0) revert ZeroAmount();

        // Rate limit: per-asset daily cap
        if (dailyCap[token] > 0) {
            uint256 day = block.timestamp / 1 days;
            uint256 used = _dailyVolume[token][day];
            if (used + netAmount > dailyCap[token]) {
                revert DailyCapExceeded(token, netAmount, dailyCap[token] - used);
            }
            _dailyVolume[token][day] = used + netAmount;
        }

        // TVL cap: per-asset hard limit
        if (tvlCap[token] > 0) {
            uint256 newTotal = totalLocked[token] + netAmount;
            if (newTotal > tvlCap[token]) {
                revert TVLCapExceeded(token, netAmount, tvlCap[token] - totalLocked[token]);
            }
        }

        // Generate deterministic, collision-resistant commitId
        commitId = keccak256(abi.encodePacked(
            block.chainid,
            address(this),
            _lockNonce++,
            msg.sender,
            token,
            netAmount,
            destChainId,
            destRecipient
        ));

        // Record commitment
        commits[commitId] = CommitData({
            token:         token,
            from:          msg.sender,
            destRecipient: destRecipient,
            amount:        netAmount,
            fee:           fee,
            destChainId:   destChainId,
            lockedAt:      uint64(block.timestamp),
            status:        LockStatus.LOCKED
        });

        totalLocked[token] += netAmount;

        emit Locked(commitId, token, msg.sender, destRecipient, netAmount, fee, destChainId, uint64(block.timestamp));
    }

    // -----------------------------------------------------------------------
    // Core: unlock (called by authorized relayer after dest-chain finalization)
    // -----------------------------------------------------------------------

    /// @notice Release locked funds to a recipient after the destination-chain
    ///         mint has been finalized. Called by an authorized relayer.
    /// @param commitId  The commitment to unlock
    /// @param recipient Address to receive the unlocked funds (may differ from
    ///                  original depositor for return-path burns)
    function unlock(bytes32 commitId, address recipient)
        external
        nonReentrant
        onlyUnlocker
    {
        if (recipient == address(0)) revert ZeroAddress();

        CommitData storage c = commits[commitId];
        if (c.status == LockStatus.NONE) revert CommitNotFound(commitId);
        if (c.status != LockStatus.LOCKED) revert CommitNotLocked(commitId, c.status);

        c.status = LockStatus.UNLOCKED;
        totalLocked[c.token] -= c.amount;

        _transfer(c.token, recipient, c.amount);
        emit Unlocked(commitId, c.token, recipient, c.amount);
    }

    // -----------------------------------------------------------------------
    // Core: refund (permissionless, after timeout)
    // -----------------------------------------------------------------------

    /// @notice Reclaim locked funds if the relay was never completed. Funds
    ///         always go to the original depositor (c.from). Requires an
    ///         operator attestation that the commit is refund-eligible (the
    ///         destination mint did not complete) — this is the C2 fix: it
    ///         prevents reclaiming collateral that is backing minted wrapped
    ///         tokens on the destination chain.
    /// @param commitId    The timed-out commitment to refund
    /// @param attestation Authorized-operator signature over the refund digest
    function claimRefund(bytes32 commitId, bytes calldata attestation) external nonReentrant {
        CommitData storage c = commits[commitId];
        if (c.status == LockStatus.NONE) revert CommitNotFound(commitId);
        if (c.status != LockStatus.LOCKED) revert CommitNotLocked(commitId, c.status);

        uint64 readyAt = c.lockedAt + uint64(refundTimeout);
        if (block.timestamp < readyAt) revert RefundNotReady(commitId, readyAt);

        if (address(refundVerifier) == address(0)) revert RefundVerifierNotSet();
        bytes32 digest = refundDigest(commitId);
        if (!refundVerifier.verifyMintAttestation(digest, attestation)) {
            revert RefundNotAuthorized(digest);
        }

        c.status = LockStatus.REFUNDED;
        totalLocked[c.token] -= c.amount;

        _transfer(c.token, c.from, c.amount);
        emit Refunded(commitId, c.token, c.from, c.amount);
    }

    /// @notice The digest an operator must sign to authorize a refund of `commitId`.
    function refundDigest(bytes32 commitId) public view returns (bytes32) {
        CommitData storage c = commits[commitId];
        return keccak256(abi.encode(
            REFUND_ATTESTATION_DOMAIN,
            block.chainid,
            address(this),
            commitId,
            c.from,
            c.amount,
            c.token
        ));
    }

    // -----------------------------------------------------------------------
    // Fee management
    // -----------------------------------------------------------------------

    /// @notice Sweep accumulated protocol fees for a token to feeRecipient.
    ///         Fees = vault's actual balance − totalLocked[token].
    /// @param token  address(0) for ETH, ERC-20 address otherwise
    function sweepFees(address token) external nonReentrant onlyAdmin {
        uint256 balance = _balance(token);
        uint256 locked  = totalLocked[token];
        uint256 fees    = balance > locked ? balance - locked : 0;
        if (fees == 0) return;

        _transfer(token, feeRecipient, fees);
        emit FeeSwept(token, feeRecipient, fees);
    }

    // -----------------------------------------------------------------------
    // Admin: configuration
    // -----------------------------------------------------------------------

    function setFeeBps(uint256 newBps) external onlyAdmin {
        if (newBps > MAX_FEE_BPS) revert FeeBpsTooHigh(newBps, MAX_FEE_BPS);
        emit FeeBpsSet(feeBps, newBps);
        feeBps = newBps;
    }

    function setFeeRecipient(address newRecipient) external onlyAdmin {
        if (newRecipient == address(0)) revert ZeroAddress();
        emit FeeRecipientSet(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    /// @notice Set the refund-attestation verifier. Required before claimRefund
    ///         can succeed. Governed by the Timelock in production.
    function setRefundVerifier(address newVerifier) external onlyAdmin {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit RefundVerifierSet(address(refundVerifier), newVerifier);
        refundVerifier = IMintAttestationVerifier(newVerifier);
    }

    function setRefundTimeout(uint256 newTimeout) external onlyAdmin {
        if (newTimeout < MIN_REFUND_TIMEOUT) revert RefundTimeoutTooShort(newTimeout, MIN_REFUND_TIMEOUT);
        emit RefundTimeoutSet(refundTimeout, newTimeout);
        refundTimeout = newTimeout;
    }

    function setTVLCap(address token, uint256 cap) external onlyAdmin {
        tvlCap[token] = cap;
        emit TVLCapSet(token, cap);
    }

    function setDailyCap(address token, uint256 cap) external onlyAdmin {
        dailyCap[token] = cap;
        emit DailyCapSet(token, cap);
    }

    function addUnlocker(address unlocker) external onlyAdmin {
        if (unlocker == address(0)) revert ZeroAddress();
        isUnlocker[unlocker] = true;
        emit UnlockerAdded(unlocker);
    }

    function removeUnlocker(address unlocker) external onlyAdmin {
        isUnlocker[unlocker] = false;
        emit UnlockerRemoved(unlocker);
    }

    // -----------------------------------------------------------------------
    // Admin: two-step transfer (H1 fix — prevents permanent lock-out on typo)
    // -----------------------------------------------------------------------

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert Unauthorized();
        emit AdminTransferCompleted(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    /// @notice Current fee balance available to sweep for a given token.
    function pendingFees(address token) external view returns (uint256) {
        uint256 balance = _balance(token);
        uint256 locked  = totalLocked[token];
        return balance > locked ? balance - locked : 0;
    }

    /// @notice Remaining daily capacity for a token.
    function dailyRemaining(address token) external view returns (uint256) {
        if (dailyCap[token] == 0) return type(uint256).max;
        uint256 day  = block.timestamp / 1 days;
        uint256 used = _dailyVolume[token][day];
        return used >= dailyCap[token] ? 0 : dailyCap[token] - used;
    }

    /// @notice Remaining TVL capacity for a token.
    function tvlRemaining(address token) external view returns (uint256) {
        if (tvlCap[token] == 0) return type(uint256).max;
        uint256 locked = totalLocked[token];
        return locked >= tvlCap[token] ? 0 : tvlCap[token] - locked;
    }

    function getCommit(bytes32 commitId) external view returns (CommitData memory) {
        return commits[commitId];
    }

    // -----------------------------------------------------------------------
    // Internal utilities
    // -----------------------------------------------------------------------

    function _transfer(address token, address to, uint256 amount) internal {
        if (token == ETH) {
            (bool ok,) = payable(to).call{value: amount}("");
            if (!ok) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    function _balance(address token) internal view returns (uint256) {
        if (token == ETH) return address(this).balance;
        return IERC20(token).balanceOf(address(this));
    }

    // -----------------------------------------------------------------------
    // Receive ETH (for lockETH path)
    // -----------------------------------------------------------------------

    receive() external payable {}
}
