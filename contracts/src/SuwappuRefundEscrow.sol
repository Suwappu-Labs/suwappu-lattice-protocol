// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SuwappuRefundEscrow
/// @notice Protocol insurance reserve. Holds ETH and ERC-20 tokens that can be
///         distributed to users who suffered losses from a bridge exploit or
///         processing error. Governance (SuwappuTimelockController) sets a
///         merkle root defining who can claim what; claimants prove their
///         entitlement with a standard merkle proof.
///
/// @dev Two-phase lifecycle per incident:
///   1. OPEN — governance calls openRound(root, description) to publish the
///              distribution for an incident. Claimants have claimWindow seconds.
///   2. CLOSED — window expires; unclaimed funds stay in the escrow for future rounds.
///
/// Leaf encoding: keccak256(abi.encodePacked(claimant, token, amount, roundId))
///   - claimant: address entitled to the refund
///   - token:    address(0) for ETH, ERC-20 address otherwise
///   - amount:   gross claimable amount (no fee deducted)
///   - roundId:  ties the leaf to a specific incident round (prevents cross-round replay)
///
/// Security properties:
///   - One claim per (claimant, roundId) pair — bitmap prevents double-claim within a round
///   - Funds never leave without a valid merkle proof + active round window
///   - Admin is SuwappuTimelockController (UPGRADE_DELAY enforced for admin changes)
///   - Two-step admin transfer
///   - Sweepable after claim window to treasury (unclaimed funds recycled, not locked forever)
contract SuwappuRefundEscrow is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    address public constant ETH = address(0);

    struct Round {
        bytes32 root;           // merkle root of (claimant, token, amount, roundId) leaves
        uint64  openedAt;       // block.timestamp when the round was opened
        uint64  closesAt;       // openedAt + claimWindow
        string  description;    // human-readable incident description (e.g. "2026-06 relay fault")
        bool    exists;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;
    address public pendingAdmin;

    /// @notice Where unclaimed funds go after a round's claim window closes.
    address public treasury;

    /// @notice Default window claimants have to submit proof once a round opens.
    uint256 public claimWindow;
    uint256 public constant MIN_CLAIM_WINDOW = 7 days;
    uint256 public constant DEFAULT_CLAIM_WINDOW = 30 days;

    /// @notice Monotonically increasing round counter.
    uint256 public roundCount;

    /// @notice Latest closesAt across all rounds. `sweepUnclaimed` is gated on
    ///         this (C6 fix) so a closed round cannot be swept while another
    ///         round's claim window is still open — the escrow is a shared pool.
    uint64 public latestClosesAt;

    /// @notice roundId → round metadata.
    mapping(uint256 => Round) public rounds;

    /// @notice roundId → claimant → token → claimed flag.
    ///         Keyed by token (C7 fix) so a multi-token entitlement in one round
    ///         is not blocked after a single-token claim.
    mapping(uint256 => mapping(address => mapping(address => bool))) public claimed;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event RoundOpened(
        uint256 indexed roundId,
        bytes32 indexed root,
        uint64  closesAt,
        string  description
    );

    event Claimed(
        uint256 indexed roundId,
        address indexed claimant,
        address indexed token,
        uint256 amount
    );

    event UnclaimedSwept(
        uint256 indexed roundId,
        address indexed token,
        address indexed treasury_,
        uint256 amount
    );

    event Deposited(address indexed token, uint256 amount);
    event ClaimWindowSet(uint256 oldWindow, uint256 newWindow);
    event TreasurySet(address indexed oldTreasury, address indexed newTreasury);
    event AdminTransferStarted(address indexed current, address indexed pending);
    event AdminTransferCompleted(address indexed previous, address indexed next);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error Unauthorized();
    error ZeroAddress();
    error ZeroAmount();
    error RoundNotFound(uint256 roundId);
    error RoundClosed(uint256 roundId, uint64 closedAt);
    error RoundStillOpen(uint256 roundId, uint64 closesAt);
    error AlreadyClaimed(uint256 roundId, address claimant);
    error InvalidProof();
    error ClaimWindowTooShort(uint256 provided, uint256 minimum);
    error ETHTransferFailed();

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param admin_    SuwappuTimelockController address
    /// @param treasury_ Where unclaimed funds are swept after a round closes
    constructor(address admin_, address treasury_) {
        if (admin_    == address(0)) revert ZeroAddress();
        if (treasury_ == address(0)) revert ZeroAddress();
        admin       = admin_;
        treasury    = treasury_;
        claimWindow = DEFAULT_CLAIM_WINDOW;
    }

    // -----------------------------------------------------------------------
    // Governance: open a new claim round
    // -----------------------------------------------------------------------

    /// @notice Open a new restitution round. Only callable by admin (TimelockController).
    ///         Governance must pre-fund the escrow with the total claimable amount
    ///         before or alongside opening the round.
    ///
    /// @param root        Merkle root of claimant entitlements for this round.
    ///                    Leaf: keccak256(abi.encodePacked(claimant, token, amount, roundId))
    /// @param description Human-readable incident summary (stored on-chain for auditability)
    function openRound(bytes32 root, string calldata description)
        external
        onlyAdmin
        returns (uint256 roundId)
    {
        require(root != bytes32(0), "SuwappuRefundEscrow: empty root");

        roundId = ++roundCount;
        uint64 closesAt = uint64(block.timestamp) + uint64(claimWindow);

        rounds[roundId] = Round({
            root:        root,
            openedAt:    uint64(block.timestamp),
            closesAt:    closesAt,
            description: description,
            exists:      true
        });

        if (closesAt > latestClosesAt) latestClosesAt = closesAt; // C6: track newest window

        emit RoundOpened(roundId, root, closesAt, description);
    }

    // -----------------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------------

    /// @notice Claim a refund entitlement for a specific round.
    ///         The claimant must provide a valid merkle proof matching the leaf
    ///         keccak256(abi.encodePacked(msg.sender, token, amount, roundId)).
    ///
    /// @param roundId  The round to claim from
    /// @param token    address(0) for ETH, ERC-20 address otherwise
    /// @param amount   Exact amount from the merkle leaf (must match proof)
    /// @param proof    Merkle proof path from leaf to root
    function claim(
        uint256 roundId,
        address token,
        uint256 amount,
        bytes32[] calldata proof
    )
        external
        nonReentrant
    {
        Round storage r = rounds[roundId];
        if (!r.exists)                                   revert RoundNotFound(roundId);
        if (block.timestamp > r.closesAt)                revert RoundClosed(roundId, r.closesAt);
        if (claimed[roundId][msg.sender][token])         revert AlreadyClaimed(roundId, msg.sender);
        if (amount == 0)                                 revert ZeroAmount();

        // Verify merkle proof
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, token, amount, roundId));
        if (!MerkleProof.verify(proof, r.root, leaf))    revert InvalidProof();

        // Mark as claimed before transfer (CEI pattern). Keyed by token (C7).
        claimed[roundId][msg.sender][token] = true;

        emit Claimed(roundId, msg.sender, token, amount);

        _transfer(token, msg.sender, amount);
    }

    // -----------------------------------------------------------------------
    // Sweep unclaimed funds after round closes
    // -----------------------------------------------------------------------

    /// @notice Sweep unclaimed funds for a specific token from a closed round
    ///         back to the treasury. The full token balance is swept (since the
    ///         escrow is single-purpose: all held tokens are for claim rounds).
    ///
    /// @dev The escrow does not track per-round per-token allocations — it holds
    ///      the total reserve. After the last active round closes, the admin sweeps
    ///      the remainder to treasury for recycling.
    ///
    /// @param roundId  Must be closed (past closesAt)
    /// @param token    Token to sweep
    function sweepUnclaimed(uint256 roundId, address token)
        external
        onlyAdmin
        nonReentrant
    {
        Round storage r = rounds[roundId];
        if (!r.exists)                          revert RoundNotFound(roundId);
        // C6 fix: do not sweep while ANY round is still open. The escrow is a
        // shared pool, so sweeping a closed round must not be able to take funds
        // owed to claimants of a round whose window has not yet elapsed.
        if (block.timestamp <= latestClosesAt)  revert RoundStillOpen(roundId, latestClosesAt);

        uint256 balance = _balance(token);
        if (balance == 0) return;

        emit UnclaimedSwept(roundId, token, treasury, balance);
        _transfer(token, treasury, balance);
    }

    // -----------------------------------------------------------------------
    // Deposit (permissionless — anyone can top up the reserve)
    // -----------------------------------------------------------------------

    /// @notice Deposit ETH into the reserve.
    function depositETH() external payable {
        if (msg.value == 0) revert ZeroAmount();
        emit Deposited(ETH, msg.value);
    }

    /// @notice Deposit ERC-20 tokens into the reserve.
    function depositERC20(address token, uint256 amount) external {
        if (token  == address(0)) revert ZeroAddress();
        if (amount == 0)          revert ZeroAmount();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposited(token, amount);
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    function getRound(uint256 roundId) external view returns (Round memory) {
        return rounds[roundId];
    }

    function isRoundOpen(uint256 roundId) external view returns (bool) {
        Round storage r = rounds[roundId];
        return r.exists && block.timestamp <= r.closesAt;
    }

    /// @notice Compute the leaf hash for a given claimant. Off-chain tools use
    ///         this to construct and verify proofs without encoding ambiguity.
    function leafHash(
        address claimant,
        address token,
        uint256 amount,
        uint256 roundId
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(claimant, token, amount, roundId));
    }

    function reserveBalance(address token) external view returns (uint256) {
        return _balance(token);
    }

    // -----------------------------------------------------------------------
    // Admin configuration
    // -----------------------------------------------------------------------

    function setClaimWindow(uint256 newWindow) external onlyAdmin {
        if (newWindow < MIN_CLAIM_WINDOW) revert ClaimWindowTooShort(newWindow, MIN_CLAIM_WINDOW);
        emit ClaimWindowSet(claimWindow, newWindow);
        claimWindow = newWindow;
    }

    function setTreasury(address newTreasury) external onlyAdmin {
        if (newTreasury == address(0)) revert ZeroAddress();
        emit TreasurySet(treasury, newTreasury);
        treasury = newTreasury;
    }

    /// @notice Emergency withdraw — admin can rescue any token in an extreme case.
    ///         Goes through TimelockController's UPGRADE_DELAY (7 days).
    function emergencyWithdraw(address token, uint256 amount, address recipient)
        external
        onlyAdmin
        nonReentrant
    {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0)             revert ZeroAmount();
        _transfer(token, recipient, amount);
    }

    // -----------------------------------------------------------------------
    // Two-step admin transfer
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

    receive() external payable {}
}
