// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ETPGovernance
/// @notice On-chain governance for ETP network phase transitions.
///
/// Tracks operator votes for phase transitions (BOOTSTRAP → GROWTH → MATURITY).
/// Votes require >=2/3 supermajority of registered operators.
///
/// ML-DSA-65 signature verification happens off-chain (Python side).
/// The contract validates: operator authorization, duplicate rejection,
/// sequence monotonicity, temporal expiry, and supermajority threshold.
///
/// Architecture:
///   Operators (registered by admin) → castVote() → supermajority check
///   → executeTransition() → currentPhase updated
///
/// Admin: Timelock (same governance chain as LTPAnchorRegistry)
contract ETPGovernance {

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    bytes32 public constant PHASE_BOOTSTRAP = keccak256("bootstrap");
    bytes32 public constant PHASE_GROWTH = keccak256("growth");
    bytes32 public constant PHASE_MATURITY = keccak256("maturity");
    uint256 public constant BASIS_POINTS = 10000;

    // -----------------------------------------------------------------------
    // Custom Errors
    // -----------------------------------------------------------------------

    error NotAdmin(address caller);
    error OperatorNotAuthorized(bytes32 vkHash);
    error OperatorAlreadyRegistered(bytes32 vkHash);
    error OperatorNotRegistered(bytes32 vkHash);
    error DuplicateVote(bytes32 transitionKey, bytes32 vkHash);
    error SequenceTooLow(bytes32 vkHash, uint64 provided, uint64 required);
    error VoteExpired(uint64 validUntil, uint64 currentTime);
    error SupermajorityNotReached(bytes32 transitionKey, uint256 have, uint256 need);
    error InvalidPhaseTransition(bytes32 from_, bytes32 to_);
    error NotCurrentPhase(bytes32 expected, bytes32 actual);
    error ZeroVkHash();
    error ZeroOperatorAddress();
    error NotOperatorCaller(bytes32 vkHash, address caller, address expected);

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event OperatorRegistered(bytes32 indexed vkHash);
    event OperatorRevoked(bytes32 indexed vkHash);
    event VoteCast(bytes32 indexed transitionKey, bytes32 indexed voterVkHash, uint64 sequence);
    event SupermajorityReached(bytes32 indexed transitionKey, uint256 voteCount, uint256 required);
    event PhaseTransitioned(bytes32 indexed fromPhase, bytes32 indexed toPhase, uint256 timestamp);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;
    bytes32 public currentPhase;
    uint256 public operatorCount;
    uint256 public requiredRatio; // In basis points (6667 = 66.67%)

    mapping(bytes32 => bool) public authorizedOperators;
    mapping(bytes32 => address) public operatorAddress;     // vkHash → authorized caller
    mapping(bytes32 => uint256) public voteCount;
    mapping(bytes32 => mapping(bytes32 => bool)) public hasVoted;
    mapping(bytes32 => uint64) public operatorSequences;
    mapping(bytes32 => uint256) public operatorCountAtFirstVote; // Snapshot for supermajority

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address _admin, uint256 _requiredRatio) {
        if (_admin == address(0)) revert NotAdmin(address(0));
        admin = _admin;
        requiredRatio = _requiredRatio > 0 ? _requiredRatio : 6667; // Default 66.67%
        currentPhase = PHASE_BOOTSTRAP;
    }

    // -----------------------------------------------------------------------
    // Admin Functions
    // -----------------------------------------------------------------------

    function registerOperator(bytes32 vkHash, address operator) external onlyAdmin {
        if (vkHash == bytes32(0)) revert ZeroVkHash();
        if (operator == address(0)) revert ZeroOperatorAddress();
        if (authorizedOperators[vkHash]) revert OperatorAlreadyRegistered(vkHash);
        authorizedOperators[vkHash] = true;
        operatorAddress[vkHash] = operator;
        operatorCount++;
        emit OperatorRegistered(vkHash);
    }

    function revokeOperator(bytes32 vkHash) external onlyAdmin {
        if (!authorizedOperators[vkHash]) revert OperatorNotRegistered(vkHash);
        authorizedOperators[vkHash] = false;
        operatorCount--;
        emit OperatorRevoked(vkHash);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert NotAdmin(address(0));
        address old = admin;
        admin = newAdmin;
        emit AdminTransferred(old, newAdmin);
    }

    // -----------------------------------------------------------------------
    // Voting
    // -----------------------------------------------------------------------

    /// @notice Cast a vote for a phase transition.
    /// @param transitionKey keccak256("bootstrap->growth") or similar
    /// @param voterVkHash Hash of the voter's ML-DSA-65 verification key
    /// @param sequence Per-operator monotonic sequence number
    /// @param validUntil Unix timestamp after which the vote expires
    function castVote(
        bytes32 transitionKey,
        bytes32 voterVkHash,
        uint64 sequence,
        uint64 validUntil
    ) external {
        // 1. Operator must be authorized
        if (!authorizedOperators[voterVkHash]) revert OperatorNotAuthorized(voterVkHash);

        // 1b. Caller must be the registered operator address (no admin bypass)
        address expected = operatorAddress[voterVkHash];
        if (msg.sender != expected) {
            revert NotOperatorCaller(voterVkHash, msg.sender, expected);
        }

        // 2. No duplicate votes
        if (hasVoted[transitionKey][voterVkHash]) revert DuplicateVote(transitionKey, voterVkHash);

        // 3. Sequence must be strictly increasing
        uint64 lastSeq = operatorSequences[voterVkHash];
        if (sequence <= lastSeq) revert SequenceTooLow(voterVkHash, sequence, lastSeq);

        // 4. Vote must not be expired
        if (block.timestamp > validUntil) revert VoteExpired(validUntil, uint64(block.timestamp));

        // Record vote
        hasVoted[transitionKey][voterVkHash] = true;
        operatorSequences[voterVkHash] = sequence;
        voteCount[transitionKey]++;

        // Snapshot operator count on first vote for this transition
        if (operatorCountAtFirstVote[transitionKey] == 0) {
            operatorCountAtFirstVote[transitionKey] = operatorCount;
        }

        emit VoteCast(transitionKey, voterVkHash, sequence);

        // Check supermajority (using snapshot)
        uint256 snapshotCount = operatorCountAtFirstVote[transitionKey];
        uint256 required = (snapshotCount * requiredRatio + BASIS_POINTS - 1) / BASIS_POINTS;
        if (voteCount[transitionKey] >= required) {
            emit SupermajorityReached(transitionKey, voteCount[transitionKey], required);
        }
    }

    /// @notice Execute a phase transition after supermajority is reached.
    /// @param fromPhase Current phase (must match currentPhase)
    /// @param toPhase Target phase
    function executeTransition(bytes32 fromPhase, bytes32 toPhase) external {
        // Validate current phase
        if (currentPhase != fromPhase) revert NotCurrentPhase(currentPhase, fromPhase);

        // Validate transition is valid (forward only)
        if (!_isValidTransition(fromPhase, toPhase)) revert InvalidPhaseTransition(fromPhase, toPhase);

        // Check supermajority (using snapshot from first vote)
        bytes32 transitionKey = keccak256(abi.encodePacked(fromPhase, "->", toPhase));
        uint256 snapshotCount = operatorCountAtFirstVote[transitionKey];
        if (snapshotCount == 0) snapshotCount = operatorCount; // No votes yet
        // C3: with zero operators, `required` below computes to 0 via integer
        // division, so `voteCount < required` (0 < 0) is false and any EOA
        // could execute a transition with no votes at all. Reject explicitly.
        require(snapshotCount > 0, "SuwappuGovernance: no operators registered");
        uint256 required = (snapshotCount * requiredRatio + BASIS_POINTS - 1) / BASIS_POINTS;
        if (voteCount[transitionKey] < required) {
            revert SupermajorityNotReached(transitionKey, voteCount[transitionKey], required);
        }

        // Execute transition
        currentPhase = toPhase;
        emit PhaseTransitioned(fromPhase, toPhase, block.timestamp);
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    function getVoteCount(bytes32 transitionKey) external view returns (uint256) {
        return voteCount[transitionKey];
    }

    function hasOperatorVoted(bytes32 transitionKey, bytes32 vkHash) external view returns (bool) {
        return hasVoted[transitionKey][vkHash];
    }

    function isSupermajority(bytes32 transitionKey) external view returns (bool) {
        return voteCount[transitionKey] >= getRequiredVotes();
    }

    function getRequiredVotes() public view returns (uint256) {
        if (operatorCount == 0) return 0;
        // ceil(operatorCount * requiredRatio / BASIS_POINTS)
        return (operatorCount * requiredRatio + BASIS_POINTS - 1) / BASIS_POINTS;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    function _isValidTransition(bytes32 from_, bytes32 to_) internal pure returns (bool) {
        if (from_ == PHASE_BOOTSTRAP && to_ == PHASE_GROWTH) return true;
        if (from_ == PHASE_GROWTH && to_ == PHASE_MATURITY) return true;
        return false;
    }
}
