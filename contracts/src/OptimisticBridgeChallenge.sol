// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OptimisticBridgeChallenge
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice On-chain challenge window management for the ETP optimistic bridge.
///         Operators bond when opening windows; challengers bond when filing
///         fraud proofs. Losing party's bond is slashed to the winner.
/// @dev Standalone contract — does not upgrade LTPAnchorRegistry.
///      Resolution is admin-only; replaced by ZK verification when available.
///      Uses manual reentrancy guard on all functions that transfer ETH.
contract OptimisticBridgeChallenge {
    // Reentrancy guard
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _reentrancyStatus = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, "ReentrancyGuard: reentrant call");
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }
    // -----------------------------------------------------------------------
    // Challenge status enum (mirrors Python ChallengeStatus)
    // -----------------------------------------------------------------------

    uint8 public constant STATUS_NONE       = 0;
    uint8 public constant STATUS_OPEN       = 1;
    uint8 public constant STATUS_CHALLENGED = 2;
    uint8 public constant STATUS_RESOLVED   = 3;
    uint8 public constant STATUS_FINALIZED  = 4;
    uint8 public constant STATUS_EXPIRED    = 5;

    // -----------------------------------------------------------------------
    // Challenge struct
    // -----------------------------------------------------------------------

    struct Challenge {
        bytes32 anchorDigest;
        address opener;             // Operator who opened the window
        address challenger;         // 0x0 until challenged
        bytes32 fraudProofHash;     // SHA3-256 of off-chain proof data
        uint8   fraudProofType;     // FraudProofType enum ordinal
        uint64  openedAt;
        uint64  deadline;           // openedAt + challengePeriod
        uint8   status;
        uint256 operatorBond;
        uint256 challengerBond;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    mapping(bytes32 => Challenge) private _challenges;

    address public admin;
    uint256 public challengePeriod;
    uint256 public minOperatorBond;
    uint256 public minChallengerBond;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event WindowOpened(bytes32 indexed anchorDigest, address indexed opener, uint256 bond, uint64 deadline);
    event ChallengeSubmitted(bytes32 indexed anchorDigest, address indexed challenger, uint8 proofType, bytes32 proofHash);
    event ChallengeResolved(bytes32 indexed anchorDigest, bool fraudValid, address winner, uint256 reward);
    event WindowFinalized(bytes32 indexed anchorDigest, address indexed opener, uint256 bondReturned);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error Unauthorized();
    error WindowAlreadyExists();
    error WindowNotOpen();
    error WindowNotChallenged();
    error WindowNotExpired();
    error InsufficientBond(uint256 required, uint256 provided);
    error ChallengeDeadlinePassed();
    error ZeroDigest();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(
        address _admin,
        uint256 _challengePeriod,
        uint256 _minOperatorBond,
        uint256 _minChallengerBond
    ) {
        admin = _admin;
        challengePeriod = _challengePeriod;
        minOperatorBond = _minOperatorBond;
        minChallengerBond = _minChallengerBond;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    // -----------------------------------------------------------------------
    // Core functions
    // -----------------------------------------------------------------------

    /// @notice Open a challenge window for an anchor digest. Operator deposits bond.
    function openWindow(bytes32 anchorDigest) external payable {
        if (anchorDigest == bytes32(0)) revert ZeroDigest();
        if (_challenges[anchorDigest].status != STATUS_NONE) revert WindowAlreadyExists();
        if (msg.value < minOperatorBond) revert InsufficientBond(minOperatorBond, msg.value);

        uint64 deadline = uint64(block.timestamp) + uint64(challengePeriod);

        _challenges[anchorDigest] = Challenge({
            anchorDigest: anchorDigest,
            opener: msg.sender,
            challenger: address(0),
            fraudProofHash: bytes32(0),
            fraudProofType: 0,
            openedAt: uint64(block.timestamp),
            deadline: deadline,
            status: STATUS_OPEN,
            operatorBond: msg.value,
            challengerBond: 0
        });

        emit WindowOpened(anchorDigest, msg.sender, msg.value, deadline);
    }

    /// @notice Submit a fraud proof challenge against an open window. Challenger deposits bond.
    function submitChallenge(
        bytes32 anchorDigest,
        uint8 proofType,
        bytes32 proofHash
    ) external payable {
        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_OPEN) revert WindowNotOpen();
        if (block.timestamp > c.deadline) revert ChallengeDeadlinePassed();
        if (msg.value < minChallengerBond) revert InsufficientBond(minChallengerBond, msg.value);

        c.status = STATUS_CHALLENGED;
        c.challenger = msg.sender;
        c.fraudProofHash = proofHash;
        c.fraudProofType = proofType;
        c.challengerBond = msg.value;

        emit ChallengeSubmitted(anchorDigest, msg.sender, proofType, proofHash);
    }

    /// @notice Resolve a challenged window. Admin-only.
    /// @param fraudValid True if the fraud proof is valid (operator slashed),
    ///        false if the challenge is invalid (challenger slashed).
    function resolveChallenge(bytes32 anchorDigest, bool fraudValid) external onlyAdmin nonReentrant {
        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_CHALLENGED) revert WindowNotChallenged();

        c.status = STATUS_RESOLVED;
        uint256 totalBonds = c.operatorBond + c.challengerBond;

        if (fraudValid) {
            // Operator was fraudulent — challenger wins both bonds
            (bool success, ) = payable(c.challenger).call{value: totalBonds}("");
            require(success, "Transfer to challenger failed");
            emit ChallengeResolved(anchorDigest, fraudValid, c.challenger, totalBonds);
        } else {
            // Challenge was invalid — operator wins both bonds
            (bool success, ) = payable(c.opener).call{value: totalBonds}("");
            require(success, "Transfer to opener failed");
            emit ChallengeResolved(anchorDigest, fraudValid, c.opener, totalBonds);
        }
    }

    /// @notice Finalize an unchallenged window after the deadline. Returns operator bond.
    function finalizeWindow(bytes32 anchorDigest) external nonReentrant {
        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_OPEN) revert WindowNotOpen();
        if (block.timestamp <= c.deadline) revert WindowNotExpired();

        c.status = STATUS_FINALIZED;
        uint256 bond = c.operatorBond;

        (bool success, ) = payable(c.opener).call{value: bond}("");
        require(success, "Transfer to opener failed");

        emit WindowFinalized(anchorDigest, c.opener, bond);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    function getChallenge(bytes32 anchorDigest) external view returns (Challenge memory) {
        return _challenges[anchorDigest];
    }

    function getChallengeStatus(bytes32 anchorDigest) external view returns (uint8) {
        return _challenges[anchorDigest].status;
    }

    function isFinalized(bytes32 anchorDigest) external view returns (bool) {
        return _challenges[anchorDigest].status == STATUS_FINALIZED;
    }

    function isChallenged(bytes32 anchorDigest) external view returns (bool) {
        return _challenges[anchorDigest].status == STATUS_CHALLENGED;
    }

    // -----------------------------------------------------------------------
    // Admin functions
    // -----------------------------------------------------------------------

    function setChallengePeriod(uint256 newPeriod) external onlyAdmin {
        challengePeriod = newPeriod;
    }

    function setMinOperatorBond(uint256 newMin) external onlyAdmin {
        minOperatorBond = newMin;
    }

    function setMinChallengerBond(uint256 newMin) external onlyAdmin {
        minChallengerBond = newMin;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    // -----------------------------------------------------------------------
    // ZK Bridge integration
    // -----------------------------------------------------------------------

    /// @notice Authorized ZK verifier contract address.
    address public zkVerifier;

    event ZKVerifierSet(address indexed zkVerifier);

    function setZKVerifier(address _zkVerifier) external onlyAdmin {
        zkVerifier = _zkVerifier;
        emit ZKVerifierSet(_zkVerifier);
    }

    /// @notice Finalize a window via ZK proof of *validity*. Callable by admin
    ///         or authorized ZK verifier. Skips the challenge period — instant
    ///         finality. Returns both bonds (operator was honest; challenger
    ///         acted in good faith and is not slashed). LTP-A-001.
    function finalizeWithZKProof(bytes32 anchorDigest) external nonReentrant {
        if (msg.sender != admin && msg.sender != zkVerifier) revert Unauthorized();

        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_OPEN && c.status != STATUS_CHALLENGED) revert WindowNotOpen();

        c.status = STATUS_FINALIZED;

        // Return operator bond
        uint256 opBond = c.operatorBond;
        if (opBond > 0) {
            (bool s1, ) = payable(c.opener).call{value: opBond}("");
            require(s1, "Transfer to opener failed");
        }
        // Return challenger bond (ZK proof supersedes challenge)
        uint256 chBond = c.challengerBond;
        if (chBond > 0) {
            (bool s2, ) = payable(c.challenger).call{value: chBond}("");
            require(s2, "Transfer to challenger failed");
        }

        emit WindowFinalized(anchorDigest, c.opener, opBond);
    }

    /// @notice Finalize a *challenged* window via ZK proof of *fraud*. Mirrors
    ///         finalizeWithZKProof but rules in the challenger's favor: the
    ///         operator's bond is slashed and paid (together with the
    ///         challenger's bond) to the challenger. Callable only by the
    ///         authorized ZK verifier — admin cannot invoke this path
    ///         (LTP-A-001 Option E: admin-independent fraud finalization).
    /// @dev    The ZK verifier is expected to have already validated a
    ///         SNARK proving the attestation didn't verify under the
    ///         declared group public key, or that the anchor is otherwise
    ///         provably fraudulent. This contract trusts the verifier
    ///         to have run that check; the verifier itself is gated by
    ///         setZKVerifier (admin-only).
    function finalizeWithFraudProof(bytes32 anchorDigest) external nonReentrant {
        if (msg.sender != zkVerifier) revert Unauthorized();

        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_CHALLENGED) revert WindowNotChallenged();

        c.status = STATUS_RESOLVED;
        uint256 totalBonds = c.operatorBond + c.challengerBond;

        // Challenger wins both bonds (operator was fraudulent).
        if (totalBonds > 0) {
            (bool ok, ) = payable(c.challenger).call{value: totalBonds}("");
            require(ok, "Transfer to challenger failed");
        }

        emit ChallengeResolved(anchorDigest, true, c.challenger, totalBonds);
    }
}
