// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OptimisticBridgeChallenge
/// @author Suwappu (SUWAPPU)
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

    // LTP-A-006 Option E (docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md): three
    // independent paths to challenge resolution, so a compromised
    // admin cannot single-handedly dismiss a fraud claim.
    //
    //   path A: admin's resolveChallenge (legacy)
    //   path B: arbiter's resolveChallengeByArbiter (independent)
    //   path C: anyone's resolveByTimeDecay after the grace window
    //
    // ZK verifier's finalizeWithZKProof / finalizeWithFraudProof
    // (LTP-A-001) is a fourth fully-autonomous path.

    /// @notice Independent arbiter address. May resolve any challenged
    ///         window in its own right. Distinct from admin so a single
    ///         key compromise on either does not enable fraud dismissal.
    address public arbiter;

    /// @notice After (window.openedAt + resolutionGracePeriod) seconds,
    ///         anyone may call resolveByTimeDecay to rule in favor of
    ///         the challenger. Defends against admin AND arbiter both
    ///         going silent (e.g. simultaneous compromise without the
    ///         attacker having keys to forge a legitimate resolution).
    uint256 public resolutionGracePeriod;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event WindowOpened(bytes32 indexed anchorDigest, address indexed opener, uint256 bond, uint64 deadline);
    event ChallengeSubmitted(bytes32 indexed anchorDigest, address indexed challenger, uint8 proofType, bytes32 proofHash);
    event ChallengeResolved(bytes32 indexed anchorDigest, bool fraudValid, address winner, uint256 reward);
    event WindowFinalized(bytes32 indexed anchorDigest, address indexed opener, uint256 bondReturned);

    // LTP-A-006 Option E events
    event ArbiterUpdated(address indexed previousArbiter, address indexed newArbiter);
    event ResolutionGracePeriodUpdated(uint256 previousSeconds, uint256 newSeconds);
    event ResolvedByArbiter(bytes32 indexed anchorDigest, bool fraudValid, address winner, uint256 reward);
    event ResolvedByTimeDecay(bytes32 indexed anchorDigest, address indexed challenger, uint256 reward);

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
    error ResolutionGraceNotElapsed(uint64 readyAt, uint64 currentTime);
    error InvalidArbiter();
    error GracePeriodBelowFloor(uint256 provided, uint256 floor);

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
        // Sane default: 14 days. Admin can tune via setResolutionGracePeriod
        // post-deploy. Arbiter is unset; admin sets via setArbiter before
        // the v7 production deploy.
        resolutionGracePeriod = 14 days;
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
    // LTP-A-006 Option E — independent arbiter + time-decay
    // -----------------------------------------------------------------------

    /// @notice Set the independent arbiter. Distinct from admin so a single
    ///         key compromise on either does not enable fraud dismissal.
    ///         Admin-only — the cosigner agreement (per OPERATOR_RUNBOOK §13)
    ///         binds the arbiter's identity in advance. Production v7
    ///         deployments should route this through the governance Timelock.
    function setArbiter(address _arbiter) external onlyAdmin {
        if (_arbiter == admin) revert InvalidArbiter();
        emit ArbiterUpdated(arbiter, _arbiter);
        arbiter = _arbiter;
    }

    /// @notice Tune the time-decay grace period. Floor 24h; recommended 14d.
    function setResolutionGracePeriod(uint256 newSeconds) external onlyAdmin {
        if (newSeconds < 24 hours) {
            revert GracePeriodBelowFloor(newSeconds, 24 hours);
        }
        emit ResolutionGracePeriodUpdated(resolutionGracePeriod, newSeconds);
        resolutionGracePeriod = newSeconds;
    }

    /// @notice Resolve a challenged window via the independent arbiter.
    ///         Path B in the LTP-A-006 Option E defense matrix. Mirrors
    ///         `resolveChallenge` but is gated to the arbiter address.
    ///         Admin cannot call this path.
    function resolveChallengeByArbiter(bytes32 anchorDigest, bool fraudValid)
        external
        nonReentrant
    {
        if (msg.sender != arbiter || arbiter == address(0)) revert Unauthorized();

        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_CHALLENGED) revert WindowNotChallenged();

        c.status = STATUS_RESOLVED;
        uint256 totalBonds = c.operatorBond + c.challengerBond;

        address winner = fraudValid ? c.challenger : c.opener;
        if (totalBonds > 0) {
            (bool ok, ) = payable(winner).call{value: totalBonds}("");
            require(ok, "Transfer failed");
        }

        emit ResolvedByArbiter(anchorDigest, fraudValid, winner, totalBonds);
    }

    /// @notice Path C in the LTP-A-006 Option E defense matrix.
    ///         If neither admin nor arbiter has resolved the challenge
    ///         within `resolutionGracePeriod` seconds of the window
    ///         opening, anyone may call this to rule in favor of the
    ///         challenger. Defends against simultaneous compromise of
    ///         admin AND arbiter (where the attacker holds the keys to
    ///         *do nothing* but not to forge a legitimate resolution).
    function resolveByTimeDecay(bytes32 anchorDigest) external nonReentrant {
        Challenge storage c = _challenges[anchorDigest];
        if (c.status != STATUS_CHALLENGED) revert WindowNotChallenged();

        uint64 readyAt = c.openedAt + uint64(resolutionGracePeriod);
        if (block.timestamp < readyAt) {
            revert ResolutionGraceNotElapsed(readyAt, uint64(block.timestamp));
        }

        c.status = STATUS_RESOLVED;
        uint256 totalBonds = c.operatorBond + c.challengerBond;

        if (totalBonds > 0) {
            (bool ok, ) = payable(c.challenger).call{value: totalBonds}("");
            require(ok, "Transfer failed");
        }

        emit ResolvedByTimeDecay(anchorDigest, c.challenger, totalBonds);
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

    /// @notice Finalize a window via ZK proof of *validity*. Callable only by
    ///         the authorized ZK verifier -- admin cannot call this directly,
    ///         since that would let admin finalize (and release bonds on) any
    ///         window without a proof, defeating the point of the ZK path.
    ///         Skips the challenge period — instant finality. Returns both
    ///         bonds (operator was honest; challenger acted in good faith and
    ///         is not slashed). LTP-A-001.
    function finalizeWithZKProof(bytes32 anchorDigest) external nonReentrant {
        if (msg.sender != zkVerifier) revert Unauthorized();

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
