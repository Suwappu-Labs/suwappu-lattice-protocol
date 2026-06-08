// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title CommitteeHeaderOracle
/// @notice P10 INTERIM oracle-committee header source: a k-of-N committee attests a
///         source block's `stateRoot`, and a quorum finalizes it on-chain for the
///         storage-proof verifier to consume.
///
/// @dev TRUST MODEL — read honestly. This is NOT a light client and does NOT
///      verify source-chain consensus. It is a governance-appointed M-of-N oracle:
///      correctness of `headerStateRoot` rests on an honest super-quorum (>=
///      threshold) of an admin-managed committee that signs a BESPOKE bridge digest
///      (SUWAPPU_SOURCE_HEADER_V1) — the validators sign as a bridge committee, not
///      as the source chain's consensus, and the set is governance-managed, not
///      derived from or kept in sync with the source validator set. This is the
///      SAME trust class as the k-of-N mint verifier (a committee), moved up a
///      level: the committee now attests STATE ROOTS and the MPT storage proof
///      binds each mint to that root — a smaller, more-auditable trust surface than
///      per-mint attestation, but NOT trust elimination, and NOT post-quantum just
///      because the signatures could be ML-DSA (PQ sigs make the attestation PQ,
///      not the trust model trustless).
///
///      The genuine header trust-minimization is Sp1HeliosHeaderOracle (verifies
///      real Ethereum consensus via a SNARK). A true GSX-DAG consensus client
///      (verifying real consensus certificates against a self-updating validator
///      set) is still UNBUILT. This oracle is the deployable interim while that
///      matures. See P10_SOURCE_EVENT_PROOF.md.
///
///      Once a (chainId, blockNumber) is finalized it is immutable: a second
///      submission with a DIFFERENT root reverts (equivocation guard); an
///      identical resubmission is a no-op. The signed digest binds the
///      destination chain + this oracle instance, so a quorum signature cannot be
///      replayed onto another deployment.
contract CommitteeHeaderOracle is ISourceHeaderOracle {
    using ECDSA for bytes32;

    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_SOURCE_HEADER_V1");

    address public admin;
    address public pendingAdmin;

    /// sourceChainId => validator => authorized
    mapping(uint256 => mapping(address => bool)) public isValidator;
    /// sourceChainId => number of authorized validators (N)
    mapping(uint256 => uint256) public validatorCount;
    /// sourceChainId => quorum size (K), 0 = corridor disabled
    mapping(uint256 => uint256) public threshold;
    /// sourceChainId => blockNumber => finalized state root
    mapping(uint256 => mapping(uint256 => bytes32)) private _stateRoots;

    event HeaderFinalized(
        uint256 indexed sourceChainId, uint256 indexed blockNumber, bytes32 stateRoot
    );
    event ValidatorSet(uint256 indexed sourceChainId, address indexed validator, bool authorized);
    event ThresholdSet(uint256 indexed sourceChainId, uint256 threshold);
    event AdminTransferStarted(address indexed current, address indexed pending);
    event AdminTransferCompleted(address indexed previous, address indexed next);

    error Unauthorized();
    error ZeroAddress();
    error ZeroStateRoot();
    error CorridorDisabled(uint256 sourceChainId);
    error BelowQuorum(uint256 got, uint256 needed);
    error HeaderConflict(uint256 sourceChainId, uint256 blockNumber);
    error InvalidThreshold(uint256 threshold_, uint256 validatorCount_);
    error BadSignature();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    constructor(address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    /// @notice The digest each committee validator signs to attest a header.
    function headerDigest(uint256 sourceChainId, uint256 blockNumber, bytes32 stateRoot)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                HEADER_DOMAIN, block.chainid, address(this), sourceChainId, blockNumber, stateRoot
            )
        );
    }

    /// @notice Finalize a source `stateRoot` for `blockNumber` with a quorum of
    ///         committee signatures. Signatures (65-byte ECDSA over the EIP-191
    ///         hash of headerDigest) MUST be ordered by strictly-increasing signer
    ///         address (dedup + gas bound). Idempotent for an identical root;
    ///         reverts on a conflicting root for an already-finalized block.
    function submitHeader(
        uint256 sourceChainId,
        uint256 blockNumber,
        bytes32 stateRoot,
        bytes[] calldata sigs
    ) external {
        if (stateRoot == bytes32(0)) revert ZeroStateRoot();

        bytes32 existing = _stateRoots[sourceChainId][blockNumber];
        if (existing != bytes32(0)) {
            if (existing != stateRoot) revert HeaderConflict(sourceChainId, blockNumber);
            return; // already finalized with the same root — no-op
        }

        uint256 k = threshold[sourceChainId];
        if (k == 0) revert CorridorDisabled(sourceChainId);

        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(
            headerDigest(sourceChainId, blockNumber, stateRoot)
        );

        address last = address(0);
        uint256 count;
        for (uint256 i = 0; i < sigs.length; i++) {
            (address signer, ECDSA.RecoverError err,) = ethHash.tryRecover(sigs[i]);
            if (err != ECDSA.RecoverError.NoError) revert BadSignature();
            if (signer <= last) revert BadSignature(); // strictly increasing: dedup + bound
            last = signer;
            if (isValidator[sourceChainId][signer]) {
                count++;
            }
        }
        if (count < k) revert BelowQuorum(count, k);

        _stateRoots[sourceChainId][blockNumber] = stateRoot;
        emit HeaderFinalized(sourceChainId, blockNumber, stateRoot);
    }

    /// @inheritdoc ISourceHeaderOracle
    function headerStateRoot(uint256 sourceChainId, uint256 blockNumber)
        external
        view
        override
        returns (bytes32)
    {
        return _stateRoots[sourceChainId][blockNumber];
    }

    // ---- governance ----

    function setValidator(uint256 sourceChainId, address validator, bool authorized)
        external
        onlyAdmin
    {
        if (validator == address(0)) revert ZeroAddress();
        bool cur = isValidator[sourceChainId][validator];
        if (cur == authorized) return;
        if (authorized) {
            isValidator[sourceChainId][validator] = true;
            validatorCount[sourceChainId] += 1;
        } else {
            // fail-closed: never let N drop below K
            if (validatorCount[sourceChainId] - 1 < threshold[sourceChainId]) {
                revert InvalidThreshold(threshold[sourceChainId], validatorCount[sourceChainId] - 1);
            }
            isValidator[sourceChainId][validator] = false;
            validatorCount[sourceChainId] -= 1;
        }
        emit ValidatorSet(sourceChainId, validator, authorized);
    }

    function setThreshold(uint256 sourceChainId, uint256 newThreshold) external onlyAdmin {
        if (newThreshold == 0 || newThreshold > validatorCount[sourceChainId]) {
            revert InvalidThreshold(newThreshold, validatorCount[sourceChainId]);
        }
        threshold[sourceChainId] = newThreshold;
        emit ThresholdSet(sourceChainId, newThreshold);
    }

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
}
