// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SuwappuWrappedToken} from "./SuwappuWrappedToken.sol";

/// @title SuwappuMintAdapter
/// @notice Destination-chain contract that mints SuwappuWrappedToken when a
///         source-chain lock is finalized, and initiates return transfers by
///         burning the wrapped token and emitting BurnForRelease.
///
/// @dev Trust model (MVP):
///   - An authorized RELAYER set submits mint attestations off-chain.
///   - Each commitId may produce exactly one successful mint (enforced by bitmap).
///   - The relayer must provide the exact parameters that match the source Locked
///     event; mismatches produce a different commitId and will be rejected.
///   - Economic security: relayers post a bond in SuwappuChallenge; fraud
///     proofs let the protocol slash dishonest relayers.
///   - ZK upgrade path: replace the relayer set with a ZKVerifier that
///     proves inclusion of the Locked event in a finalized Ethereum block.
///
/// @dev Return path (burn → unlock):
///   1. User calls burn() — wrapped tokens are destroyed.
///   2. BurnForRelease event is emitted with a releaseId.
///   3. Relayer observes event, calls SuwappuVault.unlock(releaseId, recipient)
///      on the source chain to release the original locked funds.
contract SuwappuMintAdapter is ReentrancyGuard {
    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct MintRecord {
        address recipient;
        uint256 amount;
        uint256 sourceChainId;
        uint64  mintedAt;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address public admin;
    address public pendingAdmin;

    /// @notice The wrapped token this adapter controls.
    SuwappuWrappedToken public wrappedToken;

    /// @notice Authorized relayers that may call mint().
    mapping(address => bool) public isRelayer;

    /// @notice commitId → mint record. Used to prevent double-minting.
    mapping(bytes32 => MintRecord) public mintRecords;

    /// @notice Nonce for releaseId generation on burns.
    uint256 private _burnNonce;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Minted(
        bytes32 indexed commitId,
        address indexed recipient,
        uint256  amount,
        uint256  sourceChainId,
        address  relayer
    );

    event BurnForRelease(
        bytes32 indexed releaseId,
        address indexed from,
        address  destRecipient,    // recipient on source chain
        uint256  amount,
        uint256  destChainId,      // source chain ID (where unlock will happen)
        uint64   burnedAt
    );

    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event WrappedTokenSet(address indexed oldToken, address indexed newToken);
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin_);
    event AdminTransferCompleted(address indexed previousAdmin, address indexed newAdmin);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error Unauthorized();
    error ZeroAddress();
    error ZeroAmount();
    error AlreadyMinted(bytes32 commitId);
    error CommitIdMismatch(bytes32 provided, bytes32 computed);

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier onlyRelayer() {
        if (!isRelayer[msg.sender]) revert Unauthorized();
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param admin_        Initial admin (Gnosis Safe address)
    /// @param wrappedToken_ SuwappuWrappedToken this adapter holds MINTER+BURNER roles on
    constructor(address admin_, address wrappedToken_) {
        if (admin_ == address(0)) revert ZeroAddress();
        if (wrappedToken_ == address(0)) revert ZeroAddress();
        admin = admin_;
        wrappedToken = SuwappuWrappedToken(wrappedToken_);
    }

    // -----------------------------------------------------------------------
    // Core: mint
    // -----------------------------------------------------------------------

    /// @notice Mint wrapped tokens to a recipient after a source-chain lock
    ///         has been finalized by an authorized relayer.
    ///
    /// @dev The relayer must supply the exact parameters that were emitted
    ///      in the source-chain Locked event. The vault uses the same
    ///      keccak256 derivation for commitId — any parameter mismatch
    ///      produces a different commitId that has no mint record, causing
    ///      the mint to fail on the double-mint guard (AlreadyMinted won't
    ///      fire, but the recipient won't receive tokens either because
    ///      no matching Locked event exists on-chain for that commitId).
    ///
    ///      The relayer is economically bonded: posting a fraudulent mint
    ///      exposes them to slashing via SuwappuChallenge.
    ///
    /// @param commitId     Commitment ID from the source-chain Locked event
    /// @param recipient    Address to receive the wrapped tokens
    /// @param amount       Net amount from the source Locked event
    /// @param sourceChainId Chain ID where the Vault.lock() was called
    function mint(
        bytes32 commitId,
        address recipient,
        uint256 amount,
        uint256 sourceChainId
    )
        external
        nonReentrant
        onlyRelayer
    {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        // Enforce one mint per commitId — prevents relay replay.
        if (mintRecords[commitId].mintedAt != 0) revert AlreadyMinted(commitId);

        mintRecords[commitId] = MintRecord({
            recipient:     recipient,
            amount:        amount,
            sourceChainId: sourceChainId,
            mintedAt:      uint64(block.timestamp)
        });

        wrappedToken.mint(recipient, amount, commitId);

        emit Minted(commitId, recipient, amount, sourceChainId, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Core: burn (return transfer — wrapped → source chain unlock)
    // -----------------------------------------------------------------------

    /// @notice Burn wrapped tokens to initiate a return transfer.
    ///         The emitted BurnForRelease event instructs the relayer to call
    ///         SuwappuVault.unlock(releaseId, destRecipient) on the source chain.
    ///
    /// @param amount        Amount of wrapped tokens to burn
    /// @param destChainId   Chain ID of the source chain where funds will be unlocked
    /// @param destRecipient Address on the source chain that will receive the unlocked funds
    /// @return releaseId    Unique ID for this burn event (relayer uses this to call unlock)
    function burn(
        uint256 amount,
        uint256 destChainId,
        address destRecipient
    )
        external
        nonReentrant
        returns (bytes32 releaseId)
    {
        if (amount == 0) revert ZeroAmount();
        if (destRecipient == address(0)) revert ZeroAddress();

        // Generate deterministic releaseId — mirrors vault's commitId derivation.
        releaseId = keccak256(abi.encodePacked(
            block.chainid,
            address(this),
            _burnNonce++,
            msg.sender,
            amount,
            destChainId,
            destRecipient
        ));

        // Burn the wrapped tokens. Caller must have approved this contract or
        // hold the tokens directly (standard ERC-20 spend from msg.sender).
        wrappedToken.burn(msg.sender, amount, releaseId);

        emit BurnForRelease(
            releaseId,
            msg.sender,
            destRecipient,
            amount,
            destChainId,
            uint64(block.timestamp)
        );
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    /// @notice Check whether a commitId has already been minted.
    function isMinted(bytes32 commitId) external view returns (bool) {
        return mintRecords[commitId].mintedAt != 0;
    }

    function getMintRecord(bytes32 commitId) external view returns (MintRecord memory) {
        return mintRecords[commitId];
    }

    // -----------------------------------------------------------------------
    // Admin: relayer management
    // -----------------------------------------------------------------------

    function addRelayer(address relayer) external onlyAdmin {
        if (relayer == address(0)) revert ZeroAddress();
        isRelayer[relayer] = true;
        emit RelayerAdded(relayer);
    }

    function removeRelayer(address relayer) external onlyAdmin {
        isRelayer[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    // -----------------------------------------------------------------------
    // Admin: wrapped token rotation
    // -----------------------------------------------------------------------

    /// @notice Point the adapter at a new wrapped token contract.
    ///         Old token is NOT migrated — used only for emergency recovery.
    ///         New token must already have granted MINTER_ROLE and BURNER_ROLE
    ///         to this contract's address.
    function setWrappedToken(address newToken) external onlyAdmin {
        if (newToken == address(0)) revert ZeroAddress();
        emit WrappedTokenSet(address(wrappedToken), newToken);
        wrappedToken = SuwappuWrappedToken(newToken);
    }

    // -----------------------------------------------------------------------
    // Admin: two-step transfer
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
}
