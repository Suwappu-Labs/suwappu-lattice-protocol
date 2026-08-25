// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LTPMultiSig
/// @author Suwappu (SUWAPPU)
/// @notice Lightweight N-of-M multi-signature wallet for LTPAnchorRegistry admin.
/// @dev Owners propose transactions, collect confirmations, then execute.
///      Designed for testnet (2-of-3). Production should use Gnosis Safe.
contract LTPMultiSig {
    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event TransactionSubmitted(uint256 indexed txId, address indexed to, bytes data);
    event TransactionConfirmed(uint256 indexed txId, address indexed owner);
    event TransactionRevoked(uint256 indexed txId, address indexed owner);
    event TransactionExecuted(uint256 indexed txId);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error NotOwner(address caller);
    error TxNotFound(uint256 txId);
    error TxAlreadyExecuted(uint256 txId);
    error TxAlreadyConfirmed(uint256 txId, address owner);
    error TxNotConfirmed(uint256 txId, address owner);
    error InsufficientConfirmations(uint256 txId, uint256 have, uint256 need);
    error TxExecutionFailed(uint256 txId, bytes returnData);
    error InvalidThreshold(uint256 threshold, uint256 ownerCount);
    error DuplicateOwner(address owner);
    error ZeroAddress();
    error OnlySelf();

    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;

    Transaction[] public transactions;
    /// @notice txId => owner => confirmed
    mapping(uint256 => mapping(address => bool)) public confirmations;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(address[] memory _owners, uint256 _threshold) {
        if (_owners.length == 0) revert InvalidThreshold(_threshold, 0);
        if (_threshold == 0 || _threshold > _owners.length) {
            revert InvalidThreshold(_threshold, _owners.length);
        }

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            if (owner == address(0)) revert ZeroAddress();
            if (isOwner[owner]) revert DuplicateOwner(owner);
            isOwner[owner] = true;
            owners.push(owner);
            emit OwnerAdded(owner);
        }

        threshold = _threshold;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert NotOwner(msg.sender);
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    modifier txExists(uint256 txId) {
        if (txId >= transactions.length) revert TxNotFound(txId);
        _;
    }

    modifier notExecuted(uint256 txId) {
        if (transactions[txId].executed) revert TxAlreadyExecuted(txId);
        _;
    }

    // -----------------------------------------------------------------------
    // Owner functions
    // -----------------------------------------------------------------------

    /// @notice Submit a new transaction for confirmation.
    function submitTransaction(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyOwner returns (uint256 txId) {
        txId = transactions.length;
        transactions.push(Transaction({
            to: to,
            value: value,
            data: data,
            executed: false,
            confirmations: 0
        }));

        emit TransactionSubmitted(txId, to, data);

        // Auto-confirm for the submitter
        _confirm(txId);
    }

    /// @notice Confirm a pending transaction.
    function confirmTransaction(uint256 txId)
        external
        onlyOwner
        txExists(txId)
        notExecuted(txId)
    {
        _confirm(txId);
    }

    /// @notice Revoke a previously given confirmation.
    function revokeConfirmation(uint256 txId)
        external
        onlyOwner
        txExists(txId)
        notExecuted(txId)
    {
        if (!confirmations[txId][msg.sender]) {
            revert TxNotConfirmed(txId, msg.sender);
        }

        confirmations[txId][msg.sender] = false;
        transactions[txId].confirmations -= 1;

        emit TransactionRevoked(txId, msg.sender);
    }

    /// @notice Execute a confirmed transaction.
    function executeTransaction(uint256 txId)
        external
        onlyOwner
        txExists(txId)
        notExecuted(txId)
    {
        Transaction storage txn = transactions[txId];
        if (txn.confirmations < threshold) {
            revert InsufficientConfirmations(txId, txn.confirmations, threshold);
        }

        txn.executed = true;

        (bool success, bytes memory returnData) = txn.to.call{value: txn.value}(txn.data);
        if (!success) revert TxExecutionFailed(txId, returnData);

        emit TransactionExecuted(txId);
    }

    // -----------------------------------------------------------------------
    // Self-governance (executed through the multi-sig itself)
    // -----------------------------------------------------------------------

    /// @notice Add a new owner. Must be called via multi-sig.
    function addOwner(address owner) external onlySelf {
        if (owner == address(0)) revert ZeroAddress();
        if (isOwner[owner]) revert DuplicateOwner(owner);
        isOwner[owner] = true;
        owners.push(owner);
        emit OwnerAdded(owner);
    }

    /// @notice Remove an owner. Must be called via multi-sig.
    function removeOwner(address owner) external onlySelf {
        if (!isOwner[owner]) revert NotOwner(owner);
        isOwner[owner] = false;

        // Remove from array
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == owner) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                break;
            }
        }

        // Adjust threshold if needed
        if (threshold > owners.length) {
            uint256 old = threshold;
            threshold = owners.length;
            emit ThresholdChanged(old, threshold);
        }

        emit OwnerRemoved(owner);
    }

    /// @notice Change the confirmation threshold. Must be called via multi-sig.
    function changeThreshold(uint256 newThreshold) external onlySelf {
        if (newThreshold == 0 || newThreshold > owners.length) {
            revert InvalidThreshold(newThreshold, owners.length);
        }
        uint256 old = threshold;
        threshold = newThreshold;
        emit ThresholdChanged(old, newThreshold);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getTransactionCount() external view returns (uint256) {
        return transactions.length;
    }

    function getTransaction(uint256 txId) external view returns (Transaction memory) {
        return transactions[txId];
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    function _confirm(uint256 txId) internal {
        if (confirmations[txId][msg.sender]) {
            revert TxAlreadyConfirmed(txId, msg.sender);
        }

        confirmations[txId][msg.sender] = true;
        transactions[txId].confirmations += 1;

        emit TransactionConfirmed(txId, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Receive ETH (for gas funding)
    // -----------------------------------------------------------------------

    receive() external payable {}
}
