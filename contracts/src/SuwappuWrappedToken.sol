// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SuwappuWrappedToken
/// @notice ERC-20 representation of a source-chain asset on a destination chain.
///         Minted by SuwappuMintAdapter when a bridge lock is finalized;
///         burned by SuwappuMintAdapter when the user initiates a return transfer.
///
/// @dev Deployed once per bridged asset per destination chain.
///      The MintAdapter holds both MINTER_ROLE and BURNER_ROLE.
///      Admin (Gnosis Safe + TimelockController) can rotate roles and recover
///      from a compromised adapter without redeploying the token.
contract SuwappuWrappedToken is ERC20, AccessControl {
    // -----------------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------------

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    /// @notice Admin role for MINTER_ROLE / BURNER_ROLE. Self-administered and
    ///         held by a dedicated minter-manager (the Timelock in production),
    ///         SEPARATE from DEFAULT_ADMIN_ROLE. This is the P3-3 fix: the token
    ///         admin can no longer grant itself mint authority — only the
    ///         minter-manager can change the minter/burner set, and DEFAULT_ADMIN
    ///         is not the admin of MINTER_ADMIN_ROLE, so it cannot escalate.
    bytes32 public constant MINTER_ADMIN_ROLE = keccak256("MINTER_ADMIN_ROLE");

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    uint8 private immutable _decimals;
    uint256 public sourceChainId;    // chain ID where the underlying asset lives
    address public sourceToken;      // token address on source chain (address(0) for native ETH)

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Minted(address indexed to, uint256 amount, bytes32 indexed commitId);
    event Burned(address indexed from, uint256 amount, bytes32 indexed releaseId);

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param name_         Full token name, e.g. "Suwappu Wrapped Ether"
    /// @param symbol_       Ticker, e.g. "swETH"
    /// @param decimals_     Matches the source asset decimals (18 for ETH, 6 for USDC)
    /// @param sourceChainId_ Chain ID of the source chain
    /// @param sourceToken_  Token address on source chain (address(0) for native ETH)
    /// @param admin_         Initial DEFAULT_ADMIN_ROLE holder (Gnosis Safe address).
    ///                       Can manage non-minter config but CANNOT grant mint authority.
    /// @param minterManager_ MINTER_ADMIN_ROLE holder — the only principal that can
    ///                       grant/revoke MINTER_ROLE/BURNER_ROLE. MUST be the
    ///                       TimelockController in production (P3-3).
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint256 sourceChainId_,
        address sourceToken_,
        address admin_,
        address minterManager_
    ) ERC20(name_, symbol_) {
        require(admin_ != address(0), "SuwappuWrappedToken: zero admin");
        require(minterManager_ != address(0), "SuwappuWrappedToken: zero minter manager");
        _decimals = decimals_;
        sourceChainId = sourceChainId_;
        sourceToken = sourceToken_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);

        // P3-3: minter/burner management is separated from DEFAULT_ADMIN and
        // self-administered, so the token admin can never escalate to mint.
        _setRoleAdmin(MINTER_ROLE, MINTER_ADMIN_ROLE);
        _setRoleAdmin(BURNER_ROLE, MINTER_ADMIN_ROLE);
        _setRoleAdmin(MINTER_ADMIN_ROLE, MINTER_ADMIN_ROLE);
        _grantRole(MINTER_ADMIN_ROLE, minterManager_);
    }

    // -----------------------------------------------------------------------
    // ERC-20 overrides
    // -----------------------------------------------------------------------

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    // -----------------------------------------------------------------------
    // Minter / Burner interface
    // -----------------------------------------------------------------------

    /// @notice Mint wrapped tokens to a recipient after a bridge lock is finalized.
    /// @param to       Destination recipient address
    /// @param amount   Amount to mint (in token's native decimals)
    /// @param commitId The vault commitment ID that authorized this mint
    function mint(address to, uint256 amount, bytes32 commitId)
        external
        onlyRole(MINTER_ROLE)
    {
        require(to != address(0), "SuwappuWrappedToken: zero recipient");
        require(amount > 0, "SuwappuWrappedToken: zero amount");
        _mint(to, amount);
        emit Minted(to, amount, commitId);
    }

    /// @notice Burn wrapped tokens when a user initiates a return transfer.
    /// @param from      Token holder whose balance is burned
    /// @param amount    Amount to burn
    /// @param releaseId The release ID that will authorize the source-chain unlock
    function burn(address from, uint256 amount, bytes32 releaseId)
        external
        onlyRole(BURNER_ROLE)
    {
        require(amount > 0, "SuwappuWrappedToken: zero amount");
        _burn(from, amount);
        emit Burned(from, amount, releaseId);
    }
}
