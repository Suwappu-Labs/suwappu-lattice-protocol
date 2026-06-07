// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title SuwappuTimelockController
/// @notice OZ TimelockController extended with:
///   1. Per-function-selector minimum delays (upgrade=7d, param=3d, default=3d)
///   2. A GUARDIAN_ROLE for zero-delay emergency actions (pause only)
///   3. A whitelisted set of emergency selectors the guardian may bypass timelock for
///
/// @dev Deployment recipe:
///   - proposers:  [gnosisSafe]
///   - executors:  [address(0)] — anyone can execute ready ops (standard practice)
///   - admin:      address(0)   — no post-deploy admin; self-administered via timelock
///   - minDelay:   PARAM_DELAY  — base floor; per-selector map can raise it further
///
/// Usage pattern:
///   Gnosis Safe → schedule(target, 0, calldata, 0, salt, requiredDelay)
///   After delay → anyone calls execute(target, 0, calldata, 0, salt)
///   Guardian    → guardianExecute(target, calldata) for whitelisted emergency selectors
contract SuwappuTimelockController is TimelockController {
    // -----------------------------------------------------------------------
    // Delay constants
    // -----------------------------------------------------------------------

    /// @notice Minimum delay for contract upgrades and admin transfers.
    uint256 public constant UPGRADE_DELAY = 7 days;

    /// @notice Minimum delay for parameter changes (fee rates, caps, rate limits).
    uint256 public constant PARAM_DELAY   = 3 days;

    // -----------------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------------

    /// @notice GUARDIAN_ROLE holders can execute whitelisted emergency selectors
    ///         with zero delay. Intended for the protocol pause guardian address.
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice Per-function-selector minimum delay override.
    ///         If zero, the contract's base minDelay applies.
    ///         If non-zero, max(selectorDelay, minDelay) is enforced.
    mapping(bytes4 => uint256) public selectorDelay;

    /// @notice Function selectors the guardian may execute without timelock.
    ///         Only pause() and similarly reversible emergency functions belong here.
    mapping(bytes4 => bool) public emergencySelectors;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event SelectorDelaySet(bytes4 indexed selector, uint256 delay);
    event EmergencySelectorSet(bytes4 indexed selector, bool enabled);
    event GuardianExecuted(address indexed guardian, address indexed target, bytes4 selector);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error SelectorDelayTooShort(bytes4 selector, uint256 provided, uint256 required);
    error NotEmergencySelector(bytes4 selector);
    error EmptyCalldata();

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @param proposers_  Addresses granted PROPOSER + CANCELLER roles (Gnosis Safe)
    /// @param guardians_  Addresses granted GUARDIAN_ROLE (pause guardian EOA)
    constructor(
        address[] memory proposers_,
        address[] memory guardians_
    )
        // minDelay = PARAM_DELAY; executors = [address(0)] (open); no post-deploy admin
        TimelockController(
            PARAM_DELAY,
            proposers_,
            _openExecutors(),
            address(0)
        )
    {
        // Grant GUARDIAN_ROLE to each guardian
        for (uint256 i = 0; i < guardians_.length; i++) {
            _grantRole(GUARDIAN_ROLE, guardians_[i]);
        }

        // Pre-register upgrade-tier selectors — these are the highest-risk functions
        // across all Suwappu contracts. Proposers must supply at least UPGRADE_DELAY.
        _setSelectorDelay(_sel("transferAdmin(address)"),    UPGRADE_DELAY);
        _setSelectorDelay(_sel("setWrappedToken(address)"),  UPGRADE_DELAY);
        // UUPS upgrade selector (proxiableUUID / upgradeToAndCall)
        _setSelectorDelay(_sel("upgradeToAndCall(address,bytes)"), UPGRADE_DELAY);
        _setSelectorDelay(_sel("upgradeTo(address)"),        UPGRADE_DELAY);
    }

    // -----------------------------------------------------------------------
    // schedule override — enforce per-selector minimum delay
    // -----------------------------------------------------------------------

    /// @inheritdoc TimelockController
    /// @dev Adds per-selector delay enforcement on top of the base minDelay.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override {
        _enforceMinSelectorDelay(data, delay);
        super.schedule(target, value, data, predecessor, salt, delay);
    }

    /// @inheritdoc TimelockController
    /// @dev Adds per-selector delay enforcement for each batch item.
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public override {
        for (uint256 i = 0; i < payloads.length; i++) {
            _enforceMinSelectorDelay(payloads[i], delay);
        }
        super.scheduleBatch(targets, values, payloads, predecessor, salt, delay);
    }

    // -----------------------------------------------------------------------
    // Guardian emergency execution (zero-delay, whitelisted selectors only)
    // -----------------------------------------------------------------------

    /// @notice Execute a whitelisted emergency action immediately, bypassing
    ///         the timelock queue. Only callable by GUARDIAN_ROLE holders.
    ///         The target function's selector must be registered in emergencySelectors.
    ///
    /// @dev Intentionally restricted to void-return calls (no return value forwarded)
    ///      to keep the guardian path narrow and auditable.
    ///
    /// @param target  Contract to call
    /// @param data    Calldata — first 4 bytes must be a whitelisted emergency selector
    function guardianExecute(address target, bytes calldata data)
        external
    {
        _checkRole(GUARDIAN_ROLE, msg.sender);
        if (data.length < 4) revert EmptyCalldata();

        bytes4 sel = bytes4(data[:4]);
        if (!emergencySelectors[sel]) revert NotEmergencySelector(sel);

        emit GuardianExecuted(msg.sender, target, sel);

        (bool ok, bytes memory reason) = target.call(data);
        if (!ok) {
            // Bubble up revert reason
            assembly { revert(add(reason, 32), mload(reason)) }
        }
    }

    // -----------------------------------------------------------------------
    // Admin: configure selector delays and emergency whitelist
    // These functions are self-timelocked (must go through the timelock queue).
    // -----------------------------------------------------------------------

    /// @notice Register or update a per-selector minimum delay.
    ///         Must be scheduled through this timelock (self-administered).
    /// @param selector  4-byte function selector
    /// @param delay     Minimum delay in seconds (0 = revert to base minDelay)
    function setSelectorDelay(bytes4 selector, uint256 delay) external onlySelf {
        _setSelectorDelay(selector, delay);
    }

    /// @notice Add or remove a selector from the guardian emergency whitelist.
    ///         Must be scheduled through this timelock (self-administered).
    ///         Only add selectors for REVERSIBLE emergency actions (pause, not destroy).
    /// @param selector  4-byte function selector to whitelist / de-whitelist
    /// @param enabled   true to enable, false to remove
    function setEmergencySelector(bytes4 selector, bool enabled) external onlySelf {
        emergencySelectors[selector] = enabled;
        emit EmergencySelectorSet(selector, enabled);
    }

    // -----------------------------------------------------------------------
    // View helpers
    // -----------------------------------------------------------------------

    /// @notice Minimum delay required to schedule a call with the given data.
    function requiredDelay(bytes calldata data) external view returns (uint256) {
        if (data.length < 4) return getMinDelay();
        bytes4 sel = bytes4(data[:4]);
        uint256 selMin = selectorDelay[sel];
        uint256 base   = getMinDelay();
        return selMin > base ? selMin : base;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _enforceMinSelectorDelay(bytes calldata data, uint256 delay) internal view {
        if (data.length < 4) return; // no selector → base minDelay enforced by super
        bytes4 sel    = bytes4(data[:4]);
        uint256 selMin = selectorDelay[sel];
        if (selMin > 0 && delay < selMin) {
            revert SelectorDelayTooShort(sel, delay, selMin);
        }
    }

    function _setSelectorDelay(bytes4 selector, uint256 delay) internal {
        selectorDelay[selector] = delay;
        emit SelectorDelaySet(selector, delay);
    }

    /// @dev Returns a single-element array containing address(0), which grants
    ///      the EXECUTOR_ROLE to everyone. Standard open-executor pattern.
    function _openExecutors() internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = address(0);
    }

    function _sel(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    /// @dev Modifier restricting calls to operations executed through this timelock.
    modifier onlySelf() {
        require(msg.sender == address(this), "SuwappuTimelock: caller is not this contract");
        _;
    }
}
