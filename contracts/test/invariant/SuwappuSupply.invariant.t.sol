// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SuwappuVault} from "../../src/SuwappuVault.sol";
import {SuwappuMintAdapter} from "../../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../../src/SuwappuWrappedToken.sol";

/// @title SuwappuSupplyInvariantTest
/// @notice Cross-domain stateful invariant suite for the Suwappu lock-and-mint
///         custody layer. This is the centerpiece harness called for in the
///         audit program (P1): it deploys the SOURCE-chain Vault together with
///         the DEST-chain MintAdapter + WrappedToken in one EVM and models the
///         RELAYER as the adversary — the actual trust boundary of the bridge.
///
/// The relayer can act honestly (mint exactly what was locked, using the
/// vault's own commitId) OR adversarially (mint with an arbitrary commitId /
/// amount, or reclaim a refund on a commit it already minted against). Because
/// `SuwappuMintAdapter.mint` never recomputes the commitId and `claimRefund`
/// has no cross-chain mint signal, BOTH of the following canonical bridge
/// invariants are expected to be VIOLATED on the current code:
///
///   INV-SUPPLY : wrapped.totalSupply() <= vault.totalLocked(asset)
///                (wrapped tokens must always be backed by locked collateral)
///   INV-XOR    : each vault commitId ends in at most one terminal outcome of
///                {minted, unlocked, refunded}  (no double-spend)
///
/// A GREEN run only becomes meaningful AFTER the C1 (commitId binding) and
/// C2 (refund-vs-mint) fixes land; today these must be RED. The harness follows
/// the Handler + ghost-variable pattern established in
/// OptimisticBridgeChallenge.invariant.t.sol.
contract SuwappuSupplyInvariantTest is Test {
    SuwappuVault         internal vault;
    SuwappuMintAdapter   internal adapter;
    SuwappuWrappedToken  internal wrapped;
    SuwappuSupplyHandler internal handler;

    address internal constant ADMIN = address(0xA1);
    address internal constant ETH   = address(0); // native asset sentinel

    function setUp() public {
        // feeBps = 0 so netAmount == grossAmount: keeps the supply/collateral
        // accounting exact (fees are an orthogonal concern, covered by INV-FEE).
        vault = new SuwappuVault(ADMIN, ADMIN, 0);

        // Wrapped token represents native ETH bridged from THIS chain.
        wrapped = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            block.chainid,
            ETH,
            ADMIN
        );

        adapter = new SuwappuMintAdapter(ADMIN, address(wrapped));

        handler = new SuwappuSupplyHandler(vault, adapter, wrapped);

        vm.startPrank(ADMIN);
        wrapped.grantRole(wrapped.MINTER_ROLE(), address(adapter));
        wrapped.grantRole(wrapped.BURNER_ROLE(), address(adapter));
        adapter.addRelayer(address(handler)); // relayer == adversary
        vault.addUnlocker(address(handler));   // also the source-chain unlocker
        vm.stopPrank();

        targetContract(address(handler));
    }

    /// INV-SUPPLY: minted wrapped supply can never exceed locked collateral.
    function invariant_supply_le_collateral() public view {
        assertLe(
            wrapped.totalSupply(),
            vault.totalLocked(ETH),
            "INV-SUPPLY violated: wrapped supply exceeds locked collateral"
        );
    }

    /// INV-XOR: no vault commit reaches more than one terminal outcome.
    function invariant_one_commit_one_outcome() public view {
        assertFalse(
            handler.observedDoubleSpend(),
            "INV-XOR violated: a commitId reached >1 terminal outcome"
        );
    }
}

/// @notice Bounds the fuzzer to legal (and adversarial-but-permitted) entry
///         points and tracks cross-domain ghost state.
contract SuwappuSupplyHandler is Test {
    SuwappuVault        public vault;
    SuwappuMintAdapter  public adapter;
    SuwappuWrappedToken public wrapped;

    address internal constant ETH  = address(0);
    uint256 internal constant DEST = 8453; // Base, the nominal destination chain

    bytes32[] public commits;
    mapping(bytes32 => uint256) public lockedNet; // commitId -> net locked
    mapping(bytes32 => bool) public minted;
    mapping(bytes32 => bool) public unlocked;
    mapping(bytes32 => bool) public refunded;

    bool public observedDoubleSpend;

    constructor(SuwappuVault _v, SuwappuMintAdapter _a, SuwappuWrappedToken _w) {
        vault = _v;
        adapter = _a;
        wrapped = _w;
        vm.deal(address(this), 10_000 ether);
    }

    receive() external payable {}

    function _markTerminal(bytes32 id, uint8 which) internal {
        if (which == 0) minted[id] = true;
        else if (which == 1) unlocked[id] = true;
        else refunded[id] = true;
        uint8 n = (minted[id] ? 1 : 0) + (unlocked[id] ? 1 : 0) + (refunded[id] ? 1 : 0);
        if (n > 1) observedDoubleSpend = true;
    }

    // ---- User locks ETH on the source chain ----
    function lock(uint256 amt) external {
        amt = bound(amt, 1, 10 ether);
        if (address(this).balance < amt) return;
        try vault.lockETH{value: amt}(DEST, address(this)) returns (bytes32 id) {
            commits.push(id);
            lockedNet[id] = amt; // feeBps == 0 => net == gross
        } catch {}
    }

    // ---- Relayer mints HONESTLY: exactly the locked amount, vault's commitId ----
    function honestMint(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        if (minted[id] || lockedNet[id] == 0) return;
        try adapter.mint(id, address(this), lockedNet[id], block.chainid) {
            _markTerminal(id, 0);
        } catch {}
    }

    // ---- Relayer mints ADVERSARIALLY: arbitrary commitId + amount (C1) ----
    function maliciousMint(bytes32 fakeId, uint256 amt, address to) external {
        amt = bound(amt, 1, 100 ether);
        if (to == address(0)) to = address(0xBAD);
        if (lockedNet[fakeId] != 0) return; // must be an id with NO backing lock
        try adapter.mint(fakeId, to, amt, block.chainid) {} catch {}
    }

    // ---- Relayer unlocks source collateral (return path) ----
    function unlock(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        try vault.unlock(id, address(this)) {
            _markTerminal(id, 1);
        } catch {}
    }

    // ---- User reclaims a refund after the timeout (C2 when already minted) ----
    function refund(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        try vault.claimRefund(id) {
            _markTerminal(id, 2);
        } catch {}
    }

    // ---- Advance time so refunds become claimable ----
    function warp(uint256 secs) external {
        secs = bound(secs, 0, 30 days);
        vm.warp(block.timestamp + secs);
    }
}
