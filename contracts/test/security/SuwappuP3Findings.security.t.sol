// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SuwappuVault} from "../../src/SuwappuVault.sol";
import {SuwappuMintAdapter} from "../../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../../src/SuwappuWrappedToken.sol";

/// @title SuwappuP3Findings.security.t.sol
/// @notice Empirical confirmation of the NEW P3 (attack-class review) findings.
///         These tests demonstrate the vulnerability EXISTS on current code
///         (they pass by reaching the unsafe state), per the audit plan's
///         "reproduce >=High findings before treating as confirmed".

contract SuwappuP3FindingsTest is Test {
    address internal constant ADMIN = address(0xA1);
    address internal attacker = makeAddr("attacker");
    address internal relayer  = makeAddr("relayer");
    address internal alice    = makeAddr("alice");

    // ---- P3-3 [CRITICAL]: WrappedToken DEFAULT_ADMIN_ROLE is a parallel, unconstrained minter ----
    function test_P3_3_admin_is_parallel_unconstrained_minter() public {
        SuwappuWrappedToken wt = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether", "swETH", 18, 1, address(0), ADMIN
        );
        SuwappuMintAdapter adapter = new SuwappuMintAdapter(ADMIN, address(wt));
        bytes32 minterRole = wt.MINTER_ROLE();
        vm.startPrank(ADMIN);
        wt.grantRole(minterRole, address(adapter)); // intended minter
        // The token admin can grant MINTER_ROLE to ANYONE and mint unbacked supply,
        // entirely bypassing the adapter's commitId / mintRecords / relayer-bond controls.
        wt.grantRole(minterRole, attacker);
        vm.stopPrank();

        vm.prank(attacker);
        wt.mint(attacker, 1_000_000 ether, bytes32(0)); // no commitId binding, no cap, no vault lock

        // VULNERABILITY CONFIRMED: 1M unbacked wrapped tokens exist with zero collateral.
        assertEq(wt.totalSupply(), 1_000_000 ether, "P3-3: admin minted unbacked supply via parallel minter");
        assertEq(wt.balanceOf(attacker), 1_000_000 ether);
    }

    // ---- P3-5 [HIGH]: one source Lock replays into N mints across destination MintAdapter instances ----
    function test_P3_5_cross_instance_mint_replay() public {
        // One Vault on the "source" chain.
        SuwappuVault vault = new SuwappuVault(ADMIN, ADMIN, 0);

        // TWO MintAdapter instances (the documented "one per asset per dest chain" model),
        // each with its own wrapped token. Same relayer operates both.
        SuwappuWrappedToken wt1 = new SuwappuWrappedToken("swETH-1","swETH1",18,1,address(0),ADMIN);
        SuwappuWrappedToken wt2 = new SuwappuWrappedToken("swETH-2","swETH2",18,1,address(0),ADMIN);
        SuwappuMintAdapter a1 = new SuwappuMintAdapter(ADMIN, address(wt1));
        SuwappuMintAdapter a2 = new SuwappuMintAdapter(ADMIN, address(wt2));
        vm.startPrank(ADMIN);
        wt1.grantRole(wt1.MINTER_ROLE(), address(a1));
        wt2.grantRole(wt2.MINTER_ROLE(), address(a2));
        a1.addRelayer(relayer);
        a2.addRelayer(relayer);
        vm.stopPrank();

        // Alice locks 10 ETH ONCE on the source vault -> one commitId, 10 ETH collateral.
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 10 ether}(8453, alice);

        // The SAME commitId mints on BOTH adapter instances (per-instance dedup, no destChainId binding).
        vm.startPrank(relayer);
        a1.mint(commitId, alice, 10 ether, 1);
        a2.mint(commitId, alice, 10 ether, 1); // replay succeeds on the second instance
        vm.stopPrank();

        // VULNERABILITY CONFIRMED: 20 wrapped ETH minted against 10 ETH of collateral.
        assertEq(wt1.totalSupply(), 10 ether);
        assertEq(wt2.totalSupply(), 10 ether);
        assertEq(
            wt1.totalSupply() + wt2.totalSupply(),
            20 ether,
            "P3-5: one 10-ETH lock minted 20 wrapped ETH across two adapter instances"
        );
        assertEq(vault.totalLocked(address(0)), 10 ether, "only 10 ETH actually locked");
    }
}
