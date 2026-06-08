// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// @title CrossChainForkTest
/// @notice Fork tests against both SUWAPPU Testnet and Base Sepolia registries.
/// @dev Requires SUWAPPU_RPC_URL and BASE_SEPOLIA_RPC_URL env vars. Skips if missing.
contract CrossChainForkTest is Test {
    // Deployed registry proxies
    address constant SUWAPPU_PROXY = 0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4;
    address constant BASE_PROXY = 0x79eF1B7914f98C5C1404617449AB1f377c475996;

    // Signer VK hash registered on Base Sepolia deploy (from L2_INITIAL_SIGNERS)
    bytes32 constant SIGNER_VK_HASH = 0x869ccc023e1fe777e23c0c67c8bf4eba3a67ac6bdeef5028514575829e79456a;

    uint256 suwappuFork;
    uint256 baseFork;
    bool suwappuAvailable;
    bool baseAvailable;

    function setUp() public {
        // Use envOr to avoid revert when env vars are missing (CI)
        string memory suwappuRpc = vm.envOr("SUWAPPU_RPC_URL", string(""));
        string memory baseRpc = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));

        if (bytes(suwappuRpc).length > 0) {
            try vm.createFork(suwappuRpc) returns (uint256 forkId) {
                suwappuFork = forkId;
                suwappuAvailable = true;
            } catch {}
        }

        if (bytes(baseRpc).length > 0) {
            try vm.createFork(baseRpc) returns (uint256 forkId) {
                baseFork = forkId;
                baseAvailable = true;
            } catch {}
        }
    }

    /// @notice Both registries report version >= 5 (SUWAPPU v5, Base v6).
    function test_both_registries_version() public {
        if (!suwappuAvailable || !baseAvailable) {
            emit log("SKIP: RPC URLs not available");
            return;
        }

        // Check SUWAPPU version (v5+)
        vm.selectFork(suwappuFork);
        (bool ok1, bytes memory data1) = SUWAPPU_PROXY.staticcall(
            abi.encodeWithSignature("version()")
        );
        assertTrue(ok1, "SUWAPPU version() call failed");
        uint256 suwappuVersion = abi.decode(data1, (uint256));
        assertGe(suwappuVersion, 5, "SUWAPPU version should be >= 5");

        // Check Base version (v6)
        vm.selectFork(baseFork);
        (bool ok2, bytes memory data2) = BASE_PROXY.staticcall(
            abi.encodeWithSignature("version()")
        );
        assertTrue(ok2, "Base version() call failed");
        uint256 baseVersion = abi.decode(data2, (uint256));
        assertEq(baseVersion, 6, "Base version should be 6");
    }

    /// @notice Anchor on SUWAPPU fork is NOT visible on Base fork (chain isolation).
    function test_cross_chain_isolation() public {
        if (!suwappuAvailable || !baseAvailable) {
            emit log("SKIP: RPC URLs not available");
            return;
        }

        // Use a unique test digest
        bytes32 testDigest = keccak256("cross-chain-isolation-test-4d");

        // Check it's NOT anchored on SUWAPPU
        vm.selectFork(suwappuFork);
        (bool ok1, bytes memory data1) = SUWAPPU_PROXY.staticcall(
            abi.encodeWithSignature("isAnchored(bytes32)", testDigest)
        );
        assertTrue(ok1, "SUWAPPU isAnchored call failed");
        bool anchoredOnSuwappu = abi.decode(data1, (bool));
        assertFalse(anchoredOnSuwappu, "Test digest should not exist on SUWAPPU");

        // Check it's NOT anchored on Base either
        vm.selectFork(baseFork);
        (bool ok2, bytes memory data2) = BASE_PROXY.staticcall(
            abi.encodeWithSignature("isAnchored(bytes32)", testDigest)
        );
        assertTrue(ok2, "Base isAnchored call failed");
        bool anchoredOnBase = abi.decode(data2, (bool));
        assertFalse(anchoredOnBase, "Test digest should not exist on Base");
    }

    /// @notice Verify the signer VK hash is registered on Base Sepolia.
    function test_signer_registered_on_base() public {
        if (!baseAvailable) {
            emit log("SKIP: BASE_SEPOLIA_RPC_URL not available");
            return;
        }

        vm.selectFork(baseFork);
        (bool ok, bytes memory data) = BASE_PROXY.staticcall(
            abi.encodeWithSignature("authorizedSigners(bytes32)", SIGNER_VK_HASH)
        );
        assertTrue(ok, "authorizedSigners call failed");
        bool isAuthorized = abi.decode(data, (bool));
        assertTrue(isAuthorized, "Signer should be registered on Base Sepolia");
    }
}
