// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title TestSetup
/// @notice Shared test fixtures for LTPAnchorRegistry tests.
///         Deploys behind a UUPS proxy, matching production topology.
abstract contract TestSetup is Test {
    LTPAnchorRegistry public implementation;
    LTPAnchorRegistry public registry; // points to proxy

    address public admin = address(0xAD);
    address public nonAdmin = address(0xBEEF);

    bytes32 public signerVkHash = keccak256("test-signer-vk");
    bytes32 public signerVkHash2 = keccak256("test-signer-vk-2");

    function setUp() public virtual {
        // 1. Deploy implementation
        implementation = new LTPAnchorRegistry();

        // 2. Deploy proxy pointing to implementation
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        // 3. Cast proxy to registry interface
        registry = LTPAnchorRegistry(address(proxy));

        // 4. Register a default signer
        vm.prank(admin);
        registry.registerSigner(signerVkHash);
    }

    function _digest(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("anchor-digest-", seed));
    }

    function _entityId(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("entity-id-", seed));
    }

    function _merkleRoot(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("merkle-root-", seed));
    }

    function _policyHash(uint256 seed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("policy-hash-", seed));
    }
}
