// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ZKNOX_dilithium65} from "../src/ZKNOX_dilithium65.sol";
import {F1600Helper} from "./F1600Helper.sol";

/// Signatures in test/KAT/ltp65.json were produced by LTP's own
/// ltp.primitives.MLDSA (pqcrypto 0.4.0, ML-DSA-65, empty context).
contract LTPCompatTest is Test {
    ZKNOX_dilithium65 v;
    string j;

    function setUp() public {
        v = new ZKNOX_dilithium65(F1600Helper.deploy(vm));
        j = vm.readFile("test/KAT/ltp65.json");
    }

    function _k(string memory a, uint256 i) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(".", a, "[", vm.toString(i), "]"));
    }

    function testLTPRoot32() public view {
        bytes memory root = vm.parseJsonBytes(j, ".root");
        bytes memory pk = _k("blobs", 0);
        bytes memory sig = _k("sigRoot", 0);
        uint256 g = gasleft();
        bool ok = v.verify(pk, root, sig, "");
        console.log("verify (ctx form), 32-byte root:", g - gasleft());
        assertTrue(ok);
        g = gasleft();
        bytes4 r = v.verify(pk, bytes32(root), sig);
        console.log("verify (bytes32 form):", g - gasleft());
        assertTrue(r != bytes4(0xFFFFFFFF));
    }

    function testLTPLongMessage() public view {
        bytes memory m = vm.parseJsonBytes(j, ".long");
        bytes memory pk = _k("blobs", 1);
        bytes memory sig = _k("sigLong", 1);
        uint256 g = gasleft();
        bool ok = v.verify(pk, m, sig, "");
        console.log("verify, 225-byte message:", g - gasleft());
        assertTrue(ok);
    }

    function testQuorum7of9() public view {
        bytes memory root = vm.parseJsonBytes(j, ".root");
        uint256 total;
        for (uint256 i = 0; i < 7; i++) {
            bytes memory pk = _k("blobs", i);
            bytes memory sig = _k("sigRoot", i);
            uint256 g = gasleft();
            bool ok = v.verify(pk, root, sig, "");
            total += g - gasleft();
            assertTrue(ok);
        }
        console.log("7 verifies, execution total:", total);
    }

    function _try(bytes memory pk, bytes memory m, bytes memory sig, bytes memory ctx) internal view returns (bool ok) {
        try v.verify(pk, m, sig, ctx) returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
    }

    function testRejections() public view {
        bytes memory root = vm.parseJsonBytes(j, ".root");
        bytes memory pk = _k("blobs", 0);
        bytes memory sig = _k("sigRoot", 0);
        assertTrue(_try(pk, root, sig, ""));
        // wrong key
        assertFalse(_try(_k("blobs", 1), root, sig, ""));
        // wrong message
        assertFalse(_try(pk, abi.encodePacked(keccak256(root)), sig, ""));
        // a non-empty ctx must not accept an empty-ctx signature
        assertFalse(_try(pk, root, sig, "LTP-corridor-v1"));
        // flipped bit in z
        sig[100] = bytes1(uint8(sig[100]) ^ 1);
        assertFalse(_try(pk, root, sig, ""));
    }
}
