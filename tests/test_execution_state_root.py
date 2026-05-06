"""Tests for MultiVMStateRoot — two-level Merkle over VM families."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


class TestMultiVMStateRoot:
    def test_single_vm_root(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=1)
        result = root.root
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_two_vms_same_family(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        root = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x02: b"\xbb" * 32},
            batch_round=1,
        )
        assert len(root.root) == 32

    def test_two_vms_different_families(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        root = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32},
            batch_round=1,
        )
        assert len(root.root) == 32

    def test_deterministic(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        roots = {0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32, 0xE0: b"\xcc" * 32}
        r1 = MultiVMStateRoot(vm_roots=roots, batch_round=5)
        r2 = MultiVMStateRoot(vm_roots=roots, batch_round=5)
        assert r1.root == r2.root

    def test_different_round_different_root(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        roots = {0x01: b"\xaa" * 32}
        r1 = MultiVMStateRoot(vm_roots=roots, batch_round=1)
        r2 = MultiVMStateRoot(vm_roots=roots, batch_round=2)
        assert r1.root != r2.root

    def test_order_independence(self):
        """Tag insertion order doesn't matter — sorted internally."""
        from src.ltp.execution.state_root import MultiVMStateRoot
        r1 = MultiVMStateRoot(
            vm_roots={0x10: b"\xbb" * 32, 0x01: b"\xaa" * 32},
            batch_round=1,
        )
        r2 = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32},
            batch_round=1,
        )
        assert r1.root == r2.root

    def test_active_families(self):
        from src.ltp.execution.state_root import MultiVMStateRoot
        root = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32, 0xE0: b"\xcc" * 32},
            batch_round=1,
        )
        families = root.active_families()
        assert 0x00 in families  # Account (0x01 >> 4)
        assert 0x01 in families  # Object (0x10 >> 4)
        assert 0x0E in families  # System (0xE0 >> 4)

    def test_family_subtree_root(self):
        """Can get the Merkle root for a single family."""
        from src.ltp.execution.state_root import MultiVMStateRoot
        root = MultiVMStateRoot(
            vm_roots={0x01: b"\xaa" * 32, 0x02: b"\xbb" * 32, 0x10: b"\xcc" * 32},
            batch_round=1,
        )
        account_subtree = root.family_subtree_root(0x00)
        object_subtree = root.family_subtree_root(0x01)
        assert len(account_subtree) == 32
        assert len(object_subtree) == 32
        assert account_subtree != object_subtree


class TestMultiVMStateRootHypothesis:
    @given(
        tags=st.lists(
            st.sampled_from([0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0xE0]),
            min_size=1,
            max_size=5,
            unique=True,
        ),
        round_num=st.integers(min_value=0, max_value=2**32),
    )
    @settings(max_examples=50)
    def test_deterministic_property(self, tags, round_num):
        from src.ltp.execution.state_root import MultiVMStateRoot
        roots = {tag: bytes([tag]) * 32 for tag in tags}
        r1 = MultiVMStateRoot(vm_roots=roots, batch_round=round_num)
        r2 = MultiVMStateRoot(vm_roots=roots, batch_round=round_num)
        assert r1.root == r2.root

    @given(
        tags=st.lists(
            st.sampled_from([0x01, 0x10, 0x20, 0x30, 0xE0]),
            min_size=1,
            max_size=5,
            unique=True,
        ),
    )
    @settings(max_examples=50)
    def test_root_is_32_bytes(self, tags):
        from src.ltp.execution.state_root import MultiVMStateRoot
        roots = {tag: bytes([tag]) * 32 for tag in tags}
        r = MultiVMStateRoot(vm_roots=roots, batch_round=0)
        assert len(r.root) == 32
