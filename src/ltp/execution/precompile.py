"""CrossVMPrecompile — universal cross-VM state read gateway at 0xF0."""

from __future__ import annotations

from dataclasses import dataclass

from .model import VM_TAG_PRECOMPILE
from .registry import VMRegistry
from .types import StateQuery

BASE_GAS = 700
PER_BYTE_GAS = 3


@dataclass(frozen=True)
class PrecompileResult:
    """Result of a precompile call."""

    success: bool
    data: bytes = b""
    error: str = ""
    gas_used: int = 0

    @classmethod
    def ok(cls, data: bytes, gas_used: int) -> PrecompileResult:
        return cls(success=True, data=data, gas_used=gas_used)

    @classmethod
    def fail(cls, error: str) -> PrecompileResult:
        return cls(success=False, error=error)


class CrossVMPrecompile:
    """Universal cross-VM state read gateway.

    Any VM can read any other VM's state by calling this precompile
    with [1-byte target_vm_tag][32-byte state key].
    """

    ADDRESS = VM_TAG_PRECOMPILE  # 0xF0

    def __init__(self, registry: VMRegistry) -> None:
        self._registry = registry

    def call(self, input_data: bytes, caller_vm_tag: int) -> PrecompileResult:
        """Execute a cross-VM state read."""
        if len(input_data) < 33:
            return PrecompileResult.fail("input too short: need [1-byte tag][32-byte key]")

        target_tag = input_data[0]
        key = input_data[1:33]

        if target_tag == caller_vm_tag:
            return PrecompileResult.fail("use native state access, not cross-VM")

        target = self._registry.get(target_tag)
        if target is None:
            return PrecompileResult.fail(f"vm 0x{target_tag:02X} not registered")

        query = StateQuery(target_vm=target_tag, query_type="storage", key=key)

        try:
            result = target.query_state(query)
        except Exception as exc:
            return PrecompileResult.fail(f"query failed: {exc}")

        if not result.found:
            return PrecompileResult.ok(data=b"", gas_used=BASE_GAS)

        gas_used = BASE_GAS + PER_BYTE_GAS * len(result.data)
        return PrecompileResult.ok(data=result.data, gas_used=gas_used)
