"""ExecutionModel protocol and VM tag/family constants."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import StateQuery, StateResult, TxResult

# ---------------------------------------------------------------------------
# VM family IDs (derived from tag: family = tag >> 4)
# ---------------------------------------------------------------------------

VM_FAMILY_ACCOUNT       = 0x00  # 0x01-0x0F
VM_FAMILY_OBJECT        = 0x01  # 0x10-0x1F
VM_FAMILY_REGISTER      = 0x02  # 0x20-0x2F
VM_FAMILY_UTXO          = 0x03  # 0x30-0x3F
VM_FAMILY_LEDGER_NATIVE = 0x04  # 0x40-0x4F
VM_FAMILY_SYSTEM        = 0x0E  # 0xE0-0xEF

FAMILY_NAMES: dict[int, str] = {
    VM_FAMILY_ACCOUNT: "account",
    VM_FAMILY_OBJECT: "object",
    VM_FAMILY_REGISTER: "register",
    VM_FAMILY_UTXO: "utxo",
    VM_FAMILY_LEDGER_NATIVE: "ledger_native",
    VM_FAMILY_SYSTEM: "system",
}

# ---------------------------------------------------------------------------
# Concrete VM tags
# ---------------------------------------------------------------------------

# Account-based (0x01-0x0F)
VM_TAG_EVM     = 0x01
VM_TAG_TVM     = 0x02

# Object-based (0x10-0x1F)
VM_TAG_MOVE    = 0x10

# Register-based (0x20-0x2F)
VM_TAG_SVM     = 0x20

# UTXO-based (0x30-0x3F)
VM_TAG_BITCOIN = 0x30
VM_TAG_PLUTUS  = 0x31

# Ledger-native (0x40-0x4F)
VM_TAG_CANTON  = 0x40
VM_TAG_CORDA   = 0x41
VM_TAG_FABRIC  = 0x42

# System modules (0xE0-0xEF)
VM_TAG_BRIDGE     = 0xE0
VM_TAG_GOVERNANCE = 0xE1
VM_TAG_IDENTITY   = 0xE2

# Reserved (0xF0-0xFF)
VM_TAG_PRECOMPILE = 0xF0


def family_from_tag(tag: int) -> int:
    """Derive family ID from a VM tag: family = tag >> 4."""
    return tag >> 4


# ---------------------------------------------------------------------------
# ExecutionModel protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class ExecutionModel(Protocol):
    """Universal interface — every VM executor implements this."""

    vm_tag: int
    vm_name: str
    family: str

    def execute(self, tx_bytes: bytes) -> TxResult: ...

    def state_root(self) -> bytes: ...

    def validate_tx(self, tx_bytes: bytes) -> bool: ...

    def query_state(self, query: StateQuery) -> StateResult: ...
