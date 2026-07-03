"""Corridor roster loading — the trusted-membership boundary.

The 7-of-9 corridor membership is the root of trust for attestation
verification: whoever controls the roster controls which aggregate
signatures this node accepts. Until now the ``Corridor`` was only ever
built from in-repo test fixtures or an externally supplied dict via
``wire.corridor_from_dict`` with **no** structural validation and
**opt-in** Proof-of-Possession checking.

This module is the hardened path for loading a real roster from disk:

- exactly ``LTP_ATTESTATION_QUORUM_SIZE`` members,
- distinct authority ids and distinct BLS public keys,
- every member's ``corridor`` field matches the roster id,
- Proof-of-Possession verified for every member **by default**
  (LTP-A-015 adaptive rogue-key defense) — opting out is explicit and
  reserved for legacy test fixtures.

A roster file is JSON in the same wire format ``wire.corridor_to_dict``
produces; see ``config/corridor-roster.template.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .attestation import BadCorridorSize, Corridor, LtpError
from .constants import LTP_ATTESTATION_QUORUM_SIZE
from .wire import WireFormatError, corridor_from_dict

__all__ = [
    "RosterValidationError",
    "load_corridor_roster",
    "validate_roster",
]


class RosterValidationError(LtpError):
    """A roster is structurally invalid (duplicates, id mismatch, ...)."""


def validate_roster(corridor: Corridor, *, require_pop: bool = True) -> None:
    """Validate corridor membership as a trusted roster.

    Raises ``BadCorridorSize``, ``RosterValidationError``, or
    ``CorridorPopVerificationFailed`` on the first violation; returns
    ``None`` when the roster is acceptable.

    ``require_pop=False`` skips Proof-of-Possession verification. It
    exists only for pre-LTP-A-015 fixtures; production loading MUST keep
    the default.
    """
    if len(corridor.members) != LTP_ATTESTATION_QUORUM_SIZE:
        raise BadCorridorSize(LTP_ATTESTATION_QUORUM_SIZE, len(corridor.members))

    authorities = [m.authority for m in corridor.members]
    if len(set(authorities)) != len(authorities):
        raise RosterValidationError(
            f"duplicate authority ids in roster {corridor.id}: {sorted(authorities)}"
        )

    pubkeys = [m.bls_public_key for m in corridor.members]
    if len(set(pubkeys)) != len(pubkeys):
        raise RosterValidationError(f"duplicate BLS public keys in roster {corridor.id}")

    mismatched = [m.authority for m in corridor.members if m.corridor != corridor.id]
    if mismatched:
        raise RosterValidationError(
            f"members {mismatched} declare a corridor id != roster id {corridor.id}"
        )

    if require_pop:
        corridor.verify_pops()


def load_corridor_roster(path: str | Path, *, require_pop: bool = True) -> Corridor:
    """Load and validate a corridor roster from a JSON file.

    This is the function node operators should use to install the
    corridor membership they were handed at onboarding. It never returns
    a corridor that failed validation.
    """
    raw = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise WireFormatError(f"roster file {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise WireFormatError(
            f"roster file {path} must contain a JSON object, got {type(data).__name__}"
        )
    corridor = corridor_from_dict(data)
    validate_roster(corridor, require_pop=require_pop)
    return corridor
