"""
Access-policy enforcement for the lattice key (whitepaper §2.2.1, §2.3.1 step 2).

The lattice key carries an ``access_policy`` dict; MATERIALIZE MUST enforce it
after unsealing and before any shard fetch. This module is the enforcement
point, and its semantics mirror the machine-checked policy algebra in
``formal/lean/Ltp/Policy.lean``:

    permits(p, now, count) = lowerOk(not_before, now)
                           ∧ upperOk(not_after, now)
                           ∧ countOk(max_materializations, count)

with two strict refinements, both in the fail-closed direction (rejecting more
than ``permits`` is always sound — Lean ``minimal_is_sound``):

  - An unknown or malformed policy is rejected outright, never ignored.
  - A ``one-time`` policy with no explicit ``max_materializations`` defaults
    to a limit of 1 — the type's name is its meaning.

Scope, stated honestly (whitepaper §2.2.1): enforcement is *receiver-side*.
It constrains conforming receivers; it is not a cryptographic guarantee
against a receiver that modifies its own implementation. The materialization
count lives in the enforcing ``LTPProtocol`` instance's memory, keyed by the
sealed key's digest — it bounds replay of a sealed key *at that receiver*,
and does not survive process restart or span receivers. Durable or shared
counting is a deployment concern layered above this module.
"""

from __future__ import annotations

from numbers import Real

__all__ = ["KNOWN_POLICY_TYPES", "PolicyViolation", "check_policy", "validate_policy"]

KNOWN_POLICY_TYPES = frozenset({"unrestricted", "one-time", "time-limited", "delegatable"})


class PolicyViolation(Exception):
    """The lattice key's access policy denies this materialization."""


def _bound(policy: dict, key: str) -> float | None:
    """Read an optional numeric field, rejecting non-numeric junk."""
    value = policy.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Real):
        raise PolicyViolation(f"policy field {key!r} must be a number, got {type(value).__name__}")
    return float(value)


def validate_policy(policy: object) -> dict:
    """Structural validation only — no temporal or count evaluation.

    Suitable at SEAL time, where a not-yet-open window is legitimate but a
    malformed policy produces a key no conforming receiver will ever honor.
    Returns the policy dict on success; raises PolicyViolation otherwise.
    """
    if not isinstance(policy, dict):
        raise PolicyViolation(f"access_policy must be a dict, got {type(policy).__name__}")

    ptype = policy.get("type")
    if ptype not in KNOWN_POLICY_TYPES:
        raise PolicyViolation(f"unknown policy type {ptype!r} — rejecting (fail-closed)")

    _bound(policy, "not_before")
    _bound(policy, "not_after")

    limit = policy.get("max_materializations")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
        raise PolicyViolation(f"max_materializations must be a non-negative integer, got {limit!r}")
    return policy


def check_policy(policy: object, prior_materializations: int, now: float) -> None:
    """Raise PolicyViolation unless the policy permits a materialization now.

    ``prior_materializations`` is the number of *completed* materializations
    already performed under this sealed key at this receiver. Validation is
    fail-closed: anything that is not a well-formed policy of a known type is
    a violation, never a pass-through.
    """
    validate_policy(policy)
    assert isinstance(policy, dict)  # narrowed by validate_policy
    ptype = policy.get("type")

    not_before = _bound(policy, "not_before")
    if not_before is not None and now < not_before:
        raise PolicyViolation(
            f"materialization window not yet open (now={now}, not_before={not_before})"
        )

    not_after = _bound(policy, "not_after")
    if not_after is not None and now > not_after:
        raise PolicyViolation(f"materialization window expired (now={now}, not_after={not_after})")

    limit = policy.get("max_materializations")
    if limit is None and ptype == "one-time":
        limit = 1
    if limit is not None and prior_materializations >= limit:
        raise PolicyViolation(
            f"materialization count exhausted ({prior_materializations} of {limit} used)"
        )
