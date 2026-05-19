"""RBAC roles and scoped permissions for the writer registry (Spec C2 §5).

Defines the action enum, permission model, role assignments, and three
built-in roles (Owner, Admin, Sponsor) that ship with every registry
instance.  Custom roles are constructed with the same primitives.

Design principles:
- All permission and role objects are immutable (frozen dataclasses).
- Scope is opt-in: a ``None`` scope means "all tiers" / "all VMs".
- ``matches()`` / ``has_permission()`` short-circuit cleanly — no exceptions
  for missing optional parameters.

Reference: ETP Spec C2 §5 (RBAC + Scoped Permissions)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .writer import IdentityTier

__all__ = [
    "RegistryAction",
    "ScopedPermission",
    "RegistryRole",
    "RoleAssignment",
    "builtin_owner",
    "builtin_admin",
    "builtin_sponsor",
]


# ---------------------------------------------------------------------------
# Registry Action Enum
# ---------------------------------------------------------------------------


class RegistryAction(str, Enum):
    """Operations that can be performed on the writer registry.

    Each action corresponds to a distinct privilege that must be
    explicitly granted via a ``ScopedPermission`` on a ``RegistryRole``.
    """

    APPROVE = "approve"
    REJECT = "reject"
    SUSPEND = "suspend"
    REINSTATE = "reinstate"
    REVOKE = "revoke"
    CONFIGURE_POLICY = "configure_policy"
    SET_RATE_LIMIT = "set_rate_limit"
    MANAGE_ALLOWLIST = "manage_allowlist"
    MANAGE_DENYLIST = "manage_denylist"


# ---------------------------------------------------------------------------
# Scoped Permission
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopedPermission:
    """A single permission granting ``action`` within optional scope limits.

    Scope parameters:
        tier_scope  — frozenset of :class:`IdentityTier` this permission
                      applies to.  ``None`` means all tiers.
        vm_scope    — frozenset of VM tag integers this permission applies
                      to.  ``None`` means all VMs.

    The constructor transparently converts plain ``set`` arguments to
    ``frozenset`` so callers need not do it manually.
    """

    action: RegistryAction
    tier_scope: Optional[frozenset[IdentityTier]]
    vm_scope: Optional[frozenset[int]]

    def __init__(
        self,
        action: RegistryAction,
        tier_scope: Optional[set[IdentityTier] | frozenset[IdentityTier]] = None,
        vm_scope: Optional[set[int] | frozenset[int]] = None,
    ) -> None:
        object.__setattr__(self, "action", action)
        object.__setattr__(
            self,
            "tier_scope",
            frozenset(tier_scope) if tier_scope is not None else None,
        )
        object.__setattr__(
            self,
            "vm_scope",
            frozenset(vm_scope) if vm_scope is not None else None,
        )

    def matches(
        self,
        action: RegistryAction,
        tier: Optional[IdentityTier] = None,
        vm_tag: Optional[int] = None,
    ) -> bool:
        """Return ``True`` if this permission covers *action* in the given scope.

        Logic:
        1. Action must match exactly.
        2. If ``tier_scope`` is set **and** ``tier`` is provided, ``tier``
           must be in ``tier_scope``.  (If ``tier`` is ``None`` the scope
           check is skipped — caller did not supply context.)
        3. Same logic for ``vm_scope`` / ``vm_tag``.
        """
        if self.action is not action:
            return False
        if self.tier_scope is not None and tier is not None:
            if tier not in self.tier_scope:
                return False
        if self.vm_scope is not None and vm_tag is not None:
            if vm_tag not in self.vm_scope:
                return False
        return True


# ---------------------------------------------------------------------------
# Registry Role
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistryRole:
    """An immutable named collection of :class:`ScopedPermission` objects.

    Attributes:
        name        — Human-readable role identifier.
        permissions — Ordered tuple of scoped permissions (constructor
                      accepts a list and converts).
        is_builtin  — True for the three shipped roles; False for
                      operator-defined custom roles.
    """

    name: str
    permissions: tuple[ScopedPermission, ...]
    is_builtin: bool

    def __init__(
        self,
        name: str,
        permissions: list[ScopedPermission] | tuple[ScopedPermission, ...],
        is_builtin: bool = False,
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "permissions", tuple(permissions))
        object.__setattr__(self, "is_builtin", is_builtin)

    def has_permission(
        self,
        action: RegistryAction,
        tier: Optional[IdentityTier] = None,
        vm_tag: Optional[int] = None,
    ) -> bool:
        """Return ``True`` if any permission in this role matches the call."""
        return any(p.matches(action, tier=tier, vm_tag=vm_tag) for p in self.permissions)


# ---------------------------------------------------------------------------
# Role Assignment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoleAssignment:
    """Binds a :class:`RegistryRole` to an actor identified by fingerprint.

    Attributes:
        role          — The assigned role.
        assignee_fp   — 32-byte fingerprint of the identity receiving the role.
        assigned_by   — 32-byte fingerprint of the assigning actor.
        assigned_at   — Epoch integer at which assignment was made.
        expires_at    — Optional epoch integer after which assignment lapses.
                        ``None`` means the assignment never expires.
    """

    role: RegistryRole
    assignee_fp: bytes
    assigned_by: bytes
    assigned_at: int
    expires_at: Optional[int] = None

    def is_active(self, current_epoch: int) -> bool:
        """Return ``True`` if the assignment has not yet expired.

        A permanent assignment (``expires_at is None``) is always active.
        Otherwise the assignment is active only while
        ``current_epoch < expires_at``.
        """
        if self.expires_at is None:
            return True
        return current_epoch < self.expires_at


# ---------------------------------------------------------------------------
# Built-in Role Factories
# ---------------------------------------------------------------------------


def _all_actions() -> list[ScopedPermission]:
    """Unrestricted permissions for every action."""
    return [ScopedPermission(action=a) for a in RegistryAction]


def builtin_owner() -> RegistryRole:
    """Return the built-in **Owner** role.

    Granted all 9 actions with no tier or VM restrictions.
    Intended for the registry deployer / governance controller.
    """
    return RegistryRole(
        name="owner",
        permissions=_all_actions(),
        is_builtin=True,
    )


def builtin_admin() -> RegistryRole:
    """Return the built-in **Admin** role.

    Granted: APPROVE, REJECT, SUSPEND, REINSTATE, REVOKE.
    Denied: CONFIGURE_POLICY, SET_RATE_LIMIT, MANAGE_ALLOWLIST, MANAGE_DENYLIST.
    """
    admin_actions = {
        RegistryAction.APPROVE,
        RegistryAction.REJECT,
        RegistryAction.SUSPEND,
        RegistryAction.REINSTATE,
        RegistryAction.REVOKE,
    }
    return RegistryRole(
        name="admin",
        permissions=[ScopedPermission(action=a) for a in admin_actions],
        is_builtin=True,
    )


def builtin_sponsor() -> RegistryRole:
    """Return the built-in **Sponsor** role.

    Granted: APPROVE only.
    Intended for ACTIVE writers who vouch for new enrollees.
    """
    return RegistryRole(
        name="sponsor",
        permissions=[ScopedPermission(action=RegistryAction.APPROVE)],
        is_builtin=True,
    )
