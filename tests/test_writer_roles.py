"""Tests for the RBAC roles subsystem (Spec C2 §5).

Covers the RegistryAction enum, ScopedPermission matching logic,
RegistryRole permission delegation, RoleAssignment lifecycle, and the
three built-in role factories (owner, admin, sponsor).
"""

import pytest

from src.ltp.execution.writer import IdentityTier
from src.ltp.execution.writer_roles import (
    RegistryAction,
    ScopedPermission,
    RegistryRole,
    RoleAssignment,
    builtin_owner,
    builtin_admin,
    builtin_sponsor,
)


# ---------------------------------------------------------------------------
# TestRegistryAction
# ---------------------------------------------------------------------------

class TestRegistryAction:
    """RegistryAction enum — nine distinct operations."""

    def test_approve_exists(self):
        assert RegistryAction.APPROVE.value == "approve"

    def test_reject_exists(self):
        assert RegistryAction.REJECT.value == "reject"

    def test_suspend_exists(self):
        assert RegistryAction.SUSPEND.value == "suspend"

    def test_reinstate_exists(self):
        assert RegistryAction.REINSTATE.value == "reinstate"

    def test_revoke_exists(self):
        assert RegistryAction.REVOKE.value == "revoke"

    def test_configure_policy_exists(self):
        assert RegistryAction.CONFIGURE_POLICY.value == "configure_policy"

    def test_set_rate_limit_exists(self):
        assert RegistryAction.SET_RATE_LIMIT.value == "set_rate_limit"

    def test_manage_allowlist_exists(self):
        assert RegistryAction.MANAGE_ALLOWLIST.value == "manage_allowlist"

    def test_manage_denylist_exists(self):
        assert RegistryAction.MANAGE_DENYLIST.value == "manage_denylist"

    def test_action_count_is_nine(self):
        assert len(RegistryAction) == 9


# ---------------------------------------------------------------------------
# TestScopedPermission
# ---------------------------------------------------------------------------

class TestScopedPermission:
    """ScopedPermission construction and matches() logic."""

    def test_unrestricted_permission_stores_none_scopes(self):
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.action is RegistryAction.APPROVE
        assert perm.tier_scope is None
        assert perm.vm_scope is None

    def test_scoped_permission_converts_set_to_frozenset(self):
        perm = ScopedPermission(
            action=RegistryAction.SUSPEND,
            tier_scope={IdentityTier.MLDSA, IdentityTier.BLS},
            vm_scope={1, 2, 3},
        )
        assert isinstance(perm.tier_scope, frozenset)
        assert isinstance(perm.vm_scope, frozenset)
        assert perm.tier_scope == frozenset({IdentityTier.MLDSA, IdentityTier.BLS})
        assert perm.vm_scope == frozenset({1, 2, 3})

    def test_matches_unrestricted_no_context(self):
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.matches(RegistryAction.APPROVE) is True

    def test_matches_unrestricted_with_tier_and_vm(self):
        perm = ScopedPermission(action=RegistryAction.REVOKE)
        assert perm.matches(RegistryAction.REVOKE, tier=IdentityTier.COMPOSITE, vm_tag=99) is True

    def test_matches_wrong_action_returns_false(self):
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.matches(RegistryAction.REJECT) is False

    def test_matches_scoped_tier_positive(self):
        perm = ScopedPermission(
            action=RegistryAction.SUSPEND,
            tier_scope={IdentityTier.MLDSA},
        )
        assert perm.matches(RegistryAction.SUSPEND, tier=IdentityTier.MLDSA) is True

    def test_matches_scoped_tier_negative(self):
        perm = ScopedPermission(
            action=RegistryAction.SUSPEND,
            tier_scope={IdentityTier.MLDSA},
        )
        assert perm.matches(RegistryAction.SUSPEND, tier=IdentityTier.BLS) is False

    def test_matches_scoped_vm_positive(self):
        perm = ScopedPermission(
            action=RegistryAction.SET_RATE_LIMIT,
            vm_scope={10, 20},
        )
        assert perm.matches(RegistryAction.SET_RATE_LIMIT, vm_tag=10) is True

    def test_matches_scoped_vm_negative(self):
        perm = ScopedPermission(
            action=RegistryAction.SET_RATE_LIMIT,
            vm_scope={10, 20},
        )
        assert perm.matches(RegistryAction.SET_RATE_LIMIT, vm_tag=99) is False

    def test_matches_scoped_with_none_vm_tag_skips_vm_check(self):
        """Scope is set but caller passes vm_tag=None — scope check is skipped."""
        perm = ScopedPermission(
            action=RegistryAction.MANAGE_ALLOWLIST,
            vm_scope={5},
        )
        # vm_tag not provided → no vm scope check → True
        assert perm.matches(RegistryAction.MANAGE_ALLOWLIST, vm_tag=None) is True

    def test_permission_is_frozen(self):
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        with pytest.raises((AttributeError, TypeError)):
            perm.action = RegistryAction.REJECT  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestRegistryRole
# ---------------------------------------------------------------------------

class TestRegistryRole:
    """RegistryRole construction and has_permission delegation."""

    def _custom_role(self) -> RegistryRole:
        return RegistryRole(
            name="tier_vm_reviewer",
            permissions=[
                ScopedPermission(
                    action=RegistryAction.APPROVE,
                    tier_scope={IdentityTier.COMPOSITE},
                    vm_scope={7},
                ),
                ScopedPermission(action=RegistryAction.REJECT),
            ],
            is_builtin=False,
        )

    def test_permissions_stored_as_tuple(self):
        role = self._custom_role()
        assert isinstance(role.permissions, tuple)
        assert len(role.permissions) == 2

    def test_is_builtin_false_for_custom_role(self):
        role = self._custom_role()
        assert role.is_builtin is False

    def test_has_permission_positive_scoped(self):
        role = self._custom_role()
        assert role.has_permission(
            RegistryAction.APPROVE, tier=IdentityTier.COMPOSITE, vm_tag=7
        ) is True

    def test_has_permission_negative_wrong_tier(self):
        role = self._custom_role()
        assert role.has_permission(
            RegistryAction.APPROVE, tier=IdentityTier.BLS, vm_tag=7
        ) is False

    def test_has_permission_negative_wrong_vm(self):
        role = self._custom_role()
        assert role.has_permission(
            RegistryAction.APPROVE, tier=IdentityTier.COMPOSITE, vm_tag=99
        ) is False

    def test_has_permission_unrestricted_reject(self):
        role = self._custom_role()
        assert role.has_permission(RegistryAction.REJECT) is True

    def test_has_permission_action_not_granted(self):
        role = self._custom_role()
        assert role.has_permission(RegistryAction.REVOKE) is False

    def test_role_is_frozen(self):
        role = self._custom_role()
        with pytest.raises((AttributeError, TypeError)):
            role.name = "hacked"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestBuiltinRoles
# ---------------------------------------------------------------------------

class TestBuiltinRoles:
    """Built-in role factories produce correct permission sets."""

    def test_owner_is_builtin(self):
        assert builtin_owner().is_builtin is True

    def test_owner_has_all_nine_actions(self):
        owner = builtin_owner()
        for action in RegistryAction:
            assert owner.has_permission(action), f"owner missing {action}"

    def test_owner_can_configure_policy(self):
        assert builtin_owner().has_permission(RegistryAction.CONFIGURE_POLICY) is True

    def test_owner_can_manage_allowlist(self):
        assert builtin_owner().has_permission(RegistryAction.MANAGE_ALLOWLIST) is True

    def test_admin_is_builtin(self):
        assert builtin_admin().is_builtin is True

    def test_admin_can_approve(self):
        assert builtin_admin().has_permission(RegistryAction.APPROVE) is True

    def test_admin_can_suspend(self):
        assert builtin_admin().has_permission(RegistryAction.SUSPEND) is True

    def test_admin_can_revoke(self):
        assert builtin_admin().has_permission(RegistryAction.REVOKE) is True

    def test_admin_cannot_configure_policy(self):
        assert builtin_admin().has_permission(RegistryAction.CONFIGURE_POLICY) is False

    def test_admin_cannot_set_rate_limit(self):
        assert builtin_admin().has_permission(RegistryAction.SET_RATE_LIMIT) is False

    def test_admin_cannot_manage_allowlist(self):
        assert builtin_admin().has_permission(RegistryAction.MANAGE_ALLOWLIST) is False

    def test_admin_cannot_manage_denylist(self):
        assert builtin_admin().has_permission(RegistryAction.MANAGE_DENYLIST) is False

    def test_sponsor_is_builtin(self):
        assert builtin_sponsor().is_builtin is True

    def test_sponsor_can_approve(self):
        assert builtin_sponsor().has_permission(RegistryAction.APPROVE) is True

    def test_sponsor_cannot_reject(self):
        assert builtin_sponsor().has_permission(RegistryAction.REJECT) is False

    def test_sponsor_cannot_suspend(self):
        assert builtin_sponsor().has_permission(RegistryAction.SUSPEND) is False

    def test_sponsor_cannot_revoke(self):
        assert builtin_sponsor().has_permission(RegistryAction.REVOKE) is False


# ---------------------------------------------------------------------------
# TestRoleAssignment
# ---------------------------------------------------------------------------

class TestRoleAssignment:
    """RoleAssignment lifecycle and expiry logic."""

    def _make_assignment(self, expires_at=None) -> RoleAssignment:
        role = builtin_admin()
        return RoleAssignment(
            role=role,
            assignee_fp=b"\xaa" * 32,
            assigned_by=b"\xbb" * 32,
            assigned_at=1000,
            expires_at=expires_at,
        )

    def test_fields_are_accessible(self):
        ra = self._make_assignment(expires_at=2000)
        assert ra.role.name == "admin"
        assert ra.assignee_fp == b"\xaa" * 32
        assert ra.assigned_by == b"\xbb" * 32
        assert ra.assigned_at == 1000
        assert ra.expires_at == 2000

    def test_permanent_assignment_is_always_active(self):
        ra = self._make_assignment(expires_at=None)
        assert ra.is_active(0) is True
        assert ra.is_active(999_999_999) is True

    def test_expired_assignment_returns_false(self):
        ra = self._make_assignment(expires_at=500)
        assert ra.is_active(500) is False
        assert ra.is_active(1000) is False

    def test_active_before_expiry(self):
        ra = self._make_assignment(expires_at=2000)
        assert ra.is_active(1999) is True

    def test_exactly_at_expiry_epoch_is_inactive(self):
        ra = self._make_assignment(expires_at=1500)
        assert ra.is_active(1500) is False

    def test_assignment_is_frozen(self):
        ra = self._make_assignment()
        with pytest.raises((AttributeError, TypeError)):
            ra.assigned_at = 9999  # type: ignore[misc]
