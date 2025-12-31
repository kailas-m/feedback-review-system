# reviews/utils.py
from .models import Permission, UserPermission

def user_has_perm(user, codename, obj=None):
    """
    Unified permission check:
    Priority:
    1. Superuser
    2. Direct user permission
    3. Role-based permission
    4. Ownership-based permission (explicit *_own_* pattern)
    """

    # 0️⃣ authentication check
    if not user or not getattr(user, "is_authenticated", False):
        return False

    # 1️⃣ superuser override
    if getattr(user, "is_superuser", False):
        return True

    # 2️⃣ direct user permission
    if UserPermission.objects.filter(
        user=user,
        permission__codename=codename
    ).exists():
        return True

    # 3️⃣ role-based permission
    if Permission.objects.filter(
        roles__users=user,
        codename=codename
    ).exists():
        return True

    # 4️⃣ ownership-based permission
    # example: update_any_review → update_own_review
    if obj is not None and hasattr(obj, "user") and obj.user == user:
        own_codename = codename.replace("_any_", "_own_")
        if Permission.objects.filter(
            codename=own_codename,
            roles__users=user
        ).exists() or UserPermission.objects.filter(
            user=user,
            permission__codename=own_codename
        ).exists():
            return True

    return False
