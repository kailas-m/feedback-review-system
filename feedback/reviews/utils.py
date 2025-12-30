# reviews/utils.py
from .models import Permission, Role, UserPermission

def user_has_perm(user, codename, obj=None):
    """
    Returns True if user has `codename` permission:
      - superusers always True
      - direct user permission (UserPermission) True
      - role-based permission True
      - owner implicit True if obj.user == user (you requested owner is implicitly allowed)
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False

    if getattr(user, "is_superuser", False):
        return True

    # direct user permissions
    if UserPermission.objects.filter(user=user, permission__codename=codename).exists():
        return True

    # role-based permissions
    if Permission.objects.filter(roles__users=user, codename=codename).exists():
        return True

    # implicit owner allowed (you requested implicit owner permission)
    if obj is not None and hasattr(obj, "user"):
        try:
            if obj.user == user:
                return True
        except Exception:
            pass

    return False

