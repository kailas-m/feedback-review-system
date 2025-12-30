def user_has_perm(user, codename, obj=None):
    if not user or not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    perms = set()
    for role in user.roles.all():
        perms.update(role.permissions.values_list("codename", flat=True))

    # Direct permission
    if codename in perms:
        return True

    # Ownership-based fallback
    if obj and hasattr(obj, "user") and obj.user == user:
        own_codename = codename.replace("_any_", "_own_")
        if own_codename in perms:
            return True

    return False
