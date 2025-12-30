# reviews/management/commands/create_default_roles.py
from django.core.management.base import BaseCommand
from reviews.models import Permission, Role

DEFAULT_PERMISSIONS = [
    ("Submit review", "submit_review", False),
    ("Update any review", "update_any_review", False),
    ("Delete any review", "delete_any_review", False),
    ("Update own review", "update_own_review", True),   # allowed_for_moderator not relevant here
    ("Delete own review", "delete_own_review", True),
    ("Reply any review", "reply_any_review", False),
    ("View average rating", "view_average_rating", False),
    ("Manage roles/permissions", "manage_permissions", False),
    ("Manage roles (promote moderator)", "manage_roles", False),
]

DEFAULT_ROLES = {
    "admin": [p[1] for p in DEFAULT_PERMISSIONS],  # all perms
    "moderator": ["submit_review", "update_own_review", "delete_own_review", "view_average_rating"],
    "user": ["submit_review", "update_own_review", "delete_own_review"],
}

class Command(BaseCommand):
    help = "Create default roles and permissions (admin, moderator, user)"

    def handle(self, *args, **options):
        for name, codename, allowed_for_moderator in DEFAULT_PERMISSIONS:
            Permission.objects.get_or_create(codename=codename, defaults={"name": name, "allowed_for_moderator": allowed_for_moderator})

        for role_name, perm_codenames in DEFAULT_ROLES.items():
            role, _ = Role.objects.get_or_create(name=role_name)
            perms = Permission.objects.filter(codename__in=perm_codenames)
            role.permissions.set(perms)
        self.stdout.write(self.style.SUCCESS("Default roles and permissions created/updated."))
