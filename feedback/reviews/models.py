import uuid
from django.db import models
from django.conf import settings

User = settings.AUTH_USER_MODEL

class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    rating = models.PositiveSmallIntegerField()  # 1–5
    admin_reply = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.rating}"


class Permission(models.Model):
    name = models.CharField(max_length=120)
    codename = models.CharField(max_length=120, unique=True)
    allowed_for_moderator = models.BooleanField(default=False)

    def __str__(self):
        return self.codename


class Role(models.Model):

    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField(Permission, blank=True)
    users = models.ManyToManyField(User, blank=True, related_name="roles")

    def __str__(self):
        return f"{self.id}:{self.name}"


class UserPermission(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="direct_permissions")
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "permission")

    def __str__(self):
        return f"{self.user.username} -> {self.permission.codename}"
