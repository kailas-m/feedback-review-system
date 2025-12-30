from django.contrib import admin
from .models import Review, Permission, Role, UserPermission

@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "rating", "created_at")
    search_fields = ("user__username", "comment")

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("codename", "name", "allowed_for_moderator")
    search_fields = ("codename", "name")

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    filter_horizontal = ("permissions", "users")

@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ("user", "permission")
    search_fields = ("user__username", "permission__codename")
