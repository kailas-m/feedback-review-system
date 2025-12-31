import json
import jwt
from datetime import datetime, timedelta

from django.conf import settings
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Avg
from django.shortcuts import get_object_or_404

from .models import Review, Role, Permission, UserPermission
from .utils import user_has_perm

# Token config
ACCESS_LIFETIME_MINUTES = 45
REFRESH_LIFETIME_DAYS = 7
JWT_ALGORITHM = "HS256"
JWT_SECRET = getattr(settings, "JWT_SECRET", None) or getattr(settings, "DJANGO_SECRET_KEY", None)

# ---------------- helpers -----------------

def _parse_json(request):
    try:
        return json.loads(request.body or b"{}")
    except Exception:
        return {}

def _make_token(user, token_type, exp_delta):
    payload = {
        "user_id": user.id,
        "type": token_type,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + exp_delta,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def _decode_token(token, expected_type):
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError
    return payload

def get_user_from_jwt(request):
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    try:
        prefix, token = auth.split()
        if prefix != "Bearer":
            return None
        payload = _decode_token(token, "access")
        return User.objects.get(id=payload["user_id"])
    except Exception:
        return None

# --------------- AUTH -------------------

@method_decorator(csrf_exempt, name="dispatch")
class RegisterView(View):

    def post(self, request):
        data = _parse_json(request)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return JsonResponse({"error": "username and password required"}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({"error": "username already exists"}, status=400)

        user = User.objects.create_user(username=username, password=password)


        try:
            user_role = Role.objects.get(name="user")
            user_role.users.add(user)
            for perm in user_role.permissions.all():
                UserPermission.objects.get_or_create(user=user, permission=perm)
        except Role.DoesNotExist:
            pass

        return JsonResponse({"message": "User registered", "user_id": user.id})

@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    def post(self, request):
        data = _parse_json(request)
        user = authenticate(username=data.get("username"), password=data.get("password"))
        if not user:
            return JsonResponse({"error": "Invalid credentials"}, status=400)
        access = _make_token(user, "access", timedelta(minutes=ACCESS_LIFETIME_MINUTES))
        refresh = _make_token(user, "refresh", timedelta(days=REFRESH_LIFETIME_DAYS))

        roles = list(user.roles.values_list("id", "name"))
        return JsonResponse({"access": access, "refresh": refresh, "roles": roles, "is_staff": user.is_staff})

@method_decorator(csrf_exempt, name="dispatch")
class RefreshView(View):
    def post(self, request):
        data = _parse_json(request)
        token = data.get("refresh")
        if not token:
            return JsonResponse({"error": "refresh token required"}, status=400)
        try:
            payload = _decode_token(token, "refresh")
            user = User.objects.get(id=payload["user_id"])
            access = _make_token(user, "access", timedelta(minutes=ACCESS_LIFETIME_MINUTES))
            return JsonResponse({"access": access})
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "refresh token expired"}, status=401)
        except Exception:
            return JsonResponse({"error": "invalid refresh token"}, status=401)

# --------------- REVIEWS -----------------

@method_decorator(csrf_exempt, name="dispatch")
class SubmitReviewView(View):
    def post(self, request):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)
        if not user_has_perm(user, "submit_review"):
            return JsonResponse({"error": "Permission denied: submit_review"}, status=403)
        data = _parse_json(request)
        try:
            rating = int(data.get("rating", 0))
        except Exception:
            return JsonResponse({"error": "rating must be integer"}, status=400)
        Review.objects.create(user=user, comment=data.get("comment", ""), rating=rating)
        return JsonResponse({"message": "Review submitted"})

@method_decorator(csrf_exempt, name="dispatch")
class UpdateReviewView(View):
    def put(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)
        review = get_object_or_404(Review, id=id)
        # author or permission update_any_review
        if review.user != user and not user_has_perm(user, "update_any_review"):
            return JsonResponse({"error": "You are not allowed to update this review"}, status=403)
        data = _parse_json(request)
        review.comment = data.get("comment", review.comment)
        if "rating" in data:
            try:
                review.rating = int(data["rating"])
            except Exception:
                return JsonResponse({"error": "rating must be integer"}, status=400)
        review.save()
        return JsonResponse({"message": "Review updated"})

@method_decorator(csrf_exempt, name="dispatch")
class DeleteReviewView(View):
    def delete(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)
        review = get_object_or_404(Review, id=id)
        if review.user != user and not user_has_perm(user, "delete_any_review"):
            return JsonResponse({"error": "You are not allowed to delete this review"}, status=403)
        review.delete()
        return JsonResponse({"message": "Review deleted"})

class ListReviewsView(View):
    def get(self, request):
        return JsonResponse(list(Review.objects.all().values()), safe=False)

class FilterReviewsView(View):
    def get(self, request):
        rating = request.GET.get("rating")
        qs = Review.objects.filter(rating=rating) if rating else Review.objects.all()
        return JsonResponse(list(qs.values()), safe=False)

@method_decorator(csrf_exempt, name="dispatch")
class AdminReplyView(View):
    def post(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)

        if not (user.is_superuser or user_has_perm(user, "reply_any_review")):
            return JsonResponse({"error": "Admin only"}, status=403)
        review = get_object_or_404(Review, id=id)
        review.admin_reply = _parse_json(request).get("reply", "")
        review.save()
        return JsonResponse({"message": "Admin reply added"})

class AverageRatingView(View):
    def get(self, request):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)
        if not user_has_perm(user, "view_average_rating"):
            return JsonResponse({"error": "You are not allowed to view average rating"}, status=403)
        avg = Review.objects.aggregate(avg=Avg("rating"))["avg"]
        return JsonResponse({"average": float(avg) if avg is not None else None})

# ------------- Role & Permission Management --------------

@method_decorator(csrf_exempt, name="dispatch")
class PromoteToModeratorView(View):

    def post(self, request):
        requester = get_user_from_jwt(request)
        if not requester or not (requester.is_superuser or user_has_perm(requester, "manage_roles")):
            return JsonResponse({"error": "Forbidden"}, status=403)

        data = _parse_json(request)
        uid = data.get("user_id")
        username = data.get("username")
        if not uid or not username:
            return JsonResponse({"error": "user_id and username required"}, status=400)

        # validate
        target = get_object_or_404(User, id=uid, username=username)
        mod_role = get_object_or_404(Role, name="moderator")
        mod_role.users.add(target)
        
        for perm in mod_role.permissions.all():
            UserPermission.objects.get_or_create(user=target, permission=perm)

        return JsonResponse({"message": "User promoted to moderator", "user_id": target.id, "role_id": mod_role.id})

@method_decorator(csrf_exempt, name="dispatch")
class ModifyPermissionUserView(View):

    def post(self, request):
        requester = get_user_from_jwt(request)
        if not requester or not (requester.is_superuser or user_has_perm(requester, "manage_permissions")):
            return JsonResponse({"error": "Forbidden"}, status=403)

        data = _parse_json(request)
        uid = data.get("user_id")
        perm_code = data.get("permission")
        action = data.get("action")

        if not uid or not perm_code or action not in ("add", "remove"):
            return JsonResponse({"error": "user_id, permission and action(add|remove) required"}, status=400)

        target = get_object_or_404(User, id=uid)
        perm = get_object_or_404(Permission, codename=perm_code)

        if action == "add":
            UserPermission.objects.get_or_create(user=target, permission=perm)
            return JsonResponse({"message": "Permission assigned to user", "user_id": target.id, "permission": perm.codename})
        else:
            UserPermission.objects.filter(user=target, permission=perm).delete()
            return JsonResponse({"message": "Permission revoked from user", "user_id": target.id, "permission": perm.codename})


@method_decorator(csrf_exempt, name="dispatch")
class ModifyPermissionRoleView(View):

    def post(self, request):
        requester = get_user_from_jwt(request)
        if not requester or not (requester.is_superuser or user_has_perm(requester, "manage_permissions")):
            return JsonResponse({"error": "Forbidden"}, status=403)

        data = _parse_json(request)
        role_id = data.get("role_id")
        perm_code = data.get("permission")
        action = data.get("action")

        if not role_id or not perm_code or action not in ("add", "remove"):
            return JsonResponse({"error": "role_id, permission and action(add|remove) required"}, status=400)

        role = get_object_or_404(Role, id=role_id)
        perm = get_object_or_404(Permission, codename=perm_code)

        if action == "add":
            role.permissions.add(perm)

            for u in role.users.all():
                UserPermission.objects.get_or_create(user=u, permission=perm)
            return JsonResponse({"message": "Permission added to role and propagated", "role_id": role.id, "permission": perm.codename})
        else:
            role.permissions.remove(perm)

            for u in role.users.all():
                UserPermission.objects.filter(user=u, permission=perm).delete()
            return JsonResponse({"message": "Permission removed from role and removed from role users", "role_id": role.id, "permission": perm.codename})


@method_decorator(csrf_exempt, name="dispatch")
class ModeratorModifyPermissionUserView(View):

    def post(self, request):
        requester = get_user_from_jwt(request)
        if not requester:
            return JsonResponse({"error": "Authentication required"}, status=401)


        if not requester.roles.filter(name="moderator").exists():
            return JsonResponse({"error": "Moderator role required"}, status=403)

        data = _parse_json(request)
        uid = data.get("user_id")
        perm_code = data.get("permission")
        action = data.get("action")

        if not uid or not perm_code or action not in ("add", "remove"):
            return JsonResponse({"error": "user_id, permission and action(add|remove) required"}, status=400)

        perm = get_object_or_404(Permission, codename=perm_code)
        if not perm.allowed_for_moderator:
            return JsonResponse({"error": "This permission cannot be granted/revoked by moderators"}, status=403)

        target = get_object_or_404(User, id=uid)

        if action == "add":
            UserPermission.objects.get_or_create(user=target, permission=perm)
            return JsonResponse({"message": "Permission granted by moderator", "user_id": target.id, "permission": perm.codename})
        else:
            UserPermission.objects.filter(user=target, permission=perm).delete()
            return JsonResponse({"message": "Permission revoked by moderator", "user_id": target.id, "permission": perm.codename})


@method_decorator(csrf_exempt, name="dispatch")
class ListRolesView(View):

    def get(self, request):
        requester = get_user_from_jwt(request)
        roles_qs = Role.objects.prefetch_related("permissions").all()
        roles_serialized = [
            {"id": r.id, "role": r.name, "permissions": list(r.permissions.values_list("codename", flat=True))}
            for r in roles_qs
        ]


        if requester and (requester.is_superuser or user_has_perm(requester, "manage_roles")):
            users = User.objects.all()
            users_list = []
            for u in users:

                # user roles (id, name)
                rlist = list(u.roles.values("id", "name"))
               
                perms = list(u.direct_permissions.select_related("permission").values_list("permission__codename", flat=True))
                users_list.append({
                    "user_id": u.id,
                    "username": u.username,
                    "roles": rlist,
                    "permissions": perms
                })
            return JsonResponse({"roles": roles_serialized, "users": users_list}, safe=False)

        # non-admin: only roles
        return JsonResponse({"roles": roles_serialized}, safe=False)

@method_decorator(csrf_exempt, name="dispatch")
class DemoteModeratorView(View):

    """
    Admin demotes a moderator back to user.
    Body: { "user_id": <id>, "username": "<username>" }
    """
    def post(self, request):
        requester = get_user_from_jwt(request)

        # Only admin allowed
        if not requester or not (requester.is_superuser or user_has_perm(requester, "manage_roles")):
            return JsonResponse({"error": "Forbidden"}, status=403)

        data = _parse_json(request)
        uid = data.get("user_id")
        username = data.get("username")

        if not uid or not username:
            return JsonResponse(
                {"error": "user_id and username required"},
                status=400
            )

        target = get_object_or_404(User, id=uid, username=username)


        if target.is_superuser:
            return JsonResponse(
                {"error": "Admin cannot be demoted"},
                status=403
            )

        moderator_role = get_object_or_404(Role, name="moderator")
        user_role = get_object_or_404(Role, name="user")


        if not moderator_role.users.filter(id=target.id).exists():
            return JsonResponse(
                {"error": "User is not a moderator"},
                status=400
            )


        # 1️⃣ Remove moderator role
        moderator_role.users.remove(target)

        # 2️⃣ Remove moderator permissions from direct permissions
        moderator_perms = moderator_role.permissions.all()
        UserPermission.objects.filter(
            user=target,
            permission__in=moderator_perms
        ).delete()


        # 3️⃣ Ensure user role exists
        user_role.users.add(target)

        # 4️⃣ Re-add user role permissions as direct permissions
        for perm in user_role.permissions.all():
            UserPermission.objects.get_or_create(
                user=target,
                permission=perm
            )

        return JsonResponse({
            "message": "Moderator demoted to user",
            "user_id": target.id,
            "roles": list(target.roles.values_list("name", flat=True))
        })
