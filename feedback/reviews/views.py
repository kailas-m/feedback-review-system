# reviews/views.py
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

from .models import Review

# Configurable token lifetimes
ACCESS_LIFETIME_MINUTES = 15
REFRESH_LIFETIME_DAYS = 7
JWT_ALGORITHM = "HS256"
JWT_SECRET = getattr(settings, "JWT_SECRET", None) or getattr(settings, "JWT_SECRET", None)


def _parse_json(request):
    try:
        return json.loads(request.body or b"{}")
    except Exception:
        return {}


def _make_access_token(user):
    now = datetime.utcnow()
    payload = {
        "user_id": user.id,
        "type": "access",
        "exp": now + timedelta(minutes=ACCESS_LIFETIME_MINUTES),
        "iat": now,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT >= 2.x returns str; for older versions may be bytes - ensure str
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _make_refresh_token(user):
    now = datetime.utcnow()
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "exp": now + timedelta(days=REFRESH_LIFETIME_DAYS),
        "iat": now,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def _decode_token(token, expected_type=None):
    """
    Decode JWT and optionally check 'type' claim ('access' or 'refresh').
    Returns payload dict on success, raises jwt exceptions on failure.
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if expected_type and payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Invalid token type")
    return payload


def get_user_from_jwt(request):
    """
    Read Authorization: Bearer <token>
    Return User instance or None.
    """
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    try:
        parts = auth.split()
        if len(parts) != 2:
            return None
        prefix, token = parts
        if prefix != "Bearer":
            return None
        payload = _decode_token(token, expected_type="access")
        user_id = payload.get("user_id")
        return User.objects.get(id=user_id)
    except Exception:
        return None


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
        User.objects.create_user(username=username, password=password)
        return JsonResponse({"message": "User registered"})


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    def post(self, request):
        data = _parse_json(request)
        user = authenticate(username=data.get("username"), password=data.get("password"))
        if not user:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

        access = _make_access_token(user)
        refresh = _make_refresh_token(user)

        return JsonResponse({
            "message": "User Logged In",
            "access": access,
            "refresh": refresh,
            "is_staff": user.is_staff
        })


@method_decorator(csrf_exempt, name="dispatch")
class RefreshView(View):
    """ Accepts { "refresh": "<token>" } and returns a new access token """
    def post(self, request):
        data = _parse_json(request)
        token = data.get("refresh")
        if not token:
            return JsonResponse({"error": "refresh token required"}, status=400)
        try:
            payload = _decode_token(token, expected_type="refresh")
            user = User.objects.get(id=payload.get("user_id"))
            new_access = _make_access_token(user)
            return JsonResponse({"access": new_access})
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "refresh token expired"}, status=401)
        except Exception:
            return JsonResponse({"error": "invalid refresh token"}, status=401)


@method_decorator(csrf_exempt, name="dispatch")
class SubmitReviewView(View):
    def post(self, request):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "JWT required"}, status=401)

        data = _parse_json(request)
        try:
            rating = int(data.get("rating", 0))
        except Exception:
            return JsonResponse({"error": "rating must be an integer"}, status=400)

        Review.objects.create(user=user, comment=data.get("comment", ""), rating=rating)
        return JsonResponse({"message": "Review submitted"})


@method_decorator(csrf_exempt, name="dispatch")
class UpdateReviewView(View):
    def put(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "JWT required"}, status=401)

        review = get_object_or_404(Review, id=id, user=user)
        data = _parse_json(request)

        if "comment" in data:
            review.comment = data["comment"]
        if "rating" in data:
            try:
                review.rating = int(data["rating"])
            except Exception:
                return JsonResponse({"error": "rating must be an integer"}, status=400)

        review.save()
        return JsonResponse({"message": "Review updated"})


@method_decorator(csrf_exempt, name="dispatch")
class DeleteReviewView(View):
    def delete(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "JWT required"}, status=401)

        review = get_object_or_404(Review, id=id, user=user)
        review.delete()
        return JsonResponse({"message": "Review deleted"})


class ListReviewsView(View):
    def get(self, request):
        qs = Review.objects.all().values()
        return JsonResponse(list(qs), safe=False)


class FilterReviewsView(View):
    def get(self, request):
        rating = request.GET.get("rating")
        if rating is None:
            qs = Review.objects.all().values()
        else:
            try:
                rating = int(rating)
                qs = Review.objects.filter(rating=rating).values()
            except Exception:
                return JsonResponse({"error": "rating must be integer"}, status=400)
        return JsonResponse(list(qs), safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class AdminReplyView(View):
    def post(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "JWT required"}, status=401)
        if not user.is_staff:
            return JsonResponse({"error": "Admin only"}, status=403)

        review = get_object_or_404(Review, id=id)
        review.admin_reply = _parse_json(request).get("reply", "")
        review.save()
        return JsonResponse({"message": "Admin reply added"})


class AverageRatingView(View):
    def get(self, request):
        avg = Review.objects.aggregate(avg=Avg("rating"))["avg"]
        return JsonResponse({"average": float(avg) if avg is not None else None})
