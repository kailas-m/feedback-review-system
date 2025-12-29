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

ACCESS_LIFETIME_MINUTES = 15
REFRESH_LIFETIME_DAYS = 7
JWT_ALGORITHM = "HS256"
JWT_SECRET = settings.JWT_SECRET


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
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _make_refresh_token(user):
    now = datetime.utcnow()
    payload = {
        "user_id": user.id,
        "type": "refresh",
        "exp": now + timedelta(days=REFRESH_LIFETIME_DAYS),
        "iat": now,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token, expected_type):
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Invalid token type")
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


@method_decorator(csrf_exempt, name="dispatch")
class RegisterView(View):
    def post(self, request):
        data = _parse_json(request)
        if not data.get("username") or not data.get("password"):
            return JsonResponse({"error": "username and password required"}, status=400)

        if User.objects.filter(username=data["username"]).exists():
            return JsonResponse({"error": "username already exists"}, status=400)

        User.objects.create_user(
            username=data["username"],
            password=data["password"]
        )
        return JsonResponse({"message": "User registered"})


@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    def post(self, request):
        data = _parse_json(request)
        user = authenticate(
            username=data.get("username"),
            password=data.get("password")
        )
        if not user:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

        return JsonResponse({
            "access": _make_access_token(user),
            "refresh": _make_refresh_token(user),
            "is_staff": user.is_staff
        })


@method_decorator(csrf_exempt, name="dispatch")
class RefreshView(View):
    def post(self, request):
        data = _parse_json(request)
        try:
            payload = _decode_token(data.get("refresh"), "refresh")
            user = User.objects.get(id=payload["user_id"])
            return JsonResponse({"access": _make_access_token(user)})
        except Exception:
            return JsonResponse({"error": "Invalid or expired refresh token"}, status=401)


@method_decorator(csrf_exempt, name="dispatch")
class SubmitReviewView(View):
    def post(self, request):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)

        data = _parse_json(request)
        Review.objects.create(
            user=user,
            comment=data.get("comment", ""),
            rating=int(data.get("rating", 0))
        )
        return JsonResponse({"message": "Review submitted"})


@method_decorator(csrf_exempt, name="dispatch")
class UpdateReviewView(View):
    def put(self, request, id):
        # 1️⃣ Authentication check
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse(
                {"error": "Authentication required (valid access token missing)"},
                status=401
            )

        review = get_object_or_404(Review, id=id)

        if review.user_id != user.id:
            return JsonResponse(
                {"error": "You do not own this review"},
                status=403
            )

        data = _parse_json(request)
        review.comment = data.get("comment", review.comment)

        if "rating" in data:
            try:
                review.rating = int(data["rating"])
            except ValueError:
                return JsonResponse(
                    {"error": "rating must be an integer"},
                    status=400
                )

        review.save()

        return JsonResponse({"message": "Review updated successfully"})


@method_decorator(csrf_exempt, name="dispatch")
class DeleteReviewView(View):
    def delete(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)

        review = get_object_or_404(Review, id=id)

        if review.user != user:
            return JsonResponse(
                {"error": "You are not allowed to delete this review"},
                status=403
            )

        review.delete()
        return JsonResponse({"message": "Review deleted"})


class ListReviewsView(View):
    def get(self, request):
        return JsonResponse(list(Review.objects.all().values()), safe=False)


class FilterReviewsView(View):
    def get(self, request):
        rating = request.GET.get("rating")
        qs = Review.objects.filter(rating=rating).values() if rating else Review.objects.all().values()
        return JsonResponse(list(qs), safe=False)


@method_decorator(csrf_exempt, name="dispatch")
class AdminReplyView(View):
    def post(self, request, id):
        user = get_user_from_jwt(request)
        if not user:
            return JsonResponse({"error": "Authentication required"}, status=401)
        if not user.is_staff:
            return JsonResponse({"error": "Admin only"}, status=403)

        review = get_object_or_404(Review, id=id)
        review.admin_reply = _parse_json(request).get("reply", "")
        review.save()

        return JsonResponse({"message": "Admin reply added"})


class AverageRatingView(View):
    def get(self, request):
        avg = Review.objects.aggregate(avg=Avg("rating"))["avg"]
        return JsonResponse({"average": float(avg) if avg else None})
