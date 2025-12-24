import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Avg
from django.shortcuts import get_object_or_404

from .models import Review, AuthToken

def _parse_json(request):
    try:
        return json.loads(request.body or b"{}")
    except Exception:
        return {}

def get_user_from_token(request):
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    try:
        prefix, token = auth_header.split()
        if prefix != "Token":
            return None

        token_obj = AuthToken.objects.get(token=token)
        return token_obj.user
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
        user = authenticate(
            username=data.get("username"),
            password=data.get("password")
        )

        if not user:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

        token_obj, _ = AuthToken.objects.get_or_create(user=user)

        return JsonResponse({
            "message": "Login successful",
            "token": token_obj.token,
            "is_staff": user.is_staff
        })


@method_decorator(csrf_exempt, name="dispatch")
class SubmitReviewView(View):
    def post(self, request):
        user = get_user_from_token(request)
        if not user:
            return JsonResponse({"error": "Token required"}, status=401)

        data = _parse_json(request)
        try:
            rating = int(data.get("rating"))
        except Exception:
            return JsonResponse({"error": "rating must be an integer"}, status=400)

        Review.objects.create(
            user=user,
            comment=data.get("comment", ""),
            rating=rating
        )
        return JsonResponse({"message": "Review submitted"})

@method_decorator(csrf_exempt, name="dispatch")
class UpdateReviewView(View):
    def put(self, request, id):
        user = get_user_from_token(request)
        if not user:
            return JsonResponse({"error": "Token required"}, status=401)

        review = get_object_or_404(Review, id=id, user=user)
        data = _parse_json(request)

        if "comment" in data:
            review.comment = data["comment"]

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
        user = get_user_from_token(request)
        if not user:
            return JsonResponse({"error": "Token required"}, status=401)

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
        user = get_user_from_token(request)

        if not user:
            return JsonResponse({"error": "Token required"}, status=401)

        if not user.is_staff:
            return JsonResponse({"error": "Admin only"}, status=403)

        data = _parse_json(request)
        review = get_object_or_404(Review, id=id)
        review.admin_reply = data.get("reply", "")
        review.save()

        return JsonResponse({"message": "Admin reply added"})

class AverageRatingView(View):
    def get(self, request):
        avg = Review.objects.aggregate(average=Avg("rating"))
        return JsonResponse({
            "average": float(avg["average"]) if avg["average"] is not None else None})
