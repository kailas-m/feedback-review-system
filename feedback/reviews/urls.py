from django.urls import path
from . import views

urlpatterns = [
    # auth
    path("register/", views.RegisterView.as_view()),
    path("login/", views.LoginView.as_view()),
    path("refresh/", views.RefreshView.as_view()),
<<<<<<< 

    # reviews
>>>>>>> f0ebcdb (Add moderator demotion and role-safe permission handling)
    path("submit/", views.SubmitReviewView.as_view()),
    path("update/<int:id>/", views.UpdateReviewView.as_view()),
    path("delete/<int:id>/", views.DeleteReviewView.as_view()),
    path("list/", views.ListReviewsView.as_view()),
    path("filter/", views.FilterReviewsView.as_view()),
    path("average-rating/", views.AverageRatingView.as_view()),

    path("admin-reply/<int:id>/", views.AdminReplyView.as_view()),

    path("roles/", views.ListRolesView.as_view()),
    path("roles/promote/", views.PromoteToModeratorView.as_view()),
    path("roles/modify-permission-user/", views.ModifyPermissionUserView.as_view()),
    path("roles/modify-permission-role/", views.ModifyPermissionRoleView.as_view()),
    path("roles/demote/", views.DemoteModeratorView.as_view()),
<<<<<<< HEAD
=======

    # moderator endpoints (same shape but limited by permission flag)
>>>>>>> f0ebcdb (Add moderator demotion and role-safe permission handling)
    path("moderator/modify-permission-user/", views.ModeratorModifyPermissionUserView.as_view()),
]
