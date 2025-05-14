from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from .viewsets import (
    RegisterViewSet,
    LoginViewSet,
    LogoutViewSet,
    PasswordResetRequestViewSet,
    PasswordResetConfirmViewSet,
    UserViewSet,
    ProfileViewSet,
    EmailVerificationViewSet,
    GoogleAuthViewSet,
    PhoneVerificationViewSet  # Add this import
)

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'register', RegisterViewSet, basename='register')
router.register(r'login', LoginViewSet, basename='login')
router.register(r'logout', LogoutViewSet, basename='logout')
router.register(r'password-reset-request', PasswordResetRequestViewSet, basename='password-reset-request')
router.register(r'password-reset-confirm', PasswordResetConfirmViewSet, basename='password-reset-confirm')
router.register(r'users', UserViewSet, basename='user')
router.register(r'profile', ProfileViewSet, basename='profile')
router.register(r'verify-email', EmailVerificationViewSet, basename='verify-email')
router.register(r'verify-phone', PhoneVerificationViewSet, basename='verify-phone')  # Add this line
router.register(r'auth/google', GoogleAuthViewSet, basename='google-auth')

# The API URLs are now determined automatically by the router
urlpatterns = [
    path('', include(router.urls)),
    # Add the token refresh endpoint
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('reset-password/', views.password_reset_form, name='password_reset_form'),
]