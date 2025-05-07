from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from . import views
from . import views_labs
from .views import (
    RegisterView, 
    LoginView, 
    LogoutView, 
    UserDetailView, 
    PasswordResetRequestView, 
    PasswordResetConfirmView,
    ChangePasswordView,
    EmailVerificationView,
    ResendVerificationEmailView,
    LabsTokenBridgeView
)

urlpatterns = [
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('me/', UserDetailView.as_view(), name='user-detail'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Password reset endpoints
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # CSRF token endpoint
    path('csrf/', views.get_csrf_token, name='get-csrf-token'),
    
    # Change password endpoint
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    
    # Email verification endpoints
    path('verify-email/', EmailVerificationView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    
    # Lab management endpoints
    path('labs/', views_labs.LabListView.as_view(), name='lab-list'),
    path('labs/create/', views_labs.LabCreateView.as_view(), name='lab-create'),
    path('labs/<str:lab_id>/', views_labs.LabDetailView.as_view(), name='lab-detail'),
    path('labs/templates/', views_labs.LabTemplateView.as_view(), name='lab-templates'),
    path('labs/<str:lab_id>/stop/', views_labs.LabStopView.as_view(), name='lab-stop'),
    path('labs/<str:lab_id>/restart/', views_labs.LabRestartView.as_view(), name='lab-restart'),
    
    # Labs API token bridge
    path('labs-token/', LabsTokenBridgeView.as_view(), name='labs-token'),
]