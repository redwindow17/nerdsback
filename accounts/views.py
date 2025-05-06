from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import os
import logging
from rest_framework import serializers
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render

from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer
)
from .models import UserProfile, PasswordResetToken, EmailVerificationToken
from nerdslab.email_config import send_verification_email, send_password_reset_email

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    serializer_class = RegisterSerializer
    
    def options(self, request, *args, **kwargs):
        return Response(status=status.HTTP_200_OK)
    
    def create(self, request, *args, **kwargs):
        # Log registration attempt
        logger = logging.getLogger('accounts')
        logger.info(f"Register request data: {request.data}")
        
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            
            # Use transaction.atomic to ensure data consistency
            from django.db import transaction
            try:
                with transaction.atomic():
                    user = serializer.save()
                    
                    # Create verification token inside transaction
                    token = EmailVerificationToken.objects.create(user=user)
                    
                    # Send verification email
                    try:
                        send_verification_email(user, token)
                    except Exception as e:
                        logger.error(f"Failed to send verification email: {str(e)}")
                        # Don't fail registration if email fails
                        pass
                
                return Response({
                    "message": "Registration successful. Please check your email to verify your account.",
                    "user": UserSerializer(user, context=self.get_serializer_context()).data,
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error(f"Transaction failed: {str(e)}")
                return Response({
                    "error": "Registration failed. Please try again."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except serializers.ValidationError as e:
            errors = e.detail
            if 'password' in errors:
                errors['password'] = self.get_friendly_password_errors(errors['password'])
            logger.warning(f"Validation errors: {errors}")
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error during registration: {str(e)}")
            return Response({
                "error": "An unexpected error occurred. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_friendly_password_errors(self, password_errors):
        friendly_messages = []
        for error in password_errors:
            error_str = str(error)
            if "similar to" in error_str:
                friendly_messages.append("Your password is too similar to your personal information")
            elif "too common" in error_str:
                friendly_messages.append("Please choose a stronger password")
            elif "entirely numeric" in error_str:
                friendly_messages.append("Include letters or special characters")
            elif "too short" in error_str:
                friendly_messages.append("Password must be at least 8 characters")
            else:
                friendly_messages.append(error_str)
        return friendly_messages

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    serializer_class = LoginSerializer
    
    def options(self, request, *args, **kwargs):
        return Response(status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        # Log login attempt headers for debugging
        logger = logging.getLogger('accounts')
        logger.info(f"Login request headers: {dict(request.headers)}")
        
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)
            
            if user:
                if not user.is_active:
                    return Response({
                        "error": "Account is not active. Please verify your email."
                    }, status=status.HTTP_403_FORBIDDEN)
                
                login(request, user)
                token, created = Token.objects.get_or_create(user=user)
                return Response({
                    "token": token.key,
                    "user": UserSerializer(user).data
                })
            return Response({
                "error": "Invalid credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        # Delete token to logout
        try:
            request.user.auth_token.delete()
        except Exception:
            pass
        
        # Logout from session
        logout(request)
        
        return Response(
            {"message": "Successfully logged out"}, 
            status=status.HTTP_200_OK
        )

class UserDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user

class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def post(self, request):
        logger = logging.getLogger('accounts')
        logger.info(f"Password reset request headers: {request.headers}")
        
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email)
            token = PasswordResetToken.objects.create(user=user)
            
            try:
                send_password_reset_email(user, token)
                return Response({'message': 'Password reset email sent'})
            except Exception as e:
                logger.error(f"Failed to send password reset email: {str(e)}")
                return Response(
                    {'error': 'Failed to send password reset email. Please try again later.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
                
        except User.DoesNotExist:
            # Don't reveal if email exists
            return Response({'message': 'If the email exists, a password reset link has been sent'})
        except Exception as e:
            logger.error(f"Unexpected error in password reset: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        token = serializer.validated_data['token']
        password = serializer.validated_data['password']
        
        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            if not reset_token.is_valid():
                return Response(
                    {'error': 'Token is invalid or expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = reset_token.user
            user.set_password(password)
            user.save()
            
            # Mark token as used
            reset_token.is_used = True
            reset_token.save()
            
            return Response({'message': 'Password reset successful'})
            
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger = logging.getLogger('accounts')
            logger.error(f"Error in password reset confirmation: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        token_str = str(serializer.validated_data['token'])
        
        try:
            token = EmailVerificationToken.objects.select_related('user').get(token=token_str)
            
            if not token.is_valid():
                return Response(
                    {'error': 'Verification link is invalid or has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            with transaction.atomic():
                user = token.user
                user.is_active = True
                user.save()
                
                token.is_used = True
                token.save()
                
                auth_token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                'message': 'Email verified successfully. Your account is now active.',
                'token': auth_token.key,
                'user': UserSerializer(user).data
            })
            
        except EmailVerificationToken.DoesNotExist:
            return Response(
                {'error': 'Invalid verification token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger = logging.getLogger('accounts')
            logger.error(f"Error in email verification: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ResendVerificationEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email, is_active=False)
            
            # Create a new verification token
            old_tokens = EmailVerificationToken.objects.filter(user=user, is_used=False)
            for token in old_tokens:
                token.is_used = True
                token.save()
                
            token = EmailVerificationToken.objects.create(user=user)
            
            try:
                send_verification_email(user, token)
                return Response({'message': 'Verification email sent'})
            except Exception as e:
                logger = logging.getLogger('accounts')
                logger.error(f"Failed to send verification email: {str(e)}")
                return Response(
                    {'error': 'Failed to send verification email. Please try again later.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
        except User.DoesNotExist:
            # Don't reveal if email exists
            return Response({'message': 'If the email exists and is unverified, a verification email has been sent'})
        except Exception as e:
            logger = logging.getLogger('accounts')
            logger.error(f"Unexpected error in resend verification: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

def csrf_failure(request, reason=""):
    """View for CSRF failure errors"""
    if request.headers.get('content-type') == 'application/json':
        return JsonResponse({
            'error': 'CSRF validation failed. Refresh the page and try again.',
            'details': reason
        }, status=403)
    
    # For HTML requests
    return render(request, 'accounts/csrf_error.html', {'reason': reason}, status=403)

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        
        if not old_password or not new_password:
            return Response({
                'error': 'Both old_password and new_password are required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Verify old password
        if not request.user.check_password(old_password):
            return Response({
                'error': 'Current password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Validate new password
        if len(new_password) < 8:
            return Response({
                'error': 'New password must be at least 8 characters long'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Check if new password is too similar to user info
        if new_password.lower() in [request.user.username.lower(), request.user.email.lower()]:
            return Response({
                'error': 'Password cannot be too similar to your username or email'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Check if new password is too common
        common_passwords = ['password123', '12345678', 'qwerty123']
        if new_password.lower() in common_passwords:
            return Response({
                'error': 'Please choose a stronger password'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Update password
        try:
            request.user.set_password(new_password)
            request.user.save()
            
            # Delete existing tokens to force re-login
            Token.objects.filter(user=request.user).delete()
            
            return Response({
                'message': 'Password changed successfully. Please login again.'
            })
            
        except Exception as e:
            logger = logging.getLogger('accounts')
            logger.error(f"Error changing password: {str(e)}")
            return Response({
                'error': 'Failed to change password. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)