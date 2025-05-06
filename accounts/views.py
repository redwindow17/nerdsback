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