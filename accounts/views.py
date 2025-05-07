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
import os
from rest_framework import serializers
from django.utils import timezone
from django.http import JsonResponse
from django.shortcuts import render
from django.middleware.csrf import get_token
import requests
import json
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated

from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer
)
from .models import UserProfile, PasswordResetToken, EmailVerificationToken

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for registration
    serializer_class = RegisterSerializer
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Origin"] = "https://learn.nerdslab.in"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Max-Age"] = "86400"
        return response

    def create(self, request, *args, **kwargs):
        # Print request data for debugging
        print("Register request data:", request.data)
        
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            
            # Send email verification instead of directly logging in user
            self.send_verification_email(user)
            
            return Response({
                "message": "Registration successful. Please check your email to verify your account.",
                "user": UserSerializer(user, context=self.get_serializer_context()).data,
            }, status=status.HTTP_201_CREATED)
        except serializers.ValidationError as e:
            # Handle validation errors with better messages (existing code)
            errors = e.detail
            
            # Handle password validation errors with more specific messages
            if 'password' in errors:
                password_errors = errors['password']
                
                # Check for common validation error patterns and provide better messages
                for i, error in enumerate(password_errors):
                    error_str = str(error)
                    
                    if "similar to" in error_str:
                        password_errors[i] = "Your password is too similar to your personal information. Please choose a more unique password."
                    elif "too common" in error_str or "commonly used password" in error_str:
                        password_errors[i] = "The password you chose is too common. Please choose a stronger password."
                    elif "entirely numeric" in error_str:
                        password_errors[i] = "Your password cannot consist of only numbers. Please include letters or special characters."
                    elif "too short" in error_str:
                        password_errors[i] = "Your password is too short. It must contain at least 8 characters."
                    elif "keyboard pattern" in error_str or "common pattern" in error_str or "predictable pattern" in error_str:
                        password_errors[i] = "Your password uses a common guessable pattern. Please use a more unique combination."
                    elif "common word" in error_str:
                        password_errors[i] = "Your password contains a common word that makes it easily guessable. Please choose a stronger password."
                    elif "l33t speak" in error_str or "leet_pattern" in error_str or "leet_word" in error_str:
                        password_errors[i] = "Your password uses common letter-to-symbol substitutions (like '@' for 'a'). Please use a more unique combination."
                    elif "alternating case" in error_str:
                        password_errors[i] = "Your password uses an alternating case pattern (like 'QwErTy'). Please use a more unique combination."
                
                errors['password'] = password_errors
            
            # Print specific validation errors for debugging
            print("Specific validation errors:", errors)
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    
    def send_verification_email(self, user):
        # Get the latest token for this user
        token = EmailVerificationToken.objects.filter(user=user).latest('created_at')
        
        # Prepare email with template
        verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
        context = {
            'verify_url': verify_url,
            'user': user,
            'expiry_hours': 48,  # Token expiry in hours
        }
        
        # Render HTML email template
        html_content = render_to_string('emails/email_verification.html', context)
        text_content = strip_tags(html_content)  # Generate plain text version
        
        # Create email
        subject = 'Verify Your NerdsLab Account'
        from_email = settings.DEFAULT_FROM_EMAIL
        to = [user.email]
        
        msg = EmailMultiAlternatives(subject, text_content, from_email, to)
        msg.attach_alternative(html_content, "text/html")
        
        # Send email
        msg.send()
        
        print(f"Verification email sent to {user.email} with token {token.token}")

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for login
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Origin"] = "https://learn.nerdslab.in"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Max-Age"] = "86400"
        return response
    
    def post(self, request):
        print("Login request headers:", request.headers)
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            
            response = Response({
                "user": UserSerializer(user).data,
                "token": token.key,
                "message": "Login successful"
            })
            return response
        else:
            return Response(
                {"non_field_errors": ["Invalid credentials"]},
                status=status.HTTP_401_UNAUTHORIZED
            )

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
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
    authentication_classes = []  # No authentication required for password reset request
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    def post(self, request):
        # Debug request information
        print("Password reset request headers:", request.headers)
        print("Password reset request path:", request.path)
        
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email)
            
            # Create token
            token = PasswordResetToken.objects.create(user=user)
            
            # Prepare email with template
            reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
            context = {
                'reset_url': reset_url,
                'user': user,
            }
            
            # Render HTML email template
            html_content = render_to_string('emails/password_reset.html', context)
            text_content = strip_tags(html_content)  # Generate plain text version
            
            # Create email
            subject = 'Reset Your NerdsLab Password'
            from_email = settings.DEFAULT_FROM_EMAIL
            to = [email]
            
            msg = EmailMultiAlternatives(subject, text_content, from_email, to)
            msg.attach_alternative(html_content, "text/html")
            
            # Send email
            msg.send()
            
            return Response({'message': 'Password reset email sent'})
        except User.DoesNotExist:
            # Don't reveal if email exists or not
            return Response({'message': 'Password reset email sent if email exists'})
        except Exception as e:
            import traceback
            print(f"Error: {str(e)}")
            print(traceback.format_exc())
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for password reset confirmation
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    def post(self, request):
        # Debug request information
        print("Password reset confirm headers:", request.headers)
        print("Password reset confirm path:", request.path)
        
        token = request.data.get('token')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not password:
            return Response(
                {'password': ['This field is required']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not password2:
            return Response(
                {'password2': ['This field is required']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if password != password2:
            return Response(
                {'password': ['Password fields didn\'t match']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            
            if not reset_token.is_valid():
                return Response(
                    {'error': 'Token is invalid or expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate password using Django's validators
            user = reset_token.user
            try:
                # Use the same validation as in the serializer
                from django.contrib.auth.password_validation import validate_password
                validate_password(password, user)
                
                # Reset password
                user.set_password(password)
                user.save()
                
                # Mark token as used
                reset_token.is_used = True
                reset_token.save()
                
                return Response({'message': 'Password reset successful'})
            except Exception as validation_error:
                # Handle password validation errors with more specific messages
                error_messages = []
                for error in validation_error:
                    error_str = str(error)
                    
                    if "similar to" in error_str:
                        error_messages.append("Your password is too similar to your personal information. Please choose a more unique password.")
                    elif "too common" in error_str or "commonly used password" in error_str:
                        error_messages.append("The password you chose is too common. Please choose a stronger password.")
                    elif "entirely numeric" in error_str:
                        error_messages.append("Your password cannot consist of only numbers. Please include letters or special characters.")
                    elif "too short" in error_str:
                        error_messages.append("Your password is too short. It must contain at least 8 characters.")
                    elif "keyboard pattern" in error_str or "common pattern" in error_str or "predictable pattern" in error_str:
                        error_messages.append("Your password uses a common guessable pattern. Please use a more unique combination.")
                    elif "common word" in error_str:
                        error_messages.append("Your password contains a common word that makes it easily guessable. Please choose a stronger password.")
                    elif "l33t speak" in error_str or "leet_pattern" in error_str or "leet_word" in error_str:
                        error_messages.append("Your password uses common letter-to-symbol substitutions (like '@' for 'a'). Please use a more unique combination.")
                    elif "alternating case" in error_str:
                        error_messages.append("Your password uses an alternating case pattern (like 'QwErTy'). Please use a more unique combination.")
                    else:
                        error_messages.append(error_str)
                
                return Response(
                    {'password': error_messages},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    def post(self, request):
        # Debug authentication info
        print("Auth header:", request.META.get('HTTP_AUTHORIZATION'))
        print("User authenticated:", request.user.is_authenticated)
        print("User:", request.user)
        
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        
        # Validate input
        if not current_password or not new_password:
            return Response(
                {'error': 'Both current and new password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify current password
        if not user.check_password(current_password):
            return Response(
                {'current_password': ['The current password is incorrect']},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate new password using Django's validators
        try:
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password, user)
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Generate new token (since password change invalidates sessions)
            token, _ = Token.objects.get_or_create(user=user)
            
            return Response({
                'message': 'Password changed successfully',
                'token': token.key
            })
        except Exception as validation_error:
            # Handle password validation errors with more specific messages
            error_messages = []
            for error in validation_error:
                error_str = str(error)
                
                if "similar to" in error_str:
                    error_messages.append("Your password is too similar to your personal information. Please choose a more unique password.")
                elif "too common" in error_str or "commonly used password" in error_str:
                    error_messages.append("The password you chose is too common. Please choose a stronger password.")
                elif "entirely numeric" in error_str:
                    error_messages.append("Your password cannot consist of only numbers. Please include letters or special characters.")
                elif "too short" in error_str:
                    error_messages.append("Your password is too short. It must contain at least 8 characters.")
                elif "keyboard pattern" in error_str or "common pattern" in error_str or "predictable pattern" in error_str:
                    error_messages.append("Your password uses a common guessable pattern. Please use a more unique combination.")
                elif "common word" in error_str:
                    error_messages.append("Your password contains a common word that makes it easily guessable. Please choose a stronger password.")
                elif "l33t speak" in error_str or "leet_pattern" in error_str or "leet_word" in error_str:
                    error_messages.append("Your password uses common letter-to-symbol substitutions (like '@' for 'a'). Please use a more unique combination.")
                elif "alternating case" in error_str:
                    error_messages.append("Your password uses an alternating case pattern (like 'QwErTy'). Please use a more unique combination.")
                else:
                    error_messages.append(error_str)
            
            return Response(
                {'new_password': error_messages},
                status=status.HTTP_400_BAD_REQUEST
            )

class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for email verification
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
    def post(self, request):
        print("Email verification request received:", request.data)
        serializer = EmailVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            print("Serializer validation failed:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        token_str = str(serializer.validated_data['token'])
        print(f"Processing verification token: {token_str}")
        
        try:
            token = EmailVerificationToken.objects.get(token=token_str)
            print(f"Found token for user: {token.user.username}, is_used: {token.is_used}, expires_at: {token.expires_at}")
            
            if not token.is_valid():
                print(f"Token is invalid: is_used={token.is_used}, expires_at={token.expires_at}, now={timezone.now()}")
                return Response(
                    {'error': 'Verification link is invalid or has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Activate the user account
            user = token.user
            print(f"User before activation: {user.username}, is_active={user.is_active}")
            user.is_active = True
            user.save()
            print(f"User after activation: {user.username}, is_active={user.is_active}")
            
            # Mark token as used
            token.is_used = True
            token.save()
            print(f"Token marked as used: {token.token}, is_used={token.is_used}")
            
            # Generate authentication token for the user
            auth_token, created = Token.objects.get_or_create(user=user)
            print(f"Generated auth token: {auth_token.key}, created={created}")
            
            return Response({
                'message': 'Email verified successfully. Your account is now active.',
                'token': auth_token.key,
                'user': UserSerializer(user).data
            })
            
        except EmailVerificationToken.DoesNotExist:
            print(f"Token not found: {token_str}")
            return Response(
                {'error': 'Invalid verification token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print(f"Verification error: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token_obj = EmailVerificationToken.objects.get(token=token)
            
            if not token_obj.is_valid():
                return Response(
                    {'is_valid': False, 'error': 'Verification link is invalid or has expired'},
                    status=status.HTTP_200_OK
                )
                
            return Response(
                {'is_valid': True},
                status=status.HTTP_200_OK
            )
            
        except EmailVerificationToken.DoesNotExist:
            return Response(
                {'is_valid': False, 'error': 'Invalid verification token'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'is_valid': False, 'error': str(e)},
                status=status.HTTP_200_OK
            )

class ResendVerificationEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []  # No authentication required for resending verification
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Allow"] = "POST,OPTIONS"
        response["Access-Control-Allow-Methods"] = "POST,OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, Authorization"
        return response
    
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
            
            # Prepare email with template
            verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
            context = {
                'verify_url': verify_url,
                'user': user,
                'expiry_hours': 48,  # Token expiry in hours
            }
            
            # Render HTML email template
            html_content = render_to_string('emails/email_verification.html', context)
            text_content = strip_tags(html_content)  # Generate plain text version
            
            # Create email
            subject = 'Verify Your NerdsLab Account'
            from_email = settings.DEFAULT_FROM_EMAIL
            to = [user.email]
            
            msg = EmailMultiAlternatives(subject, text_content, from_email, to)
            msg.attach_alternative(html_content, "text/html")
            
            # Send email
            msg.send()
            
            return Response({'message': 'Verification email sent'})
            
        except User.DoesNotExist:
            # Don't reveal if email exists for security reasons
            return Response({'message': 'If the email exists and is unverified, a verification email has been sent'})
        except Exception as e:
            return Response(
                {'error': str(e)},
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

def get_csrf_token(request):
    """View to get a new CSRF token"""
    token = get_token(request)
    return JsonResponse({
        'csrfToken': token,
        'message': 'New CSRF token generated'
    })

@permission_classes([IsAuthenticated])
class LabsTokenBridgeView(APIView):
    """
    View for bridging authentication between Server 1 and Server 2.
    This endpoint allows the frontend to get a token for Server 2
    after authenticating with Server 1.
    """
    def get(self, request):
        # Get the current user
        user = request.user
        
        # Get the service token for Server 2
        service_token = os.environ.get('LABS_SERVICE_TOKEN', settings.LABS_SERVICE_TOKEN)
        
        # Get the Server 2 API URL
        labs_api_url = os.environ.get('LABS_API_URL', settings.LABS_API_URL)
        
        # Make request to Server 2 to get a JWT token
        try:
            response = requests.post(
                f"{labs_api_url}/auth/service-token/",
                json={
                    'service_token': service_token,
                    'user_id': user.id,
                    'username': user.username,
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Check if the request was successful
            if response.status_code == 200:
                # Return the tokens to the frontend
                return Response(response.json())
            else:
                # Return the error from Server 2
                return Response({
                    'error': 'Failed to get token from Server 2',
                    'details': response.json()
                }, status=response.status_code)
        except Exception as e:
            # Return a generic error
            return Response({
                'error': f'Failed to connect to Server 2: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)