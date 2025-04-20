from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile, PasswordResetToken, EmailVerificationToken
from rest_framework.validators import UniqueValidator
import bleach

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['bio', 'profile_image']

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=False)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'profile']
        read_only_fields = ['id', 'is_active']

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    
    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name')
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
            
        # Validate email format
        email = attrs.get('email', '')
        if not email or '@' not in email:
            raise serializers.ValidationError({"email": "Invalid email format."})
            
        # Sanitize inputs
        attrs['first_name'] = bleach.clean(attrs['first_name'])
        attrs['last_name'] = bleach.clean(attrs['last_name'])
        attrs['username'] = bleach.clean(attrs['username'])
            
        return attrs
        
    def create(self, validated_data):
        # Remove password2 from the data
        validated_data.pop('password2')
        
        # Create user with is_active set to False until email verification
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=False  # User isn't active until email is verified
        )
        
        user.set_password(validated_data['password'])
        user.save()
        
        # Create profile for the user
        profile = UserProfile.objects.create(user=user)
        
        # Create an email verification token
        token = EmailVerificationToken.objects.create(user=user)
        
        return user
        
# Add a new serializer for email verification
class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)
    
    def validate_token(self, value):
        try:
            token = EmailVerificationToken.objects.get(token=value)
            if not token.is_valid():
                raise serializers.ValidationError("Token is invalid or expired.")
            return value
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Token does not exist.")

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, attrs):
        return attrs

# Password reset serializers
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user with this email address exists.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs 