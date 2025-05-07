import os
from pathlib import Path
import dotenv
from django.core.management.utils import get_random_secret_key

# Load environment variables from .env file if it exists
dotenv.load_dotenv(os.path.join(Path(__file__).resolve().parent.parent, '.env'))

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# Get SECRET_KEY from environment variable or use the one defined here as fallback
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-123456789abcdefghijklmnopqrstuvwxyz')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

# Additional allowed hosts for Cloudflare
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'nerd-api.nerdslab.in',
]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party apps
    'rest_framework',
    'rest_framework.authtoken',  # Required for token authentication
    'corsheaders',  # Enable CORS
    
    # Local apps
    'accounts',
]

MIDDLEWARE = [
    'nerdslab.cors_middleware.CorsMiddleware',  # Must be first for CORS handling
    'corsheaders.middleware.CorsMiddleware',    # Django CORS headers middleware
    'django.middleware.common.CommonMiddleware',  # Move this right after CorsMiddleware
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'accounts.middleware.PasswordRehashMiddleware',
    'nerdslab.cors_middleware.SecurityHeadersMiddleware',  # Move to the end to apply security headers
]

ROOT_URLCONF = 'nerdslab.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'accounts' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nerdslab.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password hashing configuration
PASSWORD_HASHERS = [
    # Argon2 is the recommended password hasher - strongest algorithm
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    # PBKDF2 with SHA-512 is a strong alternative
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    # BCrypt is another strong option
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    # Default hashers for backwards compatibility
    'django.contrib.auth.hashers.ScryptPasswordHasher',
]

# Configure PBKDF2 with more iterations for enhanced security
PASSWORD_HASHERS_CONFIG = {
    'PBKDF2PasswordHasher': {
        'ITERATIONS': 320000,  # Higher iteration count for stronger security
        'DIGEST': 'sha512',    # Using SHA-512 for stronger hashing
    },
    'Argon2PasswordHasher': {
        'TIME_COST': 4,        # Increased time cost for better security
        'MEMORY_COST': 65536,  # 64MB in KiB
        'PARALLELISM': 2,      # Number of parallel threads
    },
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Require longer passwords for better security
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'accounts.validators.PatternPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

# Security and CORS Settings
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = not DEBUG  # Only redirect in production
SESSION_COOKIE_SECURE = not DEBUG  # Only use secure cookies in production
CSRF_COOKIE_SECURE = not DEBUG  # Only use secure CSRF cookies in production
CSRF_USE_SESSIONS = False  # Store CSRF token in cookie instead of session
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_COOKIE_SAMESITE = 'Lax'  # Allow cross-site requests while maintaining security

# Ensure both CORS_ORIGIN_ALLOW_ALL and explicit origins are set
CORS_ALLOW_ALL_ORIGINS = True  # Allow all origins temporarily to debug issues
CORS_ALLOWED_ORIGINS = [
    'https://learn.nerdslab.in',
    'https://labs.nerdslab.in',
    'http://learn.nerdslab.in',  # Also include HTTP version
    'http://labs.nerdslab.in',   # Also include HTTP version
]

if DEBUG:
    # Add local development origins
    CORS_ALLOWED_ORIGINS.extend([
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:8000',
        'http://127.0.0.1:8000',
    ])

# Add the same origins to trusted CSRF origins
CSRF_TRUSTED_ORIGINS = CORS_ALLOWED_ORIGINS.copy()

CORS_ALLOW_CREDENTIALS = True
CORS_PREFLIGHT_MAX_AGE = 86400  # 24 hours

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'cache-control',
]

# Ensure CSRF token is included in the response headers
CORS_EXPOSE_HEADERS = [
    'x-csrftoken',
    'content-type',
    'content-length',
]

# Extended security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Frontend URL for password reset links
FRONTEND_URL = 'https://learn.nerdslab.in'

# Email settings for Zoho Mail
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.zoho.in')  # Zoho India SMTP server
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', 'no-reply@nerdslab.in')
# Store this in environment variable in production
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', 'dtaK8xf&')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# Lab Service (Server 2) Configuration
LAB_SERVICE_URL = os.environ.get('LAB_SERVICE_URL', 'http://localhost')  # URL to the lab service
# Store this in environment variable in production
LAB_SERVICE_TOKEN = os.environ.get('LAB_SERVICE_TOKEN', 'your-api-token-here')  # API token for authentication

# Add this at the end
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# Security Settings
SESSION_COOKIE_SECURE = False  # Only send over HTTPS
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # Changed from Strict to Lax for better compatibility
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'  # Changed from Strict to Lax for better compatibility
CSRF_USE_SESSIONS = True
CSRF_FAILURE_VIEW = 'accounts.views.csrf_failure'

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 3600  # 1 hour in seconds

# For development, you may need to disable some settings
if DEBUG:
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

# Ensure your API endpoints are correctly defined
# Check your views and URLs to ensure they are set up correctly

# Add to settings.py
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Add logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'nerdslab': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Add middleware for handling OPTIONS requests
def handle_options_request(request, response):
    if request.method == 'OPTIONS':
        response['Access-Control-Allow-Methods'] = 'DELETE, GET, OPTIONS, PATCH, POST, PUT'
        response['Access-Control-Allow-Headers'] = 'accept, accept-encoding, authorization, content-type, dnt, origin, user-agent, x-csrftoken, x-requested-with'
        response['Access-Control-Max-Age'] = '86400'
        response['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Content-Type'] = 'text/plain; charset=UTF-8'
        response['Content-Length'] = '0'
        return response