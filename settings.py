import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'

# Production settings
ALLOWED_HOSTS = [
    'nerd-api.nerdslab.in',
    'learn.nerdslab.in',
    'labs.nerdslab.in'
]

# CORS settings - allow only the following origins
CORS_ALLOWED_ORIGINS = [
    'https://learn.nerdslab.in',
    'https://labs.nerdslab.in',
    'https://nerd-api.nerdslab.in'
]

CORS_ALLOW_CREDENTIALS = True

# Custom configuration settings
BASE_API_URL = "/api/v1/"
# FRONTEND_URL = "http://localhost:8081"
# Frontend URL for password reset links
FRONTEND_URL = 'https://learn.nerdslab.in'  

# Email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

# CSRF settings
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure' 