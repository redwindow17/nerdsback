# Custom configuration settings
BASE_API_URL = "/api/v1/"
# FRONTEND_URL = "http://localhost:8081"
# Frontend URL for password reset links
FRONTEND_URL = 'https://learn.nerdslab.in'  

# Email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

# CSRF settings
CSRF_FAILURE_VIEW = 'django.views.csrf.csrf_failure' 