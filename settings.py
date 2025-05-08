# Custom configuration settings
BASE_API_URL = "/api/v1/"
# FRONTEND_URL = "http://localhost:8081"
# Frontend URL for password reset links and redirects
FRONTEND_URL = 'https://learn.nerdslab.in'  

# Email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

# CSRF settings
CSRF_FAILURE_VIEW = 'accounts.views.csrf_failure'

# Security settings - ensure these match .env.production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY' 