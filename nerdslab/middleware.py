from django.utils.deprecation import MiddlewareMixin

class ApiCsrfExemptMiddleware(MiddlewareMixin):
    """
    Middleware to exempt API endpoints from CSRF protection
    """
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Exempt API requests from CSRF
        if request.path.startswith('/api/') or request.path.startswith('/accounts/'):
            setattr(request, '_dont_enforce_csrf_checks', True)
        return None

class CorsHeadersMiddleware:
    """
    Middleware to add CORS headers to all responses to ensure proper cross-origin access
    DISABLED: We now handle CORS headers at the Nginx level to avoid duplication
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # CORS headers are now handled by Nginx
        # Leaving this middleware in place but disabling its functionality
        # to avoid duplicate headers
        
        # # Handle preflight OPTIONS requests specifically
        # if request.method == 'OPTIONS':
        #     # Add CORS headers for preflight requests
        #     response["Access-Control-Allow-Origin"] = "https://learn.nerdslab.in"
        #     response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        #     response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        #     response["Access-Control-Allow-Credentials"] = "true"
        #     response["Access-Control-Max-Age"] = "86400"  # 24 hours
        
        return response 