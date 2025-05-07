from django.http import HttpResponse
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle OPTIONS requests
        if request.method == "OPTIONS":
            response = HttpResponse()
            response.status_code = 200
            self._add_cors_headers(request, response)
            return response
        
        try:
            response = self.get_response(request)
            self._add_cors_headers(request, response)
            return response
        except Exception as e:
            # Log the error
            logger.error(f"Error in request processing: {e}")
            # Create a response for the error case
            response = HttpResponse(status=500)
            # Add CORS headers even for error responses
            self._add_cors_headers(request, response)
            # Re-raise the exception to let Django handle it
            raise
    
    def _add_cors_headers(self, request, response):
        """Helper method to add CORS headers to a response"""
        # Get the origin from the request
        origin = request.headers.get('Origin', '')
        
        # Get the allowed origins from settings
        allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
        allow_all = getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)
        
        # Check if the origin is allowed or if all origins are allowed
        if allow_all:
            response["Access-Control-Allow-Origin"] = origin or "*"
            response["Access-Control-Allow-Credentials"] = "true"
        elif origin in allowed_origins:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
        
        # For OPTIONS requests, add more headers
        if request.method == "OPTIONS":
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = (
                "Accept, Accept-Encoding, Authorization, Content-Type, "
                "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With"
            )
            response["Access-Control-Max-Age"] = "86400"

class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Update Content-Security-Policy to allow HTTP connections
        response["Content-Security-Policy"] = (
            "default-src 'self' http: https:; "
            "img-src 'self' data: http: https:; "
            "style-src 'self' 'unsafe-inline' http: https:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' http: https:; "
            "connect-src 'self' http: https:;"
        )
        
        return response 