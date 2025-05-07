from django.http import HttpResponse
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class CorsMiddleware:
    """Custom middleware for handling CORS when the Django CORS headers package isn't working properly."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Define allowed origins including the frontend domain
        self.allowed_origins = [
            'https://learn.nerdslab.in',
            'https://labs.nerdslab.in',
            'http://learn.nerdslab.in',
            'http://labs.nerdslab.in',
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://localhost:8000',
            'http://127.0.0.1:8000',
        ]
        logger.info(f"CorsMiddleware initialized with allowed origins: {self.allowed_origins}")

    def __call__(self, request):
        origin = request.headers.get('Origin')
        logger.info(f"CorsMiddleware processing request: {request.method} {request.path} | Origin: {origin}")
        
        # Add CORS headers for preflight requests
        if request.method == 'OPTIONS' and origin:
            logger.info(f"Handling OPTIONS request from origin: {origin}")
            response = self.handle_options_request(request)
            self._add_cors_headers(response, origin, self.allowed_origins)
            return response
        
        # Process the request normally
        response = self.get_response(request)
        
        # Add CORS headers to all responses
        if origin:
            logger.info(f"Adding CORS headers to response for origin: {origin}")
            self._add_cors_headers(response, origin, self.allowed_origins)
            
        return response

    def handle_options_request(self, request):
        response = HttpResponse()
        response.status_code = 200
        origin = request.headers.get('Origin', '')
        logger.info(f"Creating OPTIONS response for origin: {origin}")
        self._add_cors_headers(response, origin, self.allowed_origins)
        return response

    def _add_cors_headers(self, response, origin, allowed_origins):
        """Helper method to add CORS headers to a response"""
        # Check if the origin is allowed or if all origins are allowed
        allow_all = getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)
        
        # For production, we should always accept the actual origin that sent the request
        # This is more flexible than a static list of origins
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        
        logger.info(f"CORS headers set: Origin={origin}, AllowCredentials=true")
        
        # For OPTIONS requests, add more headers
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = (
            "Accept, Accept-Encoding, Authorization, Content-Type, "
            "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With, "
            "Cache-Control, X-Requested-With"
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