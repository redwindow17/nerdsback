from django.http import HttpResponse
from django.conf import settings

class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle OPTIONS requests
        if request.method == "OPTIONS":
            response = HttpResponse()
            response.status_code = 200
            
            # Get the origin from the request
            origin = request.headers.get('Origin', '')
            
            # Get the allowed origins from settings
            allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
            allow_all = getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)
            
            # Check if the origin is allowed
            if allow_all or origin in allowed_origins:
                # Add required CORS headers for preflight
                response["Access-Control-Allow-Origin"] = origin
                response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response["Access-Control-Allow-Headers"] = (
                    "Accept, Accept-Encoding, Authorization, Content-Type, "
                    "DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With"
                )
                response["Access-Control-Allow-Credentials"] = "true"
                response["Access-Control-Max-Age"] = "86400"
                
            return response
        else:
            response = self.get_response(request)

            # Get the origin from the request
            origin = request.headers.get('Origin', '')
            
            # Get the allowed origins from settings
            allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
            allow_all = getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)
            
            # Check if the origin is allowed
            if allow_all or origin in allowed_origins:
                # Add required CORS headers for actual response
                response["Access-Control-Allow-Origin"] = origin
                response["Access-Control-Allow-Credentials"] = "true"
                # Add other CORS headers for response if needed
            
            return response

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