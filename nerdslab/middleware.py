from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)

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
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Get the origin from the request
        origin = request.headers.get('Origin')
        
        # Check if the origin is in our allowed list
        allowed_origins = [
            'https://learn.nerdslab.in',
            'https://labs.nerdslab.in',
            'https://nerd-api.nerdslab.in'
        ]
        
        if origin in allowed_origins:
            # Set CORS headers for the response
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
            response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Accept-Encoding, Origin, Cache-Control, DNT, User-Agent"
            
            # For preflight requests
            if request.method == 'OPTIONS':
                response["Access-Control-Max-Age"] = "86400"  # 24 hours
                if not response.content:
                    response.content = b''
                    response["Content-Type"] = "text/plain; charset=utf-8"
                    response["Content-Length"] = "0"
                    response.status_code = 204  # No content
        
        return response

class CorsDebugMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Log CORS-related headers
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request path: {request.path}")
        logger.info("Request headers:")
        for header, value in request.headers.items():
            logger.info(f"  {header}: {value}")

        response = self.get_response(request)

        # Log response headers
        logger.info("Response headers:")
        for header, value in response.headers.items():
            logger.info(f"  {header}: {value}")

        return response

class CloudflareProxyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle Cloudflare headers
        if 'HTTP_CF_CONNECTING_IP' in request.META:
            request.META['REMOTE_ADDR'] = request.META['HTTP_CF_CONNECTING_IP']
        
        if 'HTTP_CF_VISITOR' in request.META:
            try:
                import json
                cf_visitor = json.loads(request.META['HTTP_CF_VISITOR'])
                if cf_visitor.get('scheme') == 'https':
                    request.META['wsgi.url_scheme'] = 'https'
            except:
                pass

        response = self.get_response(request)
        return response