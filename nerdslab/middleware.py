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
    """
    Middleware to add CORS headers to all responses to ensure proper cross-origin access
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_origin = 'https://learn.nerdslab.in'

    def __call__(self, request):
        response = self.get_response(request)
        
        # Get origin from request headers
        origin = request.headers.get('Origin')
        
        # Only set CORS headers if origin matches our allowed origin
        if origin == self.allowed_origin:
            response["Access-Control-Allow-Origin"] = self.allowed_origin
            response["Access-Control-Allow-Credentials"] = "true"
            
            if request.method == "OPTIONS":
                response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-CSRFToken, Accept, Origin"
                response["Access-Control-Max-Age"] = "86400"  # 24 hours
                response.content = b""
                response["Content-Length"] = "0"
                response.status_code = 204
            else:
                response["Access-Control-Expose-Headers"] = "Content-Length,Content-Range,X-CSRFToken"
                
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
    """
    Middleware to handle Cloudflare proxy headers and ensure proper CORS handling
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_origins = ['https://learn.nerdslab.in', 'https://labs.nerdslab.in']

    def __call__(self, request):
        # Handle Cloudflare headers
        if 'HTTP_CF_CONNECTING_IP' in request.META:
            request.META['REMOTE_ADDR'] = request.META['HTTP_CF_CONNECTING_IP']
        
        if 'HTTP_CF_VISITOR' in request.META:
            # Ensure proper scheme detection (http/https)
            try:
                import json
                cf_visitor = json.loads(request.META['HTTP_CF_VISITOR'])
                if cf_visitor.get('scheme') == 'https':
                    request.META['wsgi.url_scheme'] = 'https'
            except:
                pass

        response = self.get_response(request)
        
        # Always check origin and set CORS headers
        origin = request.headers.get('Origin')
        if origin in self.allowed_origins:
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
            
            if request.method == 'OPTIONS':
                response['Access-Control-Allow-Methods'] = 'DELETE, GET, OPTIONS, PATCH, POST, PUT'
                response['Access-Control-Allow-Headers'] = 'Accept, Accept-Encoding, Authorization, Content-Type, DNT, Origin, User-Agent, X-CSRFToken, X-Requested-With'
                response['Access-Control-Max-Age'] = '86400'
                response.status_code = 204
            else:
                response['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, X-CSRFToken'
                
        return response