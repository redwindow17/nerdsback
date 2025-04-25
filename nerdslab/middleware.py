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

class CorsDebugMiddleware:
    """
    Middleware to log CORS-related headers for debugging
    """
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
    Middleware to handle Cloudflare proxy headers
    """
    def __init__(self, get_response):
        self.get_response = get_response

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

        return self.get_response(request)