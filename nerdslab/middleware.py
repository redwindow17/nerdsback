from django.utils.deprecation import MiddlewareMixin

class ApiCsrfExemptMiddleware(MiddlewareMixin):
    """
    Middleware to exempt API endpoints from CSRF protection
    """
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Exempt API requests from CSRF
        if request.path.startswith('/api/'):
            setattr(request, '_dont_enforce_csrf_checks', True)
        return None 