from django.contrib import admin
from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static

@api_view(['GET'])
@permission_classes([AllowAny])
def api_health_check(request):
    return Response({'status': 'healthy'})

def handle_options(request):
    response = HttpResponse()
    origin = request.headers.get('Origin')
    
    if origin in settings.CORS_ALLOWED_ORIGINS:
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Accept, Accept-Encoding, Authorization, Content-Type, Origin, X-CSRFToken, X-Requested-With'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
    
    return response

# Simple test view to check if basic routing works
def test_view(request):
    return HttpResponse("Server is working correctly in HTTP mode!")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('health/', api_health_check, name='health-check'),
    path('test/', test_view, name='test_view'),  # Add test URL
    # Handle OPTIONS requests at the root level
    path('', handle_options),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)