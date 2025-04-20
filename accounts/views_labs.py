import logging
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

from .lab_client.client import LabClient
from django.conf import settings

logger = logging.getLogger(__name__)

class LabCreateView(APIView):
    """
    View for creating a new lab instance on Server 2.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Create a new lab instance.
        
        Required parameters:
        - lab_type: The type of lab to create (e.g., 'sql_injection', 'xss', etc.)
        
        Optional parameters:
        - config: Dictionary with additional configuration for the lab
        """
        lab_type = request.data.get('lab_type')
        config = request.data.get('config', {})
        
        if not lab_type:
            return Response(
                {'error': 'Lab type is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            client = LabClient()
            result = client.create_lab(lab_type, config)
            
            # Return the result from Server 2
            return Response(result)
            
        except Exception as e:
            logger.error(f"Error creating lab: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
class LabTemplateView(APIView):
    """API endpoint to get lab templates from Server 2"""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    @method_decorator(csrf_protect)
    def get(self, request):
        client = LabClient()
        templates = client.get_lab_templates()
        
        if templates is None:
            return Response(
                {"error": "Unable to fetch lab templates from service"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
            
        return Response(templates)

class LabDetailView(APIView):
    """API endpoint to get details for a specific lab"""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    @method_decorator(csrf_protect)
    def get(self, request, lab_id):
        client = LabClient()
        lab = client.get_lab_template(lab_id)
        
        if lab is None:
            return Response(
                {"error": "Unable to fetch lab details from service"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
            
        return Response(lab)
    
    def delete(self, request, lab_id):
        """
        Delete a lab instance.
        """
        try:
            client = LabClient()
            result = client.delete_lab(lab_id)
            return Response(result)
        except Exception as e:
            logger.error(f"Error deleting lab {lab_id}: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
class LabListView(APIView):
    """
    View for listing all lab instances.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get a list of all lab instances.
        """
        try:
            client = LabClient()
            result = client.get_labs()
            return Response(result)
        except Exception as e:
            logger.error(f"Error listing labs: {str(e)}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 