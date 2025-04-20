import requests
import logging
import json
from django.conf import settings
from typing import Dict, Any, Optional, List
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)

class LabClient:
    """
    Client for interacting with the Server 2 lab service.
    """
    
    def __init__(self):
        self.base_url = settings.LAB_SERVICE_URL
        self.token = settings.LAB_SERVICE_TOKEN
        self.timeout = 10  # seconds
        self.headers = {
            'Authorization': f'Token {self.token}',
            'Content-Type': 'application/json'
        }
    
    def _make_request(self, method, endpoint, data=None, params=None):
        """Make authenticated request to lab service with error handling"""
        url = f"{self.base_url}/api/{endpoint}"
        
        try:
            logger.info(f"Making {method.upper()} request to {url}")
            
            if method.lower() == 'get':
                response = requests.get(url, headers=self.headers, params=params, timeout=self.timeout)
            elif method.lower() == 'post':
                response = requests.post(url, headers=self.headers, json=data, timeout=self.timeout)
            elif method.lower() == 'put':
                response = requests.put(url, headers=self.headers, json=data, timeout=self.timeout)
            elif method.lower() == 'delete':
                response = requests.delete(url, headers=self.headers, timeout=self.timeout)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code >= 400:
                logger.error(f"Request failed with status {response.status_code}: {response.text}")
                
            response.raise_for_status()
            return response.json()
            
        except Timeout:
            logger.error(f"Timeout connecting to lab service: {url}")
            return None
        except RequestException as e:
            logger.error(f"Error connecting to lab service: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return None
            
    def create_lab(self, lab_type: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create a new lab instance.
        
        Args:
            lab_type: The type of lab to create (e.g., 'sql_injection', 'xss', etc.)
            config: Additional configuration parameters for the lab
            
        Returns:
            Dictionary with lab details including lab_id and URL
        """
        if config is None:
            config = {}
            
        url = f"{self.base_url}/api/labs/create/"
        data = {
            'lab_type': lab_type,
            'config': config
        }
        
        return self._make_request('post', 'labs/create/', data=data)
    
    def delete_lab(self, lab_id: str) -> Dict[str, Any]:
        """
        Delete a lab instance.
        
        Args:
            lab_id: The ID of the lab to delete
            
        Returns:
            Dictionary with the operation status
        """
        url = f"{self.base_url}/api/labs/{lab_id}/"
        
        return self._make_request('delete', f'labs/{lab_id}/')
    
    def get_lab(self, lab_id: str) -> Dict[str, Any]:
        """
        Get details about a lab instance.
        
        Args:
            lab_id: The ID of the lab
            
        Returns:
            Dictionary with lab details
        """
        url = f"{self.base_url}/api/labs/{lab_id}/"
        
        return self._make_request('get', f'labs/{lab_id}/')
    
    def get_labs(self) -> List[Dict[str, Any]]:
        """
        Get a list of all lab instances.
        
        Returns:
            List of dictionaries with lab details
        """
        url = f"{self.base_url}/api/labs/"
        
        return self._make_request('get', 'labs/')
    
    def get_lab_templates(self):
        """Get all available lab templates"""
        return self._make_request('get', 'test/templates/')
        
    def get_lab_template(self, lab_id):
        """Get a specific lab template"""
        return self._make_request('get', f'labs/templates/{lab_id}/')
        
    def create_lab_instance(self, lab_id, user_id):
        """Create a new lab instance for a user"""
        data = {
            'lab_id': lab_id,
            'user_id': user_id
        }
        return self._make_request('post', 'lab-instances/', data=data)
        
    def get_lab_status(self, lab_id=None):
        """Get lab status"""
        if lab_id:
            return self._make_request('get', f'lab-status/{lab_id}/')
        return self._make_request('get', 'lab-status/') 