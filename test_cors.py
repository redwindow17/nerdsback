#!/usr/bin/env python
"""
A simple script to test CORS configuration for our API endpoints.
This simulates a preflight OPTIONS request and checks for proper CORS headers.
"""

import os
import django
import requests
import json
from colorama import init, Fore, Style

# Initialize colorama
init()

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nerdslab.settings')
django.setup()

from django.conf import settings

def print_colored(text, color=Fore.WHITE):
    """Print colored text"""
    print(f"{color}{text}{Style.RESET_ALL}")

def test_cors_settings():
    """Test and display CORS settings"""
    print_colored("CORS Settings:", Fore.CYAN)
    print_colored(f"CORS_ALLOW_ALL_ORIGINS: {getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False)}", Fore.YELLOW)
    
    allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
    print_colored("CORS_ALLOWED_ORIGINS:", Fore.YELLOW)
    for origin in allowed_origins:
        print(f"  - {origin}")
    
    print_colored(f"CORS_ALLOW_CREDENTIALS: {getattr(settings, 'CORS_ALLOW_CREDENTIALS', False)}", Fore.YELLOW)
    
    cors_headers = getattr(settings, 'CORS_ALLOW_HEADERS', [])
    print_colored("CORS_ALLOW_HEADERS:", Fore.YELLOW)
    for header in cors_headers:
        print(f"  - {header}")
    
    cors_methods = getattr(settings, 'CORS_ALLOW_METHODS', [])
    print_colored("CORS_ALLOW_METHODS:", Fore.YELLOW)
    for method in cors_methods:
        print(f"  - {method}")
    
    expose_headers = getattr(settings, 'CORS_EXPOSE_HEADERS', [])
    print_colored("CORS_EXPOSE_HEADERS:", Fore.YELLOW)
    for header in expose_headers:
        print(f"  - {header}")
    
    print_colored(f"CORS_PREFLIGHT_MAX_AGE: {getattr(settings, 'CORS_PREFLIGHT_MAX_AGE', None)}", Fore.YELLOW)

def test_cors_response():
    """Test CORS headers in API response"""
    api_url = settings.LAB_SERVICE_URL
    origin = "https://learn.nerdslab.in"
    
    print_colored("\nTesting CORS Headers in Response:", Fore.CYAN)
    print_colored(f"API URL: {api_url}", Fore.YELLOW)
    print_colored(f"Origin: {origin}", Fore.YELLOW)
    
    try:
        # Make OPTIONS request with Origin header
        response = requests.options(
            f"{api_url}/api/health/",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type"
            },
            timeout=5,
            verify=False  # Ignore SSL for testing
        )
        
        print_colored("\nResponse Headers:", Fore.CYAN)
        for key, value in response.headers.items():
            if key.lower().startswith("access-control"):
                print_colored(f"{key}: {value}", Fore.GREEN)
            else:
                print(f"{key}: {value}")
        
        if "access-control-allow-origin" in response.headers:
            print_colored("\nCORS is properly configured!", Fore.GREEN)
        else:
            print_colored("\nCORS headers missing in response!", Fore.RED)
            
    except Exception as e:
        print_colored(f"Error testing CORS: {e}", Fore.RED)

if __name__ == "__main__":
    test_cors_settings()
    test_cors_response() 