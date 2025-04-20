#!/usr/bin/env python
"""
A simple script to test CORS configuration for our API endpoints.
This simulates a preflight OPTIONS request and checks for proper CORS headers.
"""

import requests
import sys

def test_cors_preflight(api_url, frontend_url):
    """
    Test if CORS preflight requests are handled correctly.
    """
    print(f"\n=== Testing CORS for {api_url} from {frontend_url} ===\n")
    
    # Simulate preflight OPTIONS request
    headers = {
        'Origin': frontend_url,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, Authorization'
    }
    
    try:
        response = requests.options(api_url, headers=headers, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        # Check for required CORS headers
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials'
        ]
        
        all_headers_present = True
        
        print("\nCORS Headers:")
        for header in cors_headers:
            if header in response.headers:
                print(f"  ✅ {header}: {response.headers[header]}")
                
                # Verify the origin matches our frontend
                if header == 'Access-Control-Allow-Origin':
                    if response.headers[header] != frontend_url and response.headers[header] != '*':
                        print(f"  ⚠️ Warning: Origin doesn't match frontend URL")
                        all_headers_present = False
            else:
                print(f"  ❌ {header}: Missing")
                all_headers_present = False
        
        print("\nAll Response Headers:")
        for header, value in response.headers.items():
            print(f"  {header}: {value}")
            
        if all_headers_present:
            print("\n✅ SUCCESS: CORS is properly configured!")
        else:
            print("\n❌ FAILURE: CORS is not properly configured.")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR: {e}")
        return False
    
    return all_headers_present

if __name__ == "__main__":
    # Default endpoints to check
    api_endpoints = [
        "https://nerd-api.nerdslab.in/accounts/login/",
        "https://nerd-api.nerdslab.in/accounts/register/",
        "https://nerd-api.nerdslab.in/accounts/me/"
    ]
    
    # Origin of the frontend
    frontend_url = "https://learn.nerdslab.in"
    
    # Allow custom endpoints to be passed as arguments
    if len(sys.argv) > 1:
        api_endpoints = [sys.argv[1]]
    
    # Test each endpoint
    all_passed = True
    for endpoint in api_endpoints:
        if not test_cors_preflight(endpoint, frontend_url):
            all_passed = False
    
    # Exit with appropriate status code
    sys.exit(0 if all_passed else 1) 