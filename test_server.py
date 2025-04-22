import requests
from requests.exceptions import RequestException
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings()

def test_endpoint(protocol='http'):
    base_url = f'{protocol}://localhost:8000'
    endpoints = [
        '/accounts/login/',
        '/accounts/register/',
        '/accounts/me/'
    ]
    
    headers = {
        'Origin': 'https://learn.nerdslab.in',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type, authorization'
    }
    
    for endpoint in endpoints:
        url = base_url + endpoint
        print(f"\nTesting endpoint: {url}")
        try:
            # Test OPTIONS request (preflight)
            print("\nTesting OPTIONS request:")
            response = requests.options(url, headers=headers, verify=False)
            print(f"Status Code: {response.status_code}")
            print("Response Headers:")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
                
            # Test GET request
            print("\nTesting GET request:")
            response = requests.get(url, verify=False)
            print(f"Status Code: {response.status_code}")
            
        except RequestException as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    print("Testing HTTP...")
    test_endpoint('http')
    
    print("\nTesting HTTPS...")
    test_endpoint('https')