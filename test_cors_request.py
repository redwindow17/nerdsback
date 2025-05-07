import requests

def test_cors():
    url = 'https://nerd-api.nerdslab.in/accounts/login/'
    headers = {
        'Origin': 'https://learn.nerdslab.in',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'
    }
    
    try:
        # Test OPTIONS request (preflight)
        response = requests.options(url, headers=headers)
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_cors()