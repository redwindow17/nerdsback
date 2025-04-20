import requests
import json

# Base API URL
BASE_URL = 'http://localhost:8000/api'

def test_register():
    """Test user registration API"""
    print("\n--- Testing Registration API ---")
    url = f"{BASE_URL}/accounts/register/"
    data = {
        "username": "testuser123",
        "email": "testuser123@example.com",
        "password": "StrongPassword123!",
        "password2": "StrongPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    try:
        response = requests.post(url, json=data)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 201:
            print("Registration successful!")
            print(json.dumps(response.json(), indent=2))
            return response.json()
        else:
            print("Registration failed:")
            print(json.dumps(response.json(), indent=2))
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_login(username="testuser123", password="StrongPassword123!"):
    """Test user login API"""
    print("\n--- Testing Login API ---")
    url = f"{BASE_URL}/accounts/login/"
    data = {
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(url, json=data)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("Login successful!")
            print(json.dumps(response.json(), indent=2))
            return response.json()
        else:
            print("Login failed:")
            print(json.dumps(response.json(), indent=2))
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_get_user_details(token):
    """Test get user details API"""
    print("\n--- Testing Get User Details API ---")
    url = f"{BASE_URL}/accounts/me/"
    headers = {"Authorization": f"Token {token}"}
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("Got user details:")
            print(json.dumps(response.json(), indent=2))
        else:
            print("Failed to get user details:")
            print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def test_logout(token):
    """Test logout API"""
    print("\n--- Testing Logout API ---")
    url = f"{BASE_URL}/accounts/logout/"
    headers = {"Authorization": f"Token {token}"}
    
    try:
        response = requests.post(url, headers=headers)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("Logout successful!")
            print(json.dumps(response.json(), indent=2))
        else:
            print("Logout failed:")
            print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def run_tests():
    # Step 1: Register a new user
    register_response = test_register()
    
    if register_response:
        token = register_response.get('token')
        
        # Step 2: Test login
        login_response = test_login()
        
        if login_response:
            # Use the token from login
            token = login_response.get('token')
            
            # Step 3: Get user details
            test_get_user_details(token)
            
            # Step 4: Logout
            test_logout(token)

if __name__ == "__main__":
    run_tests() 