#!/usr/bin/env python
import os
import sys
import django
import dotenv
import json
import requests

# Load the production environment
dotenv.load_dotenv('.env.production')

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nerdslab.settings')
django.setup()

# Import Django models
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework.authtoken.models import Token

def check_server1_database():
    """Check if Server 1 SQLite database is working"""
    print("\n=== Server 1 Database Check ===")
    try:
        # Get user count
        user_count = User.objects.count()
        print(f"✅ Database connection successful - {user_count} users found")
        
        # List first 3 users
        users = User.objects.all()[:3]
        if users:
            print("Sample users:")
            for user in users:
                print(f"  - {user.username} ({user.email})")
        return True
    except Exception as e:
        print(f"❌ Database error: {str(e)}")
        return False

def check_server2_connection():
    """Check if Server 2 is accessible"""
    print("\n=== Server 2 Connection Check ===")
    try:
        # Get the Labs API URL from settings
        labs_api_url = os.environ.get('LABS_API_URL', settings.LABS_API_URL)
        service_token = os.environ.get('LABS_SERVICE_TOKEN', settings.LABS_SERVICE_TOKEN)
        
        print(f"Labs API URL: {labs_api_url}")
        
        # Try to access the health endpoint
        health_url = f"{labs_api_url}/health/"
        print(f"Testing connection to {health_url}...")
        
        response = requests.get(health_url, timeout=5)
        if response.status_code == 200:
            print(f"✅ Server 2 is accessible - Status: {response.status_code}")
            print(f"Response: {response.text[:100]}...")
            return True
        else:
            print(f"❌ Server 2 returned status code: {response.status_code}")
            print(f"Response: {response.text[:100]}...")
            return False
    except requests.RequestException as e:
        print(f"❌ Connection error: {str(e)}")
        return False

def check_token_exchange():
    """Check if token exchange works"""
    print("\n=== Token Exchange Check ===")
    try:
        # Get a user to test with
        user = User.objects.filter(is_active=True).first()
        if not user:
            print("❌ No active users found for testing")
            return False
            
        print(f"Testing with user: {user.username}")
        
        # Get the Labs API URL and service token
        labs_api_url = os.environ.get('LABS_API_URL', settings.LABS_API_URL)
        service_token = os.environ.get('LABS_SERVICE_TOKEN', settings.LABS_SERVICE_TOKEN)
        
        # Test token exchange
        token_url = f"{labs_api_url}/auth/service-token/"
        print(f"Testing token exchange with {token_url}...")
        
        payload = {
            'service_token': service_token,
            'user_id': user.id,
            'username': user.username,
        }
        
        response = requests.post(token_url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"✅ Token exchange successful - Status: {response.status_code}")
            token_data = response.json()
            print(f"Tokens received: {json.dumps(token_data, indent=2)}")
            return True
        else:
            print(f"❌ Token exchange failed - Status: {response.status_code}")
            print(f"Response: {response.text[:100]}...")
            return False
    except Exception as e:
        print(f"❌ Token exchange error: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing production configuration...\n")
    
    # Check Server 1 database
    db_ok = check_server1_database()
    
    # Check Server 2 connection
    server2_ok = check_server2_connection()
    
    # Check token exchange
    token_ok = check_token_exchange() if db_ok and server2_ok else False
    
    # Print summary
    print("\n=== Summary ===")
    print(f"Server 1 Database: {'✅ OK' if db_ok else '❌ Failed'}")
    print(f"Server 2 Connection: {'✅ OK' if server2_ok else '❌ Failed'}")
    print(f"Token Exchange: {'✅ OK' if token_ok else '❌ Failed'}")
    
    if db_ok and server2_ok and token_ok:
        print("\n✅ All checks passed! Production configuration is working correctly.")
        sys.exit(0)
    else:
        print("\n❌ Some checks failed. See above for details.")
        sys.exit(1) 