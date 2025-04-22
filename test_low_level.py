import http.client
import ssl

def test_connection():
    print("Testing direct HTTP connection...")
    
    # Create connection
    conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=10)
    
    # Set headers for CORS test
    headers = {
        "Origin": "https://learn.nerdslab.in",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type, authorization"
    }
    
    try:
        # Send OPTIONS request
        print("\nSending OPTIONS request...")
        conn.request("OPTIONS", "/accounts/login/", headers=headers)
        response = conn.getresponse()
        print(f"Status: {response.status} {response.reason}")
        print("\nResponse headers:")
        for header, value in response.getheaders():
            print(f"{header}: {value}")
            
    except Exception as e:
        print(f"Error occurred: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    test_connection()