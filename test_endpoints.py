import requests

BASE_URL = 'http://localhost:8001'

def test_endpoint(path, expected_status=200):
    try:
        response = requests.get(f"{BASE_URL}{path}")
        assert response.status_code == expected_status
        print(f"✓ {path} - Status {response.status_code}")
    except Exception as e:
        print(f"✗ {path} - Error: {str(e)}")

# Test all endpoints
if __name__ == '__main__':
    endpoints = [
        ('/', 200),
        ('/login', 200),
        ('/register', 200),
        ('/health', 200),
        ('/test/404', 404),
        ('/test/500', 500),
        ('/test/db-error', 503),
        ('/nonexistent-page', 404)
    ]
    
    print("Testing endpoints...")
    for path, status in endpoints:
        test_endpoint(path, status)
    
    print("\nTesting complete!")