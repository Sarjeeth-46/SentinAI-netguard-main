import requests
import time
import json

base_url = "http://127.0.0.1:8000"

def get_auth_token():
    # Attempt login to get token
    login_url = f"{base_url}/api/auth/login"
    creds = {"username": "admin", "password": "password"}
    resp = requests.post(login_url, json=creds)
    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def test_persistence():
    token = get_auth_token()
    if not token:
        print("Login failed")
        return

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Bootstrap
    print("Bootstrapping system...")
    requests.post(f"{base_url}/api/bootstrap_system")
    
    # 2. Get Dashboard Overview
    print("Checking dashboard immediately...")
    resp = requests.get(f"{base_url}/api/dashboard/overview", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        print(f"Immediate Total Threats: {data['total_threats']}")
    else:
        print(f"Dashboard failed: {resp.status_code}")

    # 3. Simulate "Refresh"
    print("Simulating refresh (waiting 2 seconds)...")
    time.sleep(2)
    resp = requests.get(f"{base_url}/api/dashboard/overview", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        print(f"After Refresh Total Threats: {data['total_threats']}")
    else:
        print(f"Dashboard refresh failed: {resp.status_code}")

if __name__ == "__main__":
    test_persistence()
