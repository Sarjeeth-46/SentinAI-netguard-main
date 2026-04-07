import requests, json

base_url = "http://127.0.0.1:8000"

def get_auth_token():
    login_url = f"{base_url}/api/auth/login"
    creds = {"username": "admin", "password": "password"}
    resp = requests.post(login_url, json=creds)
    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def test_persistence_existing():
    token = get_auth_token()
    if not token:
        print("Login failed")
        return
    headers = {"Authorization": f"Bearer {token}"}

    # NO BOOTSTRAP HERE - test existing data from threats.json
    print("Checking dashboard for existing data (24h window)...")
    resp = requests.get(f"{base_url}/api/dashboard/overview", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        print(f"Total Threats: {data['total_threats']}")
        print(f"Window Minutes: {data['window_minutes']}")
    else:
        print(f"Dashboard failed: {resp.status_code}")

if __name__ == "__main__":
    test_persistence_existing()
