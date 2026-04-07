
import requests
import json
import sys

BASE_URL = "http://localhost:8000"

def run_verification():
    # 1. Login
    print("[*] Attempting Login...")
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "admin"})
        if resp.status_code != 200:
            print(f"[-] Login Failed: {resp.status_code} {resp.text}")
            return
        
        token = resp.json()["access_token"]
        print("[+] Login Successful. Token acquired.")
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return

    # 2. Fetch Dashboard Summary
    print("[*] Fetching Dashboard Summary...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(f"{BASE_URL}/api/dashboard/summary", headers=headers)
        if resp.status_code != 200:
            print(f"[-] API Error: {resp.status_code} {resp.text}")
            return

        data = resp.json()
        threat_count = len(data.get("threats", []))
        print(f"[+] Dashboard Summary Received. Threat Count: {threat_count}")
        
        # Print Risk Summary
        print("Risk Summary:", json.dumps(data.get("risk_summary", []), indent=2))
        
        if threat_count == 0:
            print("[-] WARNING: Threats list is empty despite DB having data.")
        else:
            print("[+] SUCCESS: Dashboard API is returning data.")

    except Exception as e:
        print(f"[-] API Request Error: {e}")

if __name__ == "__main__":
    run_verification()
