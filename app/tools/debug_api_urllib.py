import urllib.request
import urllib.parse
import json
import sys

BASE_URL = "http://localhost:8000"

def debug_api():
    try:
        # 1. Login
        login_url = f"{BASE_URL}/api/auth/login"
        login_data = json.dumps({"username": "admin", "password": "admin"}).encode('utf-8')
        req = urllib.request.Request(login_url, data=login_data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                print(f"Login Failed: {response.status}")
                return
            resp_body = response.read().decode('utf-8')
            token = json.loads(resp_body).get("access_token")

        if not token:
            print("No access token received.")
            return

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Fetch Topology
        print("\n--- Topology Data ---")
        topo_url = f"{BASE_URL}/api/network/topology"
        topo_req = urllib.request.Request(topo_url, headers=headers)
        with urllib.request.urlopen(topo_req) as topo_resp:
            topo_data = json.loads(topo_resp.read().decode('utf-8'))
            nodes = topo_data.get('nodes', [])
            print(f"Node Count: {len(nodes)}")
            if nodes:
                print("Sample Node 0:", json.dumps(nodes[0], indent=2))

        # 3. Fetch Geo Stats
        print("\n--- Geo Data ---")
        geo_url = f"{BASE_URL}/api/stats/geo"
        geo_req = urllib.request.Request(geo_url, headers=headers)
        with urllib.request.urlopen(geo_req) as geo_resp:
            geo_data = json.loads(geo_resp.read().decode('utf-8'))
            print("Geo Data Count:", len(geo_data))
            if geo_data:
                print("First 3 items:", json.dumps(geo_data[:3], indent=2))

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_api()
