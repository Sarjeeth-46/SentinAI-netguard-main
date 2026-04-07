import urllib.request
import json

BASE_URL = "http://localhost:8000"

def verify_data():
    try:
        # 1. Login
        login_url = f"{BASE_URL}/api/auth/login"
        login_data = json.dumps({"username": "admin", "password": "admin"}).encode('utf-8')
        req = urllib.request.Request(login_url, data=login_data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            token = json.loads(response.read().decode('utf-8')).get("access_token")

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Check Topology Coordinates
        print("\n--- Topology Coordinates ---")
        topo_url = f"{BASE_URL}/api/network/topology"
        topo_req = urllib.request.Request(topo_url, headers=headers)
        with urllib.request.urlopen(topo_req) as topo_resp:
            data = json.loads(topo_resp.read().decode('utf-8'))
            nodes = data.get('nodes', [])
            print(f"Total Nodes: {len(nodes)}")
            
            # Check for unique coordinates
            coords = set()
            for n in nodes:
                coords.add((n.get('x'), n.get('y')))
                # print(f"Node {n.get('name')}: x={n.get('x')}, y={n.get('y')}")
            
            print(f"Unique Coordinate Pairs: {len(coords)}")
            if len(coords) < 5:
                print("WARNING: Nodes are stacking! Low unique coordinate count.")
            else:
                print("OK: Nodes are spread out.")

        # 3. Check Geo Codes
        print("\n--- Geo Codes ---")
        geo_url = f"{BASE_URL}/api/stats/geo"
        geo_req = urllib.request.Request(geo_url, headers=headers)
        with urllib.request.urlopen(geo_req) as geo_resp:
            geo_data = json.loads(geo_resp.read().decode('utf-8'))
            print("Geo Data Sample:", json.dumps(geo_data[:5], indent=2))
            
            # Verify they are ISO Alpha-3
            valid_codes = ['USA', 'CHN', 'RUS', 'BRA', 'IND', 'DEU']
            sample_ids = [d['id'] for d in geo_data]
            matches = [c for c in sample_ids if c in valid_codes]
            print(f"Known Codes Found: {matches}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    verify_data()
