import asyncio
import httpx

async def test_api():
    # Login to get token
    async with httpx.AsyncClient() as client:
        print("Logging in...")
        res = await client.post("http://localhost:8000/api/auth/login", json={"username": "admin", "password": "admin"})
        if res.status_code != 200:
            print(f"Login failed: {res.text}")
            return
            
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        print("Querying threats...")
        res = await client.get("http://localhost:8000/api/threats?start_time=2026-02-20T00:00:00Z&end_time=2026-02-23T23:59:59Z", headers=headers)
        if res.status_code != 200:
             print(f"API Failed: {res.status_code} - {res.text}")
             return
             
        data = res.json()
        print(f"API Returned {len(data)} items.")

if __name__ == "__main__":
    asyncio.run(test_api())
