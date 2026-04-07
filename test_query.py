import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.threat_service import threat_service

async def test():
    # Today's date in UTC
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    start_time = f"{today}T00:00:00+00:00"
    end_time   = f"{today}T23:59:59+00:00"
    
    print(f"Testing filter for UTC date: {today}")
    threats = await threat_service.get_recent_threats(start_time=start_time, end_time=end_time)
    print(f"Filtered Threats Count: {len(threats)}")
    if threats:
        print("Sample timestamp:", threats[0].get("timestamp"))

if __name__ == "__main__":
    asyncio.run(test())
