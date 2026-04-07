import asyncio, sys, os
sys.path.insert(0, 'c:/SentinAI-netguard')
from app.db.connection import db

async def test_range_cloud():
    # Force cloud mode
    db.dal._is_local_mode = False
    await db.dal._ensure_connection()
    
    start = "2026-02-26 00:00:00"
    end   = "2026-02-26 23:59:59"
    
    print(f"Testing CLOUD range: {start} to {end}")
    events = await db.query_security_events_by_timerange(start, end)
    print(f"Found {len(events)} events.")
    if events:
        print(f"First event TS: {events[0].get('timestamp')}")

asyncio.run(test_range_cloud())
