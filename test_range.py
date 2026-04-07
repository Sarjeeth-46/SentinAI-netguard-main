import asyncio, sys, os
sys.path.insert(0, 'c:/SentinAI-netguard')
from app.db.connection import db

async def test_range():
    # Force local mode
    db.dal._is_local_mode = True
    
    start = "2026-02-26 00:00:00"
    end   = "2026-02-26 23:59:59"
    
    print(f"Testing LOCAL range: {start} to {end}")
    events = await db.query_security_events_by_timerange(start, end)
    print(f"Found {len(events)} events.")
    if events:
        print(f"First event TS: {events[0].get('timestamp')}")
    else:
        # Debug why it found 0
        data = await db.dal._read_local_data()
        print(f"Total raw events in local: {len(data)}")
        if data:
            ts = data[0].get('timestamp')
            print(f"Sample raw TS: '{ts}'")
            start_dt = db.dal.parse_iso_simple(start)
            end_dt = db.dal.parse_iso_simple(end)
            ts_dt = db.dal.parse_iso_simple(ts)
            print(f"Parsed Start: {start_dt}")
            print(f"Parsed End:   {end_dt}")
            print(f"Parsed Raw:  {ts_dt}")
            print(f"In range? {start_dt <= ts_dt <= end_dt}")

asyncio.run(test_range())
