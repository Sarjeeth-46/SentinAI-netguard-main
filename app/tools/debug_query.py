import asyncio
from backend.core.database import db

async def check_db():
    print("Executing query...")
    # Test for past 3 days based on current date which is ~2026-02-23
    data = await db.dal.query_security_events_by_timerange('2026-02-20T00:00:00Z', '2026-02-25T23:59:59Z')
    print(f'Total matches: {len(data)}')
    if len(data) > 0:
        print(f"Sample: {data[0]['timestamp']} - {data[0]['predicted_label']}")

if __name__ == "__main__":
    asyncio.run(check_db())
