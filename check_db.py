import asyncio
from app.db.connection import db

async def check():
    await db.connect()
    c = db.get_db()["telemetry"]
    count = await c.count_documents({})
    print("TOTAL DB COUNT:", count)
    
    # Let's get the 5 most recent
    docs = await c.find({}, {}).sort("timestamp", -1).limit(5).to_list(10)
    for index, d in enumerate(docs):
        print(f"[{index}] {d.get('timestamp')} - {d.get('label')}")
    await db.close()

asyncio.run(check())
