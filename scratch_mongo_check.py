import asyncio
import motor.motor_asyncio
from app.core.config import config

async def run():
    client = motor.motor_asyncio.AsyncIOMotorClient(config.MONGO_URI)
    db = client[config.DB_NAME]
    collection = db[config.COLLECTION_NAME]

    print("--- Collection Stats ---")
    count = await collection.count_documents({})
    print(f"Total documents: {count}")
    
    print("--- Indexes ---")
    async for index in collection.list_indexes():
        print(index)

asyncio.run(run())
