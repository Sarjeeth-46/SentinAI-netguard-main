import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel, ASCENDING, DESCENDING
from backend.core.config import config

async def setup_database():
    """
    Creates proper compound indexes based on dashboard query patterns
    and a TTL index for 30-day automatic log expiry.
    Also demonstrates optimized connection pooling via motor configuration.
    """
    print(f"Connecting to MongoDB at {config.MONGO_URI.split('@')[-1]}")
    
    # Connection Pool Tuning
    client = AsyncIOMotorClient(
        config.MONGO_URI, 
        serverSelectionTimeoutMS=5000,
        maxPoolSize=50,
        minPoolSize=10,
        maxIdleTimeMS=60000 
    )
    
    db = client[config.DB_NAME]
    collection = db[config.COLLECTION_NAME]
    
    indexes = [
        # Dashboard query pattern: { "status": 1, "timestamp": -1 }
        IndexModel([("status", ASCENDING), ("timestamp", DESCENDING)], name="idx_status_time"),
        
        # Time-range scans: { "timestamp": -1 }
        IndexModel([("timestamp", DESCENDING)], name="idx_time_desc"),
        
        # Threat Type query: { "predicted_label": 1 }
        IndexModel([("predicted_label", ASCENDING)], name="idx_label"),
        
        # TTL index: 30 days (2,592,000 seconds)
        IndexModel([("timestamp", ASCENDING)], expireAfterSeconds=2592000, name="ttl_logs_30d")
    ]
    
    print("Creating Compound and TTL Indexes...")
    try:
        await collection.create_indexes(indexes)
        print("Indexes created successfully.")
    except Exception as e:
        print(f"Failed to create indexes: {e}")
        
    client.close()

if __name__ == "__main__":
    asyncio.run(setup_database())
