from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
import structlog
from app.core.config import config

logger = structlog.get_logger("database")

class Database:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance.client = None
            cls._instance.redis = None
        return cls._instance

    async def connect(self):
        try:
            self.client = AsyncIOMotorClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
            await self.client.admin.command('ismaster')
            
            # Optimize read queries with index
            db_handle = self.client[config.DB_NAME]
            await db_handle[config.COLLECTION_NAME].create_index([("timestamp", -1)])
            
            self.redis = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT)
            await self.redis.ping()
            
            logger.info("database_connected", status="success")
        except Exception as e:
            logger.error("database_connection_failed", error=str(e))

    async def close(self):
        try:
            if self.client:
                self.client.close()
            if self.redis:
                await self.redis.close()
            logger.info("database_disconnected")
        except Exception as e:
            logger.error("database_disconnect_error", error=str(e))

    def get_db(self):
        if self.client:
            return self.client[config.DB_NAME]
        return None

    async def fetch_data(self, limit: int = 100):
        db_handle = self.get_db()
        if db_handle is None: return []
        cursor = db_handle[config.COLLECTION_NAME].find({}, {"_id": 0}).sort('timestamp', -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def save_event(self, event_data: dict):
        db_handle = self.get_db()
        if db_handle is None: return
        await db_handle[config.COLLECTION_NAME].update_one(
            {"id": event_data["id"]},
            {"$set": event_data},
            upsert=True
        )

    async def query_security_events_by_timerange(self, start_time: str, end_time: str):
        db_handle = self.get_db()
        if db_handle is None: return []
        
        # Determine the format based on the 'Z' postfix
        # The frontend supplies complete ISO 8601 strings, like "2026-04-01T00:00:00.000Z"
        # However, Python's datetime.fromisoformat() requires the 'Z' to be replaced with '+00:00'
        # before Python 3.11. Let's do this to safely convert the strings into `datetime` objects.
        import datetime
        from dateutil.parser import parse
        
        try:
            # First try parsing the string directly (handle 'Z' or offset if present)
            st_dt = parse(start_time)
            et_dt = parse(end_time)
            
            # Create a query that looks for BOTH the native timezone-aware datetime object
            # (which is how the python backend natively writes it via datetime.now(timezone.utc))
            # AND the string representation, just in case legacy tools wrote raw strings.
            query = {
                "$or": [
                    # Check natively stored Date types
                    {"timestamp": {"$gte": st_dt, "$lt": et_dt}},
                    # Check string variants
                    {"timestamp": {"$gte": start_time, "$lt": end_time}}
                ]
            }
        except Exception as e:
            logger.warning("date_parse_failure_falling_back_to_string_compare", e=str(e))
            query = {"timestamp": {"$gte": start_time, "$lt": end_time}}
            
        cursor = db_handle[config.COLLECTION_NAME].find(query, {"_id": 0}).sort('timestamp', -1)
        return await cursor.to_list(length=5000)

db = Database()
