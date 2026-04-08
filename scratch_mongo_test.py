import asyncio
import motor.motor_asyncio
from datetime import datetime, timezone, timedelta

async def run():
    from app.core.config import config
    client = motor.motor_asyncio.AsyncIOMotorClient(config.MONGO_URI)
    db = client.aegis_db
    collection = db.telemetry

    cutoff = datetime.now(timezone.utc) - timedelta(days=5)
    cutoff_iso = cutoff.isoformat()
    
    query = {
        "$or": [
            {"timestamp": {"$gte": cutoff}},
            {"timestamp": {"$gte": cutoff_iso}},
        ]
    }
    
    pipeline = [
        {"$match": query},
        {
            "$facet": {
                "risk_counts": [
                    {"$project": {
                        "risk": {
                            "$switch": {
                                "branches": [
                                    {"case": {"$gte": [{"$toDouble": {"$ifNull": ["$risk_score", 0]}}, 80]}, "then": "critical"},
                                    {"case": {"$gte": [{"$toDouble": {"$ifNull": ["$risk_score", 0]}}, 60]}, "then": "high"},
                                    {"case": {"$gte": [{"$toDouble": {"$ifNull": ["$risk_score", 0]}}, 30]}, "then": "medium"}
                                ],
                                "default": "low"
                            }
                        }
                    }},
                    {"$group": {"_id": "$risk", "count": {"$sum": 1}}}
                ],
                "attack_types": [
                    {"$project": {
                        "label": {"$ifNull": ["$predicted_label", {"$ifNull": ["$label", "Unknown"]}]}
                    }},
                    {"$group": {"_id": "$label", "count": {"$sum": 1}}}
                ],
                "total": [
                    {"$count": "count"}
                ]
            }
        }
    ]
    
    try:
        cursor = collection.aggregate(pipeline)
        result = await cursor.to_list(length=1)
        print("AGGREGATION RESULT:")
        print(result)
    except Exception as e:
        print("ERROR:", e)

asyncio.run(run())
