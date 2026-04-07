import random
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "threat_detection"
COLLECTION_NAME = "threats"
COUNTRY_CODES = ["USA", "CHN", "RUS", "BRA", "IND", "DEU", "GBR", "FRA", "JPN", "KOR"]

def backfill_mongo():
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        
        # Count documents missing source_country
        query = {"source_country": {"$exists": False}}
        count = collection.count_documents(query)
        print(f"Found {count} documents missing 'source_country'.")
        
        if count == 0:
            print("MongoDB is already consistent.")
            return

        print("Backfilling...")
        # Update one by one or bulk? Bulk is better but simple loop is safer for this script.
        # Actually, let's update_many for random distribution? No, update_many sets same value.
        # We iterate.
        cursor = collection.find(query)
        updates = 0
        
        for doc in cursor:
            country = random.choice(COUNTRY_CODES)
            collection.update_one(
                {"_id": doc["_id"]}, 
                {"$set": {"source_country": country, "predicted_label": doc.get('label', 'Normal')}}
            )
            updates += 1
            if updates % 100 == 0:
                print(f"Updated {updates} records...")
                
        print(f"Successfully backfilled {updates} records in MongoDB.")
        
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")

if __name__ == "__main__":
    backfill_mongo()
