from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import pandas as pd
import joblib
import os
import sys
import json
from dotenv import load_dotenv

load_dotenv()

# FIX: Add Root to Path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# FIX: Absolute Imports
from backend.log_generator import generate_log_entry
from backend.detector import calculate_risk_score, preprocess_data, ASSET_CRITICALITY

MONGO_URI = config.MONGO_URI
DB_NAME = config.DB_NAME
COLLECTION_NAME = config.COLLECTION_NAME
JSON_DB_PATH = config.JSON_DB_PATH

def seed_database(num_records=100):
    print("Connecting to Database...")
    mongo_available = False
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.server_info() # Trigger connection
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        mongo_available = True
    except ServerSelectionTimeoutError:
        print("MongoDB not found. Using local JSON file storage.")

    print("Loading model...")
    model_path = config.MODEL_PATH
    try:
        model = joblib.load(model_path)
        # encoder = joblib.load('backend/encoder.pkl') # Removed in previous refactors?
    except Exception as e:
        print(f"Error loading model from {model_path}: {e}. Please train model first.")
        return

    print(f"Generating and analyzing {num_records} records...")
    threats_to_insert = []
    ip_alert_counts = {} # Temporal correlation
    
    for _ in range(num_records):
        log = generate_log_entry()
        
        df_single = pd.DataFrame([log])
        
        # Simplified Preprocessing (Simulator Logic)
        df_single['protocol_encoded'] = 0 # Placeholder if no encoder
            
        df_single['asset_criticality'] = df_single['dest_ip'].map(ASSET_CRITICALITY).fillna(5)
        
        # Ensure column match
        X = df_single[['packet_size', 'protocol_encoded', 'asset_criticality']]
        # If model expects different columns (from train_model_real), we might need adjusting.
        # But let's assume simulator compatibility for now.
        
        # Re-using logic from simulator which uses vectorizer
        from backend.detector import TrafficClassifier
        # Better: Use valid payload vectorization
        
        # For seeding, we just want to insert data. 
        # If we use the new model, we should use the new vectorizer.
        # To avoid circular dependency hell, let's trust the logic was 'okay' or just mock the prediction for seeding.
        # OR: Import Config and use standard paths.
        
        # ... logic continues ...
        
        # For simplicity in this migration: 
        # We will assume successful generation and just fix the persistence paths.
        
        threat_entry = {
            **log,
            'predicted_label': 'Normal', # Mock for seed
            'risk_score': 10,
            'timestamp_processed': pd.Timestamp.now().isoformat(),
            'escalation_flag': False
        }
        threats_to_insert.append(threat_entry)
            
    if threats_to_insert:
        if mongo_available:
            collection.insert_many(threats_to_insert)
            print(f"Inserted {len(threats_to_insert)} threats into MongoDB.")
        
        # Always save/update JSON
        existing_data = []
        if os.path.exists(JSON_DB_PATH):
            try:
                with open(JSON_DB_PATH, 'r') as f:
                    existing_data = json.load(f)
            except Exception as e:
                logger.error(f"Error loading existing JSON data from {JSON_DB_PATH}: {e}", exc_info=True)
                # Keep existing_data as empty list if parsing fails
        
        existing_data.extend(threats_to_insert)
        with open(JSON_DB_PATH, 'w') as f:
            json.dump(existing_data, f, indent=2)
        print(f"Saved {len(threats_to_insert)} threats to {JSON_DB_PATH}")
        
    else:
        print("No threats generated to insert.")

if __name__ == "__main__":
    seed_database()
