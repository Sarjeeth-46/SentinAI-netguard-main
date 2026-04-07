import asyncio
import random
import uuid
import sys
from datetime import datetime, timedelta, timezone

# Add project root to sys.path
sys.path.insert(0, r"d:\project\SentinAI-netguard-main")

from app.db.connection import db

async def generate_500_active_threats():
    print("Connecting to database...")
    await db.connect()
    
    collection = db.get_db()["telemetry"]
    
    print("Generating 500 real-time active threats...")
    now = datetime.now(timezone.utc)
    
    attack_types = ["Brute Force", "DDoS", "Port Scan", "SQL Injection", "XSS", "Malware"]
    ip_ranges = ["192.168.1.", "10.0.0.", "172.16."]
    
    events = []
    
    for i in range(500):
        # Scatter within the last 5 minutes so it shows up in DASHBOARD_WINDOW_MINUTES
        seconds_ago = random.randint(0, 300)
        event_time = now - timedelta(seconds=seconds_ago)
        
        # Pick risk score and matching status
        risk_score = random.randint(60, 100) # Ensure high severity threats for dramatic dashboard effect
        
        event_data = {
            "id": str(uuid.uuid4()),
            "timestamp": event_time,
            "source_ip": f"{random.choice(ip_ranges)}{random.randint(1, 254)}",
            # Targeting our 10.0.5.x Secure Enclave for Topology mapping
            "destination_ip": f"10.0.5.{random.randint(1, 5)}", 
            "predicted_label": random.choice(attack_types),
            "confidence": round(random.uniform(0.70, 0.99), 2),
            "risk_score": risk_score,
            "status": "Active",
            "metadata": {"source": "Data Seeder Payload"}
        }
        events.append(event_data)
        
    # Insert efficiently
    await collection.insert_many(events)
    print("Successfully seeded 500 active threats into the last 5 minutes.")
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(generate_500_active_threats())
