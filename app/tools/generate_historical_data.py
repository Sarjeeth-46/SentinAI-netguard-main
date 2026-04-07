import asyncio
import random
from datetime import datetime, timedelta, timezone
from backend.core.database import db

async def generate_historical_data():
    print("Generating 30 days of historical threat data...")
    now = datetime.now(timezone.utc)
    
    attack_types = ["Brute Force", "DDoS", "Port Scan", "Normal", "SQL Injection"]
    ip_ranges = ["192.168.1.", "10.0.0.", "172.16."]
    
    total_events = 0
    # Generate data for the past 30 days
    for days_ago in range(30):
        target_date = now - timedelta(days=days_ago)
        
        # 10 to 50 events per day
        events_today = random.randint(10, 50)
        
        for _ in range(events_today):
            # random time within that day
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            event_time = target_date.replace(hour=hour, minute=minute, second=second)
            
            event_data = {
                "id": f"hist-{days_ago}-{total_events}",
                "timestamp": event_time,
                "source_ip": f"{random.choice(ip_ranges)}{random.randint(1, 254)}",
                "dest_ip": f"10.0.0.{random.randint(1, 20)}",
                "predicted_label": random.choice(attack_types),
                "confidence": round(random.uniform(0.60, 0.99), 2),
                "risk_score": random.randint(10, 100),
                "status": random.choice(["Active", "Resolved"]),
                "metadata": {"source": "Historical Generator"}
            }
            
            await db.dal.save_event(event_data)
            total_events += 1
            
    print(f"Successfully generated {total_events} events spanning the last 30 days.")

if __name__ == "__main__":
    asyncio.run(generate_historical_data())
