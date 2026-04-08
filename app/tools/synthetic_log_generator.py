import asyncio
import aiohttp
import json
import random
import time
import uuid
import sys
from datetime import datetime, timezone

# Target Backend URL
API_URL = "http://localhost:8001/api/telemetry"
API_KEY = "secure-telemetry-key-123"

# Traffic Profiles
ATTACK_TYPES = ["DDoS", "Port Scan", "Brute Force"]
SUBNETS = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."]

def generate_ip():
    return f"{random.choice(SUBNETS)}{random.randint(2, 254)}"

def generate_log_entry():
    """Generates a single synthetic log entry with ML-relevant features."""
    is_attack = random.random() < 0.2  # 20% chance of anomaly
    
    label = "Normal"
    src_ip = generate_ip()
    dest_ip = "10.0.0.5" # Internal protected server
    dest_port = 443
    packet_size = random.randint(40, 1500)
    
    if is_attack:
        label = random.choice(ATTACK_TYPES)
        if label == "DDoS":
            packet_size = random.randint(40, 100)
            dest_port = 80
        elif label == "Port Scan":
            packet_size = random.randint(40, 60)
            dest_port = random.randint(1, 65535)
        elif label == "Brute Force":
            packet_size = random.randint(200, 500)
            dest_port = 22
            
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "protocol": "TCP" if dest_port in [22, 80, 443] else "UDP",
        "packet_size": packet_size,
        "dest_port": dest_port,
        "label": label,  # Optional "ground truth" to simulate an external tagging/evaluation system
    }

async def send_logs(session, logs):
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    try:
        async with session.post(API_URL, headers=headers, json=logs) as response:
            if response.status in [200, 201]:
                data = await response.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SUCCESS] {data['count']} logs ingested.")
            else:
                text = await response.text()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [FAILED] HTTP {response.status} - {text}")
    except aiohttp.ClientError as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] Connection Error: {e}")

async def log_stream_loop(batch_size=5, interval=0.5):
    """Continuously generates and streams logs to the backend."""
    print("=========================================")
    print(" SENTINAI SYSTEM - LIVE LOG GENERATOR")
    print(f" Target: {API_URL}")
    print(f" Batch Size: {batch_size} logs")
    print(f" Interval: {interval}s")
    print(" Press Ctrl+C to stop.")
    print("=========================================\n")
    
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                # Generate a batch of synthetic logs
                logs = [generate_log_entry() for _ in range(batch_size)]
                
                # Push asynchronously
                await send_logs(session, logs)
                
                # Wait before next tick
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Generatror Exception: {e}")

if __name__ == "__main__":
    interval = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
    batch_size = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    
    try:
        asyncio.run(log_stream_loop(batch_size=batch_size, interval=interval))
    except KeyboardInterrupt:
        print("\nLog streaming interrupted. Shutting down.")
