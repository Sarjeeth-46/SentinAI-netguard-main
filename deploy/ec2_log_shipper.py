import asyncio
import aiohttp
import os
import random
import time
import uuid
import sys
import hmac
import hashlib
import json
from datetime import datetime, timezone

# --- CONFIGURATION ---
# Export this in your Ubuntu terminal: export TARGET_API_URL=https://<YOUR_DOMAIN>:8001/api/telemetry
API_URL = os.getenv("TARGET_API_URL", "https://localhost:8001/api/telemetry")
SHARED_SECRET = os.getenv("TELEMETRY_SHARED_SECRET", "dev-hmac-shared-secret-1234567890")
AWS_REGION = "us-east-1"
EC2_INTERNAL_IP = "172.31.38.172"

# Traffic Profiles
ATTACK_TYPES = ["DDoS", "Port Scan", "Brute Force"]
SUBNETS = ["192.168.1.", "172.16.0.", "203.0.113.", "8.8.8.", "8.8.4."]

# SentinAI Internal Topology Targets (allows Network Topology map to light up dynamically)
TARGET_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "10.0.5"]

def generate_ip():
    return f"{random.choice(SUBNETS)}{random.randint(2, 254)}"

def generate_target_ip():
    subnet = random.choice(TARGET_SUBNETS)
    host = random.randint(10, 14) # Internal nodes map to .10 through .14
    if subnet == "10.0.5" and host == 10:
        return "10.0.5.5" # Ensures the primary TARGET_SERVER_IP default hits
    return f"{subnet}.{host}"

# Geo mapping for global threat map
COUNTRIES = ["USA", "CHN", "RUS", "BRA", "IND", "DEU", "GBR", "FRA", "JPN", "KOR", "CAN", "AUS"]

def generate_log_entry():
    """Generates a single synthetic log entry mapped to SentinAI's LogEntryPayloadDTO."""
    # Cycle through 4 periods based on time (15-second intervals) to cluster attacks visually
    # 0 = Normal Traffic, 1 = DDoS, 2 = Port Scan, 3 = Brute Force
    elapsed = int(time.time())
    period = (elapsed // 15) % 4
    
    is_attack = False
    label = "Normal"
    
    # 5% ambient threat noise
    if random.random() < 0.05:
        is_attack = True
        label = random.choice(ATTACK_TYPES)
        
    # Periodic focused simulation
    if period == 1 and random.random() < 0.3:
        is_attack = True
        label = "DDoS"
    elif period == 2 and random.random() < 0.3:
        is_attack = True
        label = "Port Scan"
    elif period == 3 and random.random() < 0.3:
        is_attack = True
        label = "Brute Force"
        
    src_ip = generate_ip()
    dest_ip = generate_target_ip()
    dest_port = 443
    packet_size = random.randint(40, 1500)
    source_country = random.choice(COUNTRIES)
    
    if is_attack:
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
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_country": source_country,
        "protocol": "TCP" if dest_port in [22, 80, 443] else "UDP",
        "packet_size": packet_size,
        "dest_port": dest_port,
        "label": label,
        "metadata": {
            "origin": "aws-ec2-shipper",
            "region": AWS_REGION,
            "source_country": source_country
        }
    }

async def send_logs(session, logs):
    if not API_URL.startswith("https://") and "localhost" not in API_URL and "127.0.0.1" not in API_URL:
        print("[WARNING] API_URL does not use HTTPS. Production traffic must be encrypted!")

    payload = json.dumps(logs)
    timestamp = str(time.time())
    
    # Message = timestamp + payload
    message = timestamp.encode() + payload.encode()
    signature = hmac.new(SHARED_SECRET.encode(), message, hashlib.sha256).hexdigest()
    
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Signature": signature
    }
    try:
        async with session.post(API_URL, headers=headers, data=payload, timeout=5) as response:
            if response.status in [200, 201]:
                data = await response.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SUCCESS] {data.get('count', len(logs))} logs sent to {API_URL}")
            else:
                text = await response.text()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [FAILED] HTTP {response.status} - {text}")
    except aiohttp.ClientError as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] Connection Error to {API_URL}: {e}")
    except asyncio.TimeoutError:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] Timeout waiting for backend at {API_URL}")

async def log_stream_loop(batch_size=5, min_interval=4.0, max_interval=7.0):
    print("=========================================")
    print(" SENTINAI EC2 LOG SHIPPER")
    print(f" Target API: {API_URL}")
    print(f" Batch Size: {batch_size} logs")
    print(f" Interval: Random between {min_interval}s - {max_interval}s")
    print(" Press Ctrl+C to stop.")
    print("=========================================\n")
    
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                logs = [generate_log_entry() for _ in range(batch_size)]
                await send_logs(session, logs)
                sleep_time = random.uniform(min_interval, max_interval)
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[FATAL] Generator Exception: {e}")
                await asyncio.sleep(2)

if __name__ == "__main__":
    # Usage: python3 ec2_log_shipper.py <min_interval> <max_interval> <batch_size>
    min_interval = float(sys.argv[1]) if len(sys.argv) > 1 else 4.0
    max_interval = float(sys.argv[2]) if len(sys.argv) > 2 else 7.0
    batch_size = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    try:
        asyncio.run(log_stream_loop(batch_size=batch_size, min_interval=min_interval, max_interval=max_interval))
    except KeyboardInterrupt:
        print("\nShipper interrupted. Shutting down gracefully.")
