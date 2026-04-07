
import sys
import os
import time
import json
sys.path.append('/app')
from app.engine.correlation_engine import CorrelationEngine
import os
import redis

# Reset Redis Correlation
r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0, decode_responses=True)
r.delete("correlation:logs")
r.delete("correlation:packets")

engine = CorrelationEngine(window_seconds=10)

ip = "3.3.3.3"
print(f"Testing Correlation for {ip}")

# 1. Inject Log Event (SSH)
log_event = {
    "metadata": {"source": "HIDS"},
    "source_ip": ip,
    "label": "SSH Brute Force",
    "timestamp": time.time(),
    "id": "log-123"
}
alert = engine.process_event(log_event)
print(f"Added Log Event via Engine. Alert -> {alert}")
if alert:
    print("FAILURE: Premature Alert.")
    sys.exit(1)

# Check Redis state
logs_cnt = r.zcard("correlation:logs")
if logs_cnt != 1:
    print(f"FAILURE: Log not in Redis ZSET. Count: {logs_cnt}")
    sys.exit(1)

# 2. Inject Packet Event (NIDS)
packet_event = {
    "metadata": {"source": "NIDS"},
    "source_ip": ip,
    "label": "Port Scan",
    "timestamp": time.time(),
    "id": "packet-456"
}
alert = engine.process_event(packet_event)
print(f"Added Packet Event via Engine. Alert -> {alert}")

if not alert:
    print("FAILURE: No Correlation Alert generated.")
    sys.exit(1)

if alert['label'] != "Correlated Attack: Brute Force + Network Scan":
    print(f"FAILURE: Wrong Alert Label: {alert['label']}")
    sys.exit(1)

print("SUCCESS: Correlation Engine Verified with Redis.")
