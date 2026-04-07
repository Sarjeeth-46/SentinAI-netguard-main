
import sys
import os
import time
sys.path.append('/app')
from app.services.log_collector import IPReputationManager
import os
import redis

# Connect to Redis to clear test keys
r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0, decode_responses=True)
ip = "2.2.2.2"
r.delete(f"ip:score:{ip}")
r.delete(f"ip:silence:{ip}")

mgr = IPReputationManager(alert_threshold=10, silence_duration=5)

print(f"Testing IP Reputation for {ip}")

# 1. Simulate 4 attempts (Score 2, 4, 6, 8) -> No Alert
for i in range(1, 5):
    alert, score = mgr.apply_score(ip, 2)
    print(f"Attempt {i}: Alert={alert}, Score={score}")
    if alert:
        print("FAILURE: Triggered too early.")
        sys.exit(1)
    if score != i * 2:
        print(f"FAILURE: Score mismatch. Expected {i*2}, got {score}")
        sys.exit(1)

# 2. Simulate 5th attempt (Score 10) -> Alert!
alert, score = mgr.apply_score(ip, 2)
print(f"Attempt 5: Alert={alert}, Score={score}")
if not alert:
    print("FAILURE: Did not trigger at threshold.")
    sys.exit(1)

# 3. Simulate 6th attempt (Backoff) -> No Alert
alert, score = mgr.apply_score(ip, 2)
print(f"Attempt 6 (Backoff): Alert={alert}, Score={score}")
if alert:
    print("FAILURE: Backoff failed. Triggered again.")
    sys.exit(1)

# 4. Verify Silence Key Exists
if r.exists(f"ip:silence:{ip}"):
    print("SUCCESS: Silence key exists.")
else:
    print("FAILURE: Silence key missing.")
    sys.exit(1)

print("IP Reputation Logic Verified Successfully.")
