
import redis
import time
import sys

# Connect to Redis
try:
    r = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0, decode_responses=True)
    r.ping()
    print("Connected to Redis.")
except Exception as e:
    print(f"Failed to connect to Redis: {e}")
    sys.exit(1)

# Test Aggregation Logic Simulation
key = "ssh_fail:1.1.1.1"
r.delete(key)

print(f"Testing Key: {key}")

# Simulating 5 attempts
for i in range(1, 6):
    count = r.incr(key)
    if count == 1:
        r.expire(key, 5) # 5 second window for test
    print(f"Attempt {i}: Count={count}, TTL={r.ttl(key)}")
    time.sleep(0.5)

# Verify Expiry
print("Waiting for expiry (6s)...")
time.sleep(6)
exists = r.exists(key)
print(f"Key Exists after expiry? {bool(exists)}")

if not exists:
    print("SUCCESS: Redis Aggregation Logic verified.")
else:
    print("FAILURE: Key did not expire.")
    sys.exit(1)
