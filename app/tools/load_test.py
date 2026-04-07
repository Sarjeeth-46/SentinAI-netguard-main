import asyncio
import httpx
import time
import json
import random

API_URL = "http://localhost:8000/api"

def create_payload(batch_size=100):
    batch = []
    for i in range(batch_size):
        batch.append({
            "source_ip": f"192.168.1.{random.randint(1, 254)}",
            "dest_ip": f"10.0.0.{random.randint(1, 254)}",
            "dest_port": random.choice([22, 80, 443, 53, 3306]),
            "timestamp": time.time(),
            "packet_size": random.randint(40, 1500),
            "protocol": random.choice(["TCP", "UDP"]),
            "flow_duration": random.uniform(0.1, 5.0),
            "total_fwd_packets": random.randint(1, 10),
            "total_l_fwd_packets": random.randint(100, 5000),
            "metadata": {"source": "LoadTest"}
        })
    return batch

async def send_batch(client, batch):
    # Retrieve api key from config ideally, or mock
    # Hardcoding secure-telemetry-key-123 for default dev
    headers = {"X-API-Key": "secure-telemetry-key-123"}
    try:
        response = await client.post(f"{API_URL}/telemetry", headers=headers, json=batch)
        return response.status_code
    except Exception as e:
        return str(e)

async def main():
    total_events = 2000
    batch_size = 100
    batches = total_events // batch_size

    print(f"Starting Load Test: {total_events} events in batches of {batch_size}")
    start_time = time.time()
    
    async with httpx.AsyncClient() as client:
        tasks = []
        # We will stagger the requests slightly to simulate concurrent spikes
        for i in range(batches):
            tasks.append(send_batch(client, create_payload(batch_size)))
        
        results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"--- Load Test Results ---")
    print(f"Total time: {duration:.2f} seconds")
    print(f"Throughput: {total_events / duration:.2f} events/second")
    
    status_counts = {}
    for r in results:
        status_counts[r] = status_counts.get(r, 0) + 1
        
    for status, count in status_counts.items():
        print(f"[{status}]: {count} batches ({count * batch_size} events)")
        
    if 201 not in status_counts or status_counts.get(201, 0) < batches * 0.9:
        print("\n[WARNING] Load test experienced significant failures or rate limiting.")
    else:
        print("\n[SUCCESS] Load test passed gracefully.")

if __name__ == "__main__":
    asyncio.run(main())
