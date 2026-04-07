import asyncio
import httpx
import os
import time

API_URL = "http://localhost:8000/api"
API_KEY = "secure-telemetry-key-123"

async def test_invalid_telemetry_payload(client: httpx.AsyncClient):
    print("Injecting Fault: Invalid Telemetry Payload")
    headers = {"X-API-Key": API_KEY}
    # Send a dictionary instead of a list, or missing fields
    bad_payload = {"this_is": "broken"}
    r = await client.post(f"{API_URL}/telemetry", headers=headers, json=bad_payload)
    print(f"Result (Should be 422): {r.status_code}")
    assert r.status_code == 422
    print("-> System handled invalid payload gracefully.")

async def test_api_spam(client: httpx.AsyncClient):
    print("Injecting Fault: API Spam (Rate Limit Check)")
    headers = {"X-API-Key": API_KEY}
    # 1000/second limit. We will burst
    tasks = []
    # Just 1500 concurrent to test the limit
    for i in range(1500):
        tasks.append(client.post(f"{API_URL}/telemetry", headers=headers, json=[]))
    
    start_time = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    end_time = time.time()
    
    statuses = [r.status_code for r in results if hasattr(r, 'status_code')]
    limits = statuses.count(429)
    success = statuses.count(201)
    
    print(f"Spam resulted in - 201s: {success}, 429s (Rate Limited): {limits} in {end_time-start_time:.2f}s")
    if limits > 0:
         print("-> System correctly rate-limited API spam.")
    elif success == 1500:
         print("-> System handled 1500 connections concurrently (or limit is disabled).")
         
async def test_corrupted_model():
    print("Injecting Fault: Corrupted ML Model File")
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
    
    # Backup original
    import shutil
    model_path = "backend/xgboost_detector.pkl"
    backup = "backend/xgboost_detector.pkl.bak"
    if os.path.exists(model_path):
        shutil.copy(model_path, backup)
    
    try:
        # Write junk
        with open(model_path, 'w') as f:
            f.write("junk data that is not a pickle file")
            
        # load model
        from backend.ml_pipeline.evaluator import CyberSecurityModelEvaluator
        evaluator = CyberSecurityModelEvaluator(model_path=model_path)
        
        if getattr(evaluator, 'model', None) is None:
            print("-> System gracefully caught corrupted model and defaulted to None/Fallback.")
        else:
            print("-> [FAIL] System tried to load a corrupted model!")
    finally:
        # restore
        if os.path.exists(backup):
            shutil.move(backup, model_path)

async def test_db_offline():
    print("Injecting Fault: Simulate DB Offline")
    # By disconnecting MongoDB, the engine should rely on local fallback JSON
    from backend.core.database import db
    
    # Force mock mode
    db.set_mode(True)
    try:
        await db.dal.save_event({"id": "fault-1", "test": "offline"})
        result = await db.dal.query_security_events(limit=1)
        assert len(result) >= 1
        print("-> System gracefully maintained state using fallback JSON during DB offline.")
    finally:
         db.set_mode(False)

async def main():
    print("--- FAULT INJECTION SUITE ---")
    async with httpx.AsyncClient(timeout=30) as client:
        await test_invalid_telemetry_payload(client)
        await test_api_spam(client)
        
    await test_corrupted_model()
    await test_db_offline()
    print("--- FAULT INJECTION COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main())
