import asyncio
import logging
import sys
# Configure simple stdout logging so we can see the structlog output
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

from app.ingestion.log_collector import LogCollector

async def main():
    print("--- Starting LogCollector Detection Test ---")
    collector = LogCollector()
    await collector.open()

    try:
        from app.services.ip_reputation import ip_reputation_manager
        if ip_reputation_manager._client:
            print("Flushing test Redis database...")
            ip_reputation_manager._client.flushdb()
    except Exception as e:
        print(f"Skipping Redis flush: {e}")

    # Disable network push_alert so it doesn't complain about API not running
    async def mock_push(alert):
        print(f"\n>> MOCK PUSH_ALERT: {alert['label']} (Risk {alert['risk_score']}) <<")
        print(f"   Details: {alert['details']}")
    
    collector.push_alert = mock_push

    try:
        ip = "9.9.9.9"
        user = "admin"
        
        # Test 1: Normal Login (No prior failures, should NOT alert)
        print("\n[TEST] 1. Normal Login")
        await collector.process_line(f"Accepted password for {user} from {ip} port 22 ssh2")
        await asyncio.sleep(0.5)

        # Test 2: Duplicate Suppression
        print("\n[TEST] 2. Duplicate Suppression")
        line = f"Failed password for {user} from {ip} port 22 ssh2"
        await collector.process_line(line)
        await collector.process_line(line) # Should skip
        await asyncio.sleep(0.5)

        # Test 3: Brute Force Attempt (5 failures from same IP)
        print("\n[TEST] 3. Brute Force Attempt (5 failures)")
        # We did 1 failure above (the duplicate didn't count in aggregator since it was dropped)
        for i in range(2, 6):
            # Vary the port slightly to bypass dedup filter
            await collector.process_line(f"Failed password for {user} from {ip} port 22{i} ssh2")

        await asyncio.sleep(0.5)

        # Test 4: Brute Force Compromise (Success AFTER 5 failures)
        print("\n[TEST] 4. Brute Force Compromise")
        # Generate 5 more failures to hit threshold again (since threshold resets on alert)
        for i in range(6, 11):
            await collector.process_line(f"Failed password for {user} from {ip} port 22{i} ssh2")
            
        print("   --- injecting success now ---")
        await collector.process_line(f"Accepted password for {user} from {ip} port 22 ssh2")
        
    finally:
        await collector.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
