"""
Project: SentinAI NetGuard
Module: Live Monitor Service
Description: Orchestrates the continuous simulation and detection loop.
             Generates stochastic traffic, runs inference, and persists results to the database.
License: MIT / Academic Use Only
"""
import time
import requests
import random
import os
from datetime import datetime
from pymongo import MongoClient

# Import new clean architecture components
from backend.tools.traffic_simulator import NetworkTrafficGenerator
from backend.engine.inference import InferenceEngine
from backend.core.config import config

class LiveMonitor:
    """Main loop for the live detection system."""
    
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.DB_NAME]
        self.collection = self.db[config.COLLECTION_NAME]
        print(f"[Monitor] Connected to DB: {config.DB_NAME}")

    def run(self, interval=2.0):
        print(f"[Monitor] Starting detection loop (Interval: {interval}s)...")
        # Initialize generator with lambda=0.5 (avg 1 packet every 2s)
        generator = NetworkTrafficGenerator(lambda_rate=1/interval)
        
        while True:
            try:
                # 1. Generate Traffic using Stochastic Model
                packet = generator.generate_telemetry_payload()
                
                # 2. Inference
                prediction = InferenceEngine.predict(packet)
                
                # 3. Enrich Log
                log_entry = {
                    **packet,
                    "predicted_label": prediction["label"],
                    "confidence": prediction["confidence"],
                    "risk_score": prediction["risk_score"],
                    "status": "Active",
                    "source_country": random.choice(["USA", "CHN", "RUS", "DEU", "BRA", "IND", "FRA"]) # Simulated GeoIP lookup (ISO-3)
                }
                
                # 4. Action (Auto-block high risk?)
                if prediction["risk_score"] > 90:
                    print(f"!!! CRITICAL BLOCK: {log_entry['source_ip']} [{prediction['label']}]")
                    # In real system: Call Firewall API
                
                # 5. Persist
                self.collection.insert_one(log_entry)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Processed: {prediction['label']} ({prediction['risk_score']}) -> {packet['dest_ip']}")
                
                # Wait based on Poisson Inter-arrival time (optional, or fixed interval)
                # usage: time.sleep(generator._get_next_inter_arrival_time())
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[Monitor] Stopping...")
                break
            except Exception as e:
                print(f"[Monitor] Error: {e}")
                time.sleep(1)

if __name__ == "__main__":
    monitor = LiveMonitor()
    monitor.run()
