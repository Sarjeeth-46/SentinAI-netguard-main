"""
Project: AegisCore
Module: Attack Simulator / Red Team Tool
Description:
    CLI Utility to inject specific adversarial traffic patterns into the 
    Sentinel detection pipeline. Use this to demonstrate detection capabilities
    or verify dashboard alerts.

Usage:
    python backend/tools/simulate_attack.py --type ddos --count 50
    python backend/tools/simulate_attack.py --type brute_force
"""

import argparse
import sys
import os
import time
import requests

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.run_live_detection import NetworkSentinel
from backend.log_generator import _synthesizer, TrafficCategory

def main():
    parser = argparse.ArgumentParser(description="Simulate Cyber Attacks for Detection Validation")
    parser.add_argument("--type", choices=['ddos', 'brute_force', 'port_scan', 'normal'], required=True, help="Type of attack to simulate")
    parser.add_argument("--count", type=int, default=50, help="Number of packets to generate")
    args = parser.parse_args()

    # Map CLI arg to Internal Category
    category_map = {
        'ddos': TrafficCategory.VOLUMETRIC_DDOS,
        'brute_force': TrafficCategory.AUTH_BRUTE_FORCE,
        'port_scan': TrafficCategory.RECON_SCAN,
        'normal': TrafficCategory.BENIGN
    }
    
    target_category = category_map[args.type]

    print(f"\n[Simulator] Initializing '{args.type.upper()}' Attack Simulation...")
    print(f"[Simulator] Target: {args.count} events")
    
    sentinel = NetworkSentinel()
    
    # Override logic: We will inject forced packets into a custom loop using the Sentinel's pipeline
    # Note: NetworkSentinel.analyze_traffic_burst uses _synthesizer.synthesize_packet() 
    # which we just patched to accept args, BUT `analyze_traffic_burst` doesn't expose it.
    # So we will implement a custom loop here using the Sentinel's components.
    
    detected_count = 0
    print("[Simulator] injecting traffic...")
    
    # We borrow the PERSISTENCE and MODEL from the sentinel instance
    # to ensure consistency with the main app.
    
    batch_events = []

    for i in range(args.count):
        # 1. Synthesize (FORCED)
        telemetry = _synthesizer.synthesize_packet(forced_category=target_category)
        
        # 2. Vectorize
        import pandas as pd
        from backend.detector import TrafficClassifier, RiskAssessmentEngine
        
        raw_frame = pd.DataFrame([{
            'dest_port': telemetry['dest_port'],
            'packet_size': telemetry['packet_size'],
            'protocol': telemetry.get('protocol', 'TCP'),
            'source_country': telemetry.get('source_country', 'UNK'),
            'metadata': telemetry.get('metadata', {})
        }])
        input_vector = TrafficClassifier.vectorize_payload(raw_frame)
        
        # 3. Predict (Using Sentinel's loaded model)
        if sentinel.model:
            prediction = sentinel.model.predict(input_vector)[0]
            probs = sentinel.model.predict_proba(input_vector)[0]
            classes = sentinel.model.classes_
            class_idx = list(classes).index(prediction)
            confidence = probs[class_idx]
            
            # 4. Assess
            risk = RiskAssessmentEngine.compute_severity_index(confidence, prediction)
            
            # 5. Build Record
            import uuid
            incident = {
                "id": str(uuid.uuid4()),
                "timestamp": telemetry['timestamp'],
                "source_ip": telemetry['source_ip'],
                "destination_ip": telemetry['destination_ip'],
                "destination_port": telemetry['dest_port'],
                "protocol": telemetry['protocol'],
                "packet_size": telemetry['packet_size'],
                "source_country": telemetry.get('source_country', 'UNK'),
                "predicted_label": prediction,
                "confidence": float(confidence),
                "risk_score": risk,
                "status": "Active",
                "escalation_flag": False # Simple sim
            }
            batch_events.append(incident)
            
            status_icon = "[ALERT]" if prediction != 'Normal' else "[SAFE]"
            print(f"  {status_icon} Packet {i+1}: {prediction} (Confidence: {confidence:.2f})")
            
            if prediction == target_category:
                detected_count += 1
            
            # --- NOTIFICATION HOOK ---
            # payload matches what the frontend expects (type + data)
            payload = {
                "type": "THREAT_DETECTED",
                "data": incident
            }
            try:
                requests.post("http://127.0.0.1:8000/api/internal/notify", json=payload)
            except Exception as e:
                print(f"  [Simulator] FAILED to send notification: {e}")
            
            time.sleep(0.05) # Rate limit slightly for visual effect

    # 6. Persist
    sentinel.persistence.persist_batch(batch_events)
    
    print(f"\n[Simulator] Batch Complete.")
    print(f"[Simulator] Generated: {args.count}")
    print(f"[Simulator] Verified Detection: {detected_count}")
    print("\nCheck the Dashboard now to see the alerts.")

if __name__ == "__main__":
    main()
