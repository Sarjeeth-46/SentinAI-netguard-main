from backend.log_generator import _synthesizer, ThreatSignature
import json
import os

THREATS_PATH = 'backend/threats.json'

def augment_data():
    if not os.path.exists(THREATS_PATH):
        print("threats.json not found")
        return

    with open(THREATS_PATH, 'r') as f:
        current_data = json.load(f)
        
    print(f"Current Count: {len(current_data)}")

    # Augment Exfiltration (Target: +200)
    print("Augmenting Exfiltration (+200)...")
    for _ in range(200):
        log = _synthesizer.synthesize_artifact(forced_category=ThreatSignature.DATA_EXFILTRATION)
        # Backfill required fields for consistency
        log['predicted_label'] = log['label']
        if 'source_country' not in log: log['source_country'] = "UNK"
        current_data.append(log)
        
    # Augment Brute Force (Target: +100)
    print("Augmenting Brute Force (+100)...")
    for _ in range(100):
        log = _synthesizer.synthesize_artifact(forced_category=ThreatSignature.AUTH_BRUTE_FORCE)
        log['predicted_label'] = log['label']
        if 'source_country' not in log: log['source_country'] = "UNK"
        current_data.append(log)

    with open(THREATS_PATH, 'w') as f:
        json.dump(current_data, f, indent=2)
        
    print(f"New Count: {len(current_data)}")
    print("Augmentation Complete.")

if __name__ == "__main__":
    augment_data()
