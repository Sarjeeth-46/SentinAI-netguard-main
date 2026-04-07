import json
import pandas as pd
import os

THREATS_PATH = 'backend/threats.json'
OUTPUT_DIR = 'backend/Training data'
OUTPUT_FILE = 'current_threats.csv'

def convert():
    if not os.path.exists(THREATS_PATH):
        print("threats.json not found")
        return

    try:
        with open(THREATS_PATH, 'r') as f:
            data = json.load(f)
        
        df = pd.DataFrame(data)
        
        # Ensure label column exists for trainer (it expects 'Label' usually, or lowercase?)
        # Trainer: "df['Label']" (Line 170)
        # Threats.json has "label" (lowercase) based on previous `head`.
        if 'label' in df.columns:
            df.rename(columns={'label': 'Label'}, inplace=True)
            
        # Ensure directory
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        out_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
        df.to_csv(out_path, index=False)
        print(f"Converted {len(df)} records to {out_path}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    convert()
