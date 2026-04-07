import json
import pandas as pd
from collections import Counter
import os
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

THREATS_PATH = 'backend/threats.json'
from app.core.config import config
MODEL_PATH = config.MODEL_PATH

def analyze_data():
    print("--- Dataset Analysis ---")
    if not os.path.exists(THREATS_PATH):
        print("threats.json not found.")
        return

    try:
        with open(THREATS_PATH, 'r') as f:
            data = json.load(f)
        
        df = pd.DataFrame(data)
        target_col = 'label' if 'label' in df.columns else 'attack_type'
        
        if target_col not in df.columns:
            print(f"No '{target_col}' column found.")
            return

        counts = df[target_col].value_counts()
        total = len(df)
        print(f"Total Records: {total}")
        print("\nClass Distribution:")
        print(counts)
        
        print("\nImbalance Check:")
        for label, count in counts.items():
            pct = (count / total) * 100
            print(f"  - {label}: {pct:.2f}%")
        
        # Check for extreme imbalance
        min_pct = (counts.min() / total) * 100
        if min_pct < 5: # Arbitrary threshold
            print(f"\n[WARNING] Dataset is Imbalanced! '{counts.idxmin()}' has only {min_pct:.2f}% of samples.")
        else:
            print("\nDataset seems reasonably balanced (smallest class > 5%).")

    except Exception as e:
        print(f"Error analyzing data: {e}")

if __name__ == "__main__":
    analyze_data()
