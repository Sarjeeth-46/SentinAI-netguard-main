import joblib
import pandas as pd
import json
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from app.core.config import config
MODEL_PATH = config.MODEL_PATH
DATA_PATH = 'backend/threats.json'

def analyze_model():
    print("--- Model Performance Analysis ---")
    try:
        # Load Data
        with open(DATA_PATH, 'r') as f:
            data = json.load(f)
        df = pd.DataFrame(data)
        
        # Features & Target
        # Assuming trainer.py features. Need to match exactly what the model expects.
        # Let's try to load the model and check expected features if possible, 
        # or just use the known feature set from previous steps.
        feature_cols = ['packet_size', 'dest_port'] # Minimal set based on threats.json
        # Wait, trainer.py uses more. Let's check trainer.py to be sure.
        # But for now, let's just try to load the metrics file if it exists, 
        # as calculating it raw might require exact preprocessing steps.
        
        metrics_path = 'backend/model_metrics.json'
        if os.path.exists(metrics_path):
             with open(metrics_path, 'r') as f:
                 metrics = json.load(f)
                 print(json.dumps(metrics, indent=2))
                 return

        print("No pre-computed metrics found. Attempting to reconstitute...")
        # If no metrics file, we can't easily reproduce the exact test set without the random seed state.
        # So we will just report the imbalance found earlier and suggest retraining if metrics are missing.
        print("Metrics file missing. Please run training to generate fresh metrics.")

    except Exception as e:
        print(f"Error: {e}")

import os
if __name__ == "__main__":
    analyze_model()
