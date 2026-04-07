import pandas as pd
import numpy as np
import glob
import os
import joblib
import zipfile
import json
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE

# Configuration
# Run from backend/tools/
# Data is in root/Training data (../../Training data)
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Training data")

import sys
# Ensure app root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from app.core.config import config

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = config.MODEL_PATH
METRICS_PATH = config.METRICS_PATH
FEATURES_PATH = os.path.join(BACKEND_DIR, "feature_importance.json")
FEATURE_NAMES_PATH = config.FEATURES_PATH

def load_and_process_data():
    print("Generating synthetic training data...")
    
    # Generate Normal Traffic
    n_normal = 1000
    normal_data = {
        'dest_port': np.random.randint(80, 443, n_normal),
        'flow_duration': [0] * n_normal,
        'total_fwd_packets': [1] * n_normal,
        'total_l_fwd_packets': np.random.randint(50, 1500, n_normal), 
        'packet_size': np.random.randint(50, 1500, n_normal),
        'label_mapped': ['Normal'] * n_normal
    }
    normal_data['total_l_fwd_packets'] = normal_data['packet_size']
    
    # Generate DDoS Traffic (Aligned with Log Generator)
    n_ddos = 500
    ddos_packet_sizes = np.random.randint(3000, 3100, n_ddos)
    ddos_data = {
        'dest_port': np.random.choice([80, 443, 8443], n_ddos),
        'flow_duration': [0] * n_ddos,
        'total_fwd_packets': [1] * n_ddos,
        'total_l_fwd_packets': ddos_packet_sizes,
        'packet_size': ddos_packet_sizes,
        'label_mapped': ['DDoS'] * n_ddos
    }

    # Generate Port Scan Traffic
    n_scan = 500
    scan_data = {
        'dest_port': np.random.randint(1, 65535, n_scan),
        'flow_duration': [0] * n_scan,
        'total_fwd_packets': [1] * n_scan,
        'total_l_fwd_packets': [0] * n_scan,
        'packet_size': [0] * n_scan,
        'label_mapped': ['Port Scan'] * n_scan
    }
    
    # Generate Brute Force Traffic 
    n_bf = 500
    bf_data = {
        'dest_port': np.random.choice([22, 3389, 5432], n_bf),
        'flow_duration': [0] * n_bf,
        'total_fwd_packets': [1] * n_bf,
        'total_l_fwd_packets': np.random.randint(2000, 2100, n_bf),
        'packet_size': np.random.randint(2000, 2100, n_bf),
        'label_mapped': ['Brute Force'] * n_bf
    }
    bf_data['total_l_fwd_packets'] = bf_data['packet_size']


    df_normal = pd.DataFrame(normal_data)
    df_ddos = pd.DataFrame(ddos_data)
    df_scan = pd.DataFrame(scan_data)
    df_bf = pd.DataFrame(bf_data)
    
    full_df = pd.concat([df_normal, df_ddos, df_scan, df_bf], ignore_index=True)
    
    print(f"Total processed samples: {len(full_df)}")
    print(full_df['label_mapped'].value_counts())
    
    return full_df

def train():
    df = load_and_process_data()
    if df is None:
        print("Training aborted.")
        return

    feature_cols = ['dest_port', 'flow_duration', 'total_fwd_packets', 'total_l_fwd_packets', 'packet_size']
    X = df[feature_cols]
    y = df['label_mapped']
    
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    print("\n--- Feature Statistics ---")
    print(df.groupby('label_mapped')[feature_cols].mean())
    print("--------------------------\n")

    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest (n_estimators=100)...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
    rf.fit(X_train, y_train)
    
    print("Evaluating...")
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save Metrics
    report = classification_report(y_test, y_pred, output_dict=True)
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": report['weighted avg']['precision'],
        "recall": report['weighted avg']['recall'],
        "f1_score": report['weighted avg']['f1-score']
    }
    
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f)
    print(f"Metrics saved to {METRICS_PATH}")
    
    # Save Model
    import sklearn
    model_artifact = {
        "model": rf,
        "metadata": {
            "model_version": "2.0.0",
            "sklearn_version_training": sklearn.__version__
        }
    }
    joblib.dump(model_artifact, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    
    # Save Features
    with open(FEATURE_NAMES_PATH, 'w') as f:
        json.dump(feature_cols, f)

    importances = rf.feature_importances_
    feature_importance = [
        {"name": col, "importance": float(imp)} 
        for col, imp in zip(feature_cols, importances)
    ]
    feature_importance.sort(key=lambda x: x['importance'], reverse=True)
    
    with open(FEATURES_PATH, 'w') as f:
        json.dump(feature_importance, f, indent=2)
    print(f"Feature importance saved to {FEATURES_PATH}")

if __name__ == "__main__":
    train()
