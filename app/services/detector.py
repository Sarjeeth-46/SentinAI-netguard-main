"""
Project: SentinAI NetGuard
Module: Inference Engine
Description:
    Core decision-making unit that orchestrates Feature Vectorization and 
    Risk Probability Scoring.
    
    Novelty:
    - Implements a "Hybrid Severity Index" that combines raw model confidence
      with domain-specific weightings for attack categories.
    - Handles feature imputation strategies (Zero-Fill vs Mean-Fill).
"""

import pandas as pd
import numpy as np
import logging
import json

# Severity Weights based on NIST Impact Ratings
# High Impact = 1.0, Low Impact = 0.5
THREAT_GRAVITY_MATRIX = {
    'Normal': 0.0,
    'DDoS': 0.95,        # High Availability Impact
    'Brute Force': 0.85, # High Integrity Impact
    'Port Scan': 0.45,   # Low Confidentiality Impact
    'Exfiltration': 1.0  # Critical Confidentiality Impact
}

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("SentinAIInference")

class SentinAIInferenceCore:
    """
    Transforms raw telemetry into feature vectors compatible with the 
    High-Dimensional Random Forest model.
    """
    REQUIRED_FEATURES = [
        'dest_port', 
        'flow_duration', 
        'total_fwd_packets', 
        'total_l_fwd_packets', 
        'packet_size',
        'protocol_num',
        'chaos_factor',
        'country_code'
    ]
    
    _COUNTRY_MAP = None

    @staticmethod
    def _load_country_map():
        if SentinAIInferenceCore._COUNTRY_MAP is None:
            try:
                import os
                # Assuming relative to backend root or similar. 
                # Ideally config.BASE_DIR, but we imports strictly.
                # Trying absolute path based on known structure or relative to file.
                base_dir = os.path.dirname(os.path.abspath(__file__))
                map_path = os.path.join(base_dir, "country_map.json")
                if os.path.exists(map_path):
                    with open(map_path, 'r') as f:
                        SentinAIInferenceCore._COUNTRY_MAP = json.load(f)
                else:
                    logger.warning(f"Country Map not found at {map_path}. Using empty map.")
                    SentinAIInferenceCore._COUNTRY_MAP = {}
            except Exception as e:
                logger.error(f"Failed to load country map: {e}")
                SentinAIInferenceCore._COUNTRY_MAP = {}
        return SentinAIInferenceCore._COUNTRY_MAP

    @staticmethod
    def transform_telemetry(telemetry_frame: pd.DataFrame) -> pd.DataFrame:
        """
        Feature Engineering Pipeline.
        1. Aligns columns with Training Schema.
        2. Imputes missing complexity metrics.
        3. Encodes categorical features (Protocol, Country).
        4. Extracts synthetic signals (Chaos Factor).
        """
        # Create Deep Copy
        vector = telemetry_frame.copy()
        
        # --- 1. Imputation ---
        if 'flow_duration' not in vector.columns:
            vector['flow_duration'] = 0
        if 'total_fwd_packets' not in vector.columns:
            vector['total_fwd_packets'] = 1
        if 'total_l_fwd_packets' not in vector.columns:
            # If packet_size exists, use it
            if 'packet_size' in vector.columns:
                vector['total_l_fwd_packets'] = vector['packet_size']
            else:
                vector['total_l_fwd_packets'] = 0
        
        if 'packet_size' not in vector.columns:
             vector['packet_size'] = vector['total_l_fwd_packets']

        # --- 2. Protocol Encoding ---
        # Map: {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'SCTP': 132}
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'SCTP': 132}
        if 'protocol' in vector.columns:
            # Handle string case insensitivity
            vector['protocol_num'] = vector['protocol'].astype(str).str.upper().map(protocol_map).fillna(0)
        else:
            vector['protocol_num'] = 0
            
        # --- 3. Chaos Factor Extraction ---
        if 'metadata' in vector.columns:
            import ast
            def extract_chaos(x):
                try:
                    # Handle raw dict or string representation
                    if isinstance(x, dict):
                        return float(x.get('chaos_factor', 0))
                    s = str(x).replace('np.float64(', '').replace(')', '')
                    d = ast.literal_eval(s)
                    return float(d.get('chaos_factor', 0))
                except Exception as e:
                    logger.error(f"Cannot decode feature map: {e}", exc_info=True)
            vector['chaos_factor'] = vector['metadata'].apply(extract_chaos)
        else:
            vector['chaos_factor'] = 0.0
            
        # --- 4. Country Encoding ---
        country_map = SentinAIInferenceCore._load_country_map()
        if 'source_country' in vector.columns:
            vector['country_code'] = vector['source_country'].astype(str).map(country_map).fillna(0) # Default to 0 if unknown
        else:
            vector['country_code'] = 0
            
        vector = vector.copy() 
        
        # Ensure all columns exist
        for feature in SentinAIInferenceCore.REQUIRED_FEATURES:
            if feature not in vector.columns:
                vector[feature] = 0.0
        
        final_vector = vector[SentinAIInferenceCore.REQUIRED_FEATURES].fillna(0)
            
        return final_vector

class HeuristicRiskEngine:
    """
    Post-Processing Logic Layer.
    Adjusts the raw ML probabilities/log-odds into a normalized 0-100 Service Level Indicator (SLI).
    """
    
    @staticmethod
    def calculate_entropy_score(probabilities: list) -> float:
        """
        Calculates Shannon Entropy of the prediction distribution to measure uncertainty.
        High entropy = Model checks multiple classes = Lower Confidence.
        """
        import scipy.stats
        return scipy.stats.entropy(probabilities)

    @staticmethod
    def compute_severity_index(confidence_score: float, category_label: str) -> float:
        """
        Derives the base Threat Severity Score.
        """
        weight_factor = THREAT_GRAVITY_MATRIX.get(category_label, 0.5)
        raw_score = confidence_score * weight_factor * 100.0
        return round(min(max(raw_score, 0.0), 100.0), 2)

class WeightedRiskScorer:
    """
    Implements the risk assessment based on weighted scoring using severity,
    asset criticality, and historical behavior, as defined in the paper.
    Formula: Risk Score = (w1 * Threat Severity) + (w2 * Asset Criticality) + (w3 * Historical Behavior)
    """
    W1 = 0.5  # Threat Severity Weight
    W2 = 0.3  # Asset Criticality Weight
    W3 = 0.2  # Historical Behavior Weight

    _ASSET_CRITICALITY_MAP = {
        "10.0.0.5": 90.0, # e.g. Database Server
        "10.0.0.10": 80.0, # e.g. Web Server
        "127.0.0.1": 50.0  # Localhost
    }

    @classmethod
    def calculate_risk(cls, severity: float, dest_ip: str, repeat_offender_count: int) -> float:
        """
        Calculates the comprehensive risk score.
        """
        # 1. Threat Severity (0-100)
        threat_severity = severity

        # 2. Asset Criticality (0-100)
        asset_criticality = cls._ASSET_CRITICALITY_MAP.get(dest_ip, 50.0) # Default to medium criticality

        # 3. Historical Behavior (0-100)
        # Scale repeat faults to a max of 100 for historical behavior component
        historical_behavior = min(repeat_offender_count * 20.0, 100.0)

        # Calculate weighted sum
        final_risk = (cls.W1 * threat_severity) + (cls.W2 * asset_criticality) + (cls.W3 * historical_behavior)

        # Clamp
        return round(min(max(final_risk, 0.0), 100.0), 2)

# Legacy Aliases for Backward Compatibility with 'run_live_detection.py'
TrafficClassifier = SentinAIInferenceCore
RiskAssessmentEngine = HeuristicRiskEngine
TrafficClassifier.vectorize_payload = SentinAIInferenceCore.transform_telemetry

# Legacy Adapter Functions for Backward Compatibility
def preprocess_data(df: pd.DataFrame):
    """Legacy wrapper for TrafficClassifier.vectorize_payload."""
    return TrafficClassifier.vectorize_payload(df), None, None

def calculate_risk_score(probability: float, attack_type: str) -> float:
    """Legacy wrapper for RiskAssessmentEngine.compute_severity_index."""
    return RiskAssessmentEngine.compute_severity_index(probability, attack_type)

def train_model(data_path: str = 'backend/training_data.csv'):
    """
    Placeholder. Actual training logic has been moved to 'train_model_real.py'.
    Exposing this warns the operator to use the correct pipeline.
    """
    logger.warning("Legacy training entry point called. Use 'train_model_real.py' for production pipelines.")
    
    # Generate static explainability artifact for UI demo if needed
    static_explainability = [
        {"name": "Packet Size", "importance": 0.65},
        {"name": "Destination Port", "importance": 0.35}
    ]
    
    try:
        with open('backend/feature_importance.json', 'w') as f:
            json.dump(static_explainability, f)
    except IOError as e:
        logger.error(f"Failed to write feature importance artifact: {e}")

if __name__ == "__main__":
    train_model()
