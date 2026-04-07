"""
Project: AegisCore
Module: Network Sentinel (Live Monitor)
Description:
    The persistent surveillance loop that orchestrates the flow of synthetic
    telemetry through the inference engine and persists actionable intelligence
    to the data layer.

    Optimization:
    - Loads Model ONCE at startup (Singleton).
    - Batches DB writes for efficiency.
"""

import pandas as pd
import joblib
import time
import uuid
import os
import json
import logging
import asyncio
import structlog
from datetime import datetime
from dotenv import load_dotenv
from prometheus_client import Histogram

INFERENCE_LATENCY = Histogram(
    'ml_inference_latency_seconds',
    'Time spent running the ML inference model',
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
)

# Internal Modules
from app.services.detector import TrafficClassifier, RiskAssessmentEngine, calculate_risk_score
# InferenceEngine provides ML path + deterministic fallback when model absent
from app.services.ml_service import InferenceEngine

load_dotenv()

# Logger Configuration
logger = structlog.get_logger()

class NetworkSentinel:
    """
    The Active Monitoring Agent.
    """
    def __init__(self):
        # Trigger InferenceEngine to load (or access existing) model shared instance
        InferenceEngine.load_model()
        self.model = InferenceEngine._model
        self.offender_history = {} # In-memory state for temporal correlation

    async def process_telemetry_batch(self, telemetry_batch: list):
        """
        Ingests and analyzes a batch of telemetry records pushed from VM1.

        When self.model is None (model artifact absent/corrupt), each record
        is classified by InferenceEngine.predict() which internally delegates
        to DeterministicRuleEngine — ensuring continuous threat coverage.
        """
        if not telemetry_batch:
            return

        _use_ml_path = self.model is not None

        logger.info("Processing telemetry batch", count=len(telemetry_batch))
        
        detected_incidents = []
        
        for telemetry in telemetry_batch:
            try:
                # 1. Inference with Timeout and Fallback
                start_time = time.time()
                try:
                    def _sync_predict():
                        return InferenceEngine.predict(telemetry)

                    result = await asyncio.wait_for(
                        asyncio.to_thread(_sync_predict),
                        timeout=0.5
                    )
                except asyncio.TimeoutError:
                    logger.warning("ML Inference Timeout — using deterministic rule fallback")
                    from app.services.ml_service import DeterministicRuleEngine
                    result = DeterministicRuleEngine.classify(telemetry)
                except Exception as eval_err:
                    logger.error("ML Evaluator Error", error=str(eval_err))
                    from app.services.ml_service import DeterministicRuleEngine
                    result = DeterministicRuleEngine.classify(telemetry)
                    
                predicted_label = result["label"]
                confidence = result["confidence"]
                
                inference_duration = time.time() - start_time
                INFERENCE_LATENCY.observe(inference_duration)

                # 2. Assessment
                # Base Threat Severity (0-100)
                severity_index = RiskAssessmentEngine.compute_severity_index(confidence, predicted_label)

                logger.info("Inference Complete", 
                           predicted_label=predicted_label, 
                           confidence=confidence, 
                           latency_s=float(f"{inference_duration:.4f}"))

                if predicted_label != 'Normal' and predicted_label != 'BENIGN':
                    # 3. Temporal Analysis (Repeat Offender Check)
                    src_ip = telemetry.get('source_ip', '0.0.0.0')
                    self.offender_history[src_ip] = self.offender_history.get(src_ip, 0) + 1
                    
                    repeat_offender_count = self.offender_history[src_ip]
                    escalation_flag = repeat_offender_count > 1
                    if escalation_flag:
                        logger.warning("ESCALATION: Repeat offender detected", src_ip=src_ip, repeat_count=repeat_offender_count)

                    # 4. Weighted Risk Scoring (Paper Alignment)
                    dest_ip = telemetry.get("destination_ip", "Unknown")
                    from app.services.detector import WeightedRiskScorer
                    final_risk_score = WeightedRiskScorer.calculate_risk(severity_index, dest_ip, repeat_offender_count)

                    # 5. Incident Update (In-place)
                    # We mutate the incoming telemetry dictionary to enrich it with decisions.
                    # The caller (api_gateway.py) will save the mutated dict via DAL.
                    telemetry.update({
                        "predicted_label": predicted_label,
                        "confidence": float(confidence),
                        "risk_score": final_risk_score,
                        "status": "Active",
                        "escalation_flag": escalation_flag
                    })
                    detected_incidents.append(telemetry)
            
            except Exception as e:
                # Per-record try/except prevents the whole batch from failing
                logger.error("Inference Cycle Error for record", error=str(e))

        # 6. Batch Preparation
        if detected_incidents:
            logger.info("Enriched new security incidents", count=len(detected_incidents))
        else:
            logger.info("Batch analysis complete. No threats detected.")


# Singleton Instance to be imported by API
sentinel_service = NetworkSentinel()

if __name__ == "__main__":
    logger.info("Starting Sentinel in Standalone Mode...")
    # In standalone, we might want to listen to a queue or just wait
    # For now, we do nothing as it's push-based from API
    while True:
        time.sleep(1)
