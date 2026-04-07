# SentinAI NetGuard - Paper Alignment Summary

This document summarizes the architectural refinements made to the SentinAI NetGuard backend to strictly align it with the core claims of the research paper "Cloud Based Network Threat Analysis and Risk Management Using Log Analysis and Machine Learning (Random Forest)".

## 1. Centralized Log Ingestion
- Ingestion occurs via a centralized queued pipeline (`INGESTION_QUEUE` in `api_gateway.py`), normalizing structured and unstructured logs equally into an event model payload before passing them down the ML pipeline.

## 2. Explicit Feature Extraction Stage
- **Previous State:** Feature engineering was partially split between `detector.py` and `inference_service.py` where 78 features were defined despite the actual trained model using only 5. Additionally, parts of the application featured random entropy imputation.
- **Alignment Change:** A dedicated, strict `FeatureExtractor` class was implemented within `inference_service.py` (`app/services/inference_service.py`). It is responsible for intercepting raw event telemetry, performing deterministic zero-fill/default-fill procedures, and returning a strict array `[dest_port, flow_duration, total_fwd_packets, total_l_fwd_packets, packet_size]` tailored exactly to the Random Forest model expectations. Random entropy elements were completely stripped.

## 3. Deterministic Random Forest Model Inference
- **Previous State:** Prediction logic was bypassed manually by elements in `sentinel_service.py`.
- **Alignment Change:** `sentinel_service.py` was refactored to explicitly call the singleton `InferenceEngine.predict()` method for every packet. This guarantees identical routing through evaluation, guarantees deterministic output without runtime randomness, and centralizes fallbacks. Evaluator logic (`evaluator.py`) was also unified to use the central loader. No silent deactivation occurs anymore: if ML fails, a rule-based engine activates, and the system continues running reliably.

## 4. Weighted Risk Assessment
- **Previous State:** The system relied on direct mappings of confidence × arbitrary severities.
- **Alignment Change:** A `WeightedRiskScorer` was introduced in `app/services/detector.py`, explicitly implementing the paper's formula:
  `Risk Score = (w1 * Threat Severity) + (w2 * Asset Criticality) + (w3 * Historical Behavior)`
  The system tracks repeating offenders via temporal counters (`sentinel_service.py`) and passes IP definitions to assess severity continuously. The weighting enforces a true comprehensive risk context.

## 5. Feature Importance Visualization Pipeline
- **Previous State:** The explainable dashboard endpoint relied exclusively on static JSON artifacts produced by older training pipelines.
- **Alignment Change:** The `/api/model/features` gateway API was rewritten to dynamically extract native feature importances natively from the `sklearn.ensemble.RandomForestClassifier` in real-time. If the model is absent, it relies on static fallback data instead of silent crashing `500 Internal Server Error`, ensuring the dashboard loads regardless of the ML state container.

## Conclusion
The backend now rigidly honors the system flow outlined in the source documentation. ML inference relies on strict, documented feature structures and deterministic transformations while producing a risk score grounded in weighted contexts.
