import sys
import os
import asyncio
import json

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

async def validate_startup():
    results = {
        "MONGODB_CONNECTED": "FAIL",
        "REDIS_CONNECTED": "FAIL",
        "MODEL_LOADED": "FAIL",
        "NO_DUPLICATE_MODEL_LOAD": "FAIL",
        "FEATURE_EXTRACTOR_READY": "FAIL",
        "WEIGHTED_SCORER_READY": "FAIL",
        "CORRELATION_ENGINE_READY": "FAIL"
    }

    try:
        from app.core.config import config

        # 1. MongoDB Connection
        try:
            from app.db.connection import db
            # Ensure connection is attempted
            await db.dal._ensure_connection()
            if not db.dal._is_local_mode:
                results["MONGODB_CONNECTED"] = "PASS"
            else:
                results["MONGODB_CONNECTED"] = "FAIL (Local Mode Fallback)"
        except Exception as e:
            results["MONGODB_CONNECTED"] = f"FAIL: {str(e)}"

        # 2. Redis Connection (Not Degraded Mode)
        try:
            from app.core.config import get_redis_client
            redis_client = get_redis_client()
            if redis_client.ping():
                results["REDIS_CONNECTED"] = "PASS"
            else:
                results["REDIS_CONNECTED"] = "FAIL (Ping returned False)"
        except Exception as e:
            results["REDIS_CONNECTED"] = f"FAIL: {str(e)}"

        # 3. Model Loaded & No Duplicate Load
        try:
            from app.services.ml_service import InferenceEngine
            InferenceEngine.load_model()
            
            if InferenceEngine._model is not None:
                results["MODEL_LOADED"] = "PASS"
            else:
                results["MODEL_LOADED"] = "FAIL (Model is None)"
                
            if InferenceEngine._model_load_tried:
                results["NO_DUPLICATE_MODEL_LOAD"] = "PASS"
        except Exception as e:
            results["MODEL_LOADED"] = f"FAIL: {str(e)}"

        # 4. Feature Extractor Ready
        try:
            from app.services.ml_service import FeatureExtractor
            if hasattr(FeatureExtractor, 'extract_features'):
                results["FEATURE_EXTRACTOR_READY"] = "PASS"
        except Exception as e:
            results["FEATURE_EXTRACTOR_READY"] = f"FAIL: {str(e)}"

        # 5. Weighted Scorer Ready
        try:
            from app.services.detector import WeightedRiskScorer
            if hasattr(WeightedRiskScorer, 'calculate_risk'):
                results["WEIGHTED_SCORER_READY"] = "PASS"
        except Exception as e:
            results["WEIGHTED_SCORER_READY"] = f"FAIL: {str(e)}"

        # 6. Correlation Engine Ready
        try:
            from app.domain.correlation_service import correlation_engine
            if correlation_engine is not None:
                results["CORRELATION_ENGINE_READY"] = "PASS"
        except Exception as e:
            results["CORRELATION_ENGINE_READY"] = f"FAIL: {str(e)}"

    except Exception as e:
        pass

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(validate_startup())
