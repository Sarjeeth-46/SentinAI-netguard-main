import joblib
import sys
import structlog
import sklearn
from app.core.config import config

logger = structlog.get_logger("ml_service")

class MLService:
    _instance = None
    _model = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MLService, cls).__new__(cls)
        return cls._instance

    def load_model(self):
        try:
            artifact = joblib.load(config.MODEL_PATH)
            
            # Legacy/Wrapper loading logic check
            if isinstance(artifact, dict) and "model" in artifact:
                self._model = artifact["model"]
                training_ver = artifact.get("sklearn_version_training", "unknown")
                version = artifact.get("model_version", "unknown")
            else:
                self._model = artifact
                training_ver = "unknown"
                version = "legacy"
            
            runtime_ver = sklearn.__version__
            
            if training_ver != "unknown" and training_ver != runtime_ver:
                logger.warning("model_version_mismatch", training_ver=training_ver, runtime_ver=runtime_ver)
                if config.STRICT_ML_MODE:
                    logger.error("strict_ml_mode_abort")
                    sys.exit(1)
            
            logger.info("model_load", status="success", version=version, is_strict=config.STRICT_ML_MODE)
        except Exception as e:
            logger.error("model_load_failed", error=str(e), path=config.MODEL_PATH)
            if config.STRICT_ML_MODE:
                sys.exit(1)

    def predict(self, features):
        if not self._model:
            return "Normal", 1.0 # Safe Fallback
        
        prediction = self._model.predict(features)[0]
        confidence = float(max(self._model.predict_proba(features)[0]))
        return prediction, confidence

ml_service = MLService()
