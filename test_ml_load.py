import os
import joblib

path = "model_real.pkl"
data = joblib.load(path)
data["metadata"]["sklearn_version_training"] = "9.9.9" # force mismatch
joblib.dump(data, path)

os.environ["STRICT_ML_MODE"] = "true"
try:
    from app.services.ml_service import InferenceEngine
    InferenceEngine.load_model()
except SystemExit as e:
    print(f"STRICT MODE EXITED (success): {e}")

os.environ["STRICT_ML_MODE"] = "false"
InferenceEngine._model_load_tried = False
InferenceEngine.load_model()
print("NON STRICT MODE COMPLETED (success)")
