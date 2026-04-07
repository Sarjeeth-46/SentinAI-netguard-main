import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_TITLE: str = "SentinAI NetGuard"
    API_VERSION: str = "2.0.0"
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "fallback_secret_key_for_jwt_32_chars")
    
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME: str = "threat_detection"
    COLLECTION_NAME: str = "telemetry"
    
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    
    STRICT_ML_MODE: bool = os.getenv("STRICT_ML_MODE", "false").lower() == "true"
    
    # Base dir is the root of the project
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODEL_PATH: str = os.path.join(BASE_DIR, "model_real.pkl")
    METRICS_PATH: str = os.path.join(BASE_DIR, "model_metrics.json")
    FEATURES_PATH: str = os.path.join(BASE_DIR, "model_features.json")
    
    # Internal auth keys
    TELEMETRY_API_KEY: str = os.getenv("TELEMETRY_API_KEY", "secure-telemetry-key-123")
    ALLOW_EMERGENCY_ADMIN: bool = True
    
    # Dashboard and Topology Config
    DASHBOARD_WINDOW_MINUTES: int = 1440
    TARGET_SERVER_IP: str = os.getenv("TARGET_SERVER_IP", "10.0.5.5")
    TARGET_SSH_USER: str = os.getenv("TARGET_SSH_USER", "root")
    TARGET_SSH_KEY_PATH: str = os.getenv("TARGET_SSH_KEY_PATH", "~/.ssh/id_rsa")
    
    MAX_HISTORY_LIMIT: int = 5000
    JSON_DB_PATH: str = os.path.join(BASE_DIR, "fallback_db.json")

    class Config:
        env_file = ".env"
        extra = "ignore"

config = Settings()
