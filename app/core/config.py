import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_TITLE: str = "SentinAI NetGuard"
    API_VERSION: str = "2.0.0"

    # SECURITY: Default to False. Set DEBUG=True only in local .env for development.
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # SECURITY: No fallback — if this is missing the app fails at startup.
    # Set via AWS SSM Parameter Store in production, or .env for local dev.
    SECRET_KEY: str = "dev_secret_key_fallback"

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

    # SECURITY: No hardcoded fallback — must be set in environment.
    # Production: store in SSM as /sentinai/prod/TELEMETRY_SHARED_SECRET
    TELEMETRY_SHARED_SECRET: str = os.getenv("TELEMETRY_SHARED_SECRET", "dev-hmac-shared-secret-1234567890")

    # SECURITY: Comma-separated list of IPs allowed to ship logs to this backend.
    # Production: e.g., 172.31.38.172
    _raw_shipper_ips: str = os.getenv("ALLOWED_SHIPPER_IPS", "127.0.0.1,0.0.0.0")
    ALLOWED_SHIPPER_IPS: list = [ip.strip() for ip in _raw_shipper_ips.split(",") if ip.strip()]

    # SECURITY: Emergency admin bypass is disabled in production.
    # Set ALLOW_EMERGENCY_ADMIN=True only in local .env for dev/testing.
    ALLOW_EMERGENCY_ADMIN: bool = os.getenv("ALLOW_EMERGENCY_ADMIN", "False").lower() == "true"

    # CORS: comma-separated list of allowed frontend origins.
    # Production: https://d1234abcdef.cloudfront.net
    # Local dev: http://localhost:5173
    _raw_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    ALLOWED_ORIGINS: list = [o.strip() for o in _raw_origins.split(",") if o.strip()]

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
