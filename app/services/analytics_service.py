"""
Project: AegisCore
Module: Telemetry Analytics
Description:
    Computes real-time statistical distributions from the telemetry stream.
    Provides the Data Presentation Layer with aggregated insights.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

try:
    from bson import ObjectId
    _BSON_AVAILABLE = True
except ImportError:
    ObjectId = None          # type: ignore[assignment,misc]
    _BSON_AVAILABLE = False

from app.db.connection import db as persistence_layer
from app.core.config import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DTO Sanitization Helpers
# ---------------------------------------------------------------------------

def _sanitize_doc(doc: Any) -> dict:
    """
    Convert a raw MongoDB document to a JSON-safe plain dict.
    - _id (ObjectId)  → "id" (str)
    - Any ObjectId    → str
    - datetime        → ISO 8601 string
    Extra Mongo internals are preserved as strings where needed.
    """
    if not isinstance(doc, dict):
        return {}
    result: dict = {}
    for k, v in doc.items():
        if k == "_id":
            result["id"] = str(v)
        elif _BSON_AVAILABLE and isinstance(v, ObjectId):
            result[k] = str(v)
        elif isinstance(v, datetime):
            result[k] = v.isoformat()
        elif isinstance(v, dict):
            result[k] = _sanitize_doc(v)          # recurse nested docs
        elif isinstance(v, list):
            result[k] = [_sanitize_doc(i) if isinstance(i, dict) else i for i in v]
        else:
            result[k] = v
    return result


def _coerce_name_value(items: List[Dict]) -> List[Dict]:
    """
    Enforce NameValueDTO shape: {name: str, value: int}.
    Drops entries where name is None/empty.
    Coerces value to int (None → 0, float → int).
    """
    out: List[Dict] = []
    for item in (items or []):
        name = item.get("name")
        if not name:                               # drop None / empty-string name
            continue
        out.append({"name": str(name), "value": int(item.get("value") or 0)})
    return out


def _coerce_geo_stat(items: List[Dict]) -> List[Dict]:
    """
    Enforce GeoStatDTO shape: {id: str, value: int}.
    Drops entries where id is None/empty.
    Coerces value to int.
    """
    out: List[Dict] = []
    for item in (items or []):
        geo_id = item.get("id")
        if not geo_id:                             # drop None / empty id
            continue
        out.append({"id": str(geo_id), "value": int(item.get("value") or 0)})
    return out


def _coerce_metrics(raw: Any) -> Dict[str, float]:
    """
    Enforce ModelMetricsDTO shape: all fields are float, None → 0.0.
    Only the four expected keys are kept (extra fields dropped).
    """
    if not isinstance(raw, dict):
        raw = {}
    keys = ("accuracy", "precision", "recall", "f1_score")
    return {k: float(raw.get(k) or 0.0) for k in keys}


def _coerce_features(raw: Any) -> List[Dict]:
    """
    Enforce ModelFeatureDTO shape: {feature: str, importance: float}.
    Drops entries with missing/None feature names.
    """
    out: List[Dict] = []
    for item in (raw if isinstance(raw, list) else []):
        if not isinstance(item, dict):
            continue
        feature = item.get("feature")
        if not feature:
            continue
        out.append({
            "feature":    str(feature),
            "importance": float(item.get("importance") or 0.0),
        })
    return out


# ---------------------------------------------------------------------------
# Safe default DTO — returned whenever data is unavailable or computation fails
# ---------------------------------------------------------------------------
_SAFE_DEFAULT_DTO: Dict[str, Any] = {
    "threats": [],
    "risk_summary": [
        {"name": "Critical", "value": 0},
        {"name": "High",     "value": 0},
        {"name": "Medium",   "value": 0},
        {"name": "Low",      "value": 0},
    ],
    "attack_types":   [],
    "geo_stats":      [],
    "critical_alerts": [],
    "features":       [],
    "metrics": {
        "accuracy":  0.0,
        "precision": 0.0,
        "recall":    0.0,
        "f1_score":  0.0,
    },
}


class MetricPipeline:
    """
    Aggregation pipeline that transforms raw event streams into
    consumable dashboard metrics.
    """

    @classmethod
    async def get_dashboard_summary(cls) -> Dict[str, Any]:
        """
        Public entry point used by the API gateway.
        Wraps compile_dashboard_intelligence with a top-level safety net
        so the endpoint never emits an unhandled 500.
        """
        try:
            return await cls.compile_dashboard_intelligence()
        except Exception:
            logger.exception(
                "Dashboard summary computation failed — returning safe default DTO"
            )
            return _SAFE_DEFAULT_DTO.copy()

    @classmethod
    async def compile_dashboard_intelligence(cls) -> Dict[str, Any]:
        """
        Main aggregations entry point.
        Compiles: Threat Feed, Risk Distribution, Vector Distribution, and Geo-map data.
        """
        # 1. Retrieve Raw Telemetry Window
        try:
            telemetry_window = await persistence_layer.fetch_data(
                limit=config.MAX_HISTORY_LIMIT
            )
            if not telemetry_window:
                telemetry_window = []
            logger.info(
                "Analytics pipeline fetched %d records.", len(telemetry_window)
            )
        except Exception:
            logger.exception("Failed to fetch telemetry window — using empty dataset")
            telemetry_window = []

        # 2. Compute Derivative Metrics
        try:
            risk_histogram = await cls._compute_risk_histogram(telemetry_window)
        except Exception:
            logger.exception("_compute_risk_histogram failed")
            risk_histogram = _SAFE_DEFAULT_DTO["risk_summary"]

        try:
            vector_histogram = await cls._compute_vector_histogram(telemetry_window)
        except Exception:
            logger.exception("_compute_vector_histogram failed")
            vector_histogram = []

        try:
            geo_distribution = await cls._compute_geo_distribution(telemetry_window)
        except Exception:
            logger.exception("_compute_geo_distribution failed")
            geo_distribution = []

        # 3. Extract High-Priority Signals
        try:
            priority_alerts = cls._filter_priority_signals(telemetry_window)
        except Exception:
            logger.exception("_filter_priority_signals failed")
            priority_alerts = []

        # 4. Enriched Context (ML Artifacts) — awaited to avoid blocking event loop
        model_features = await cls._retrieve_static_artifact(config.FEATURES_PATH, [])
        model_metrics  = await cls._retrieve_static_artifact(
            config.METRICS_PATH,
            _SAFE_DEFAULT_DTO["metrics"].copy()
        )

        # -----------------------------------------------------------------------
        # Sanitize & coerce — enforce strict DashboardSummaryDTO / Pydantic v2
        # -----------------------------------------------------------------------
        sanitized_threats        = [_sanitize_doc(t) for t in telemetry_window]
        sanitized_alerts         = [_sanitize_doc(a) for a in priority_alerts]
        sanitized_risk_summary   = _coerce_name_value(risk_histogram)
        sanitized_attack_types   = _coerce_name_value(vector_histogram)
        sanitized_geo_stats      = _coerce_geo_stat(geo_distribution)
        sanitized_metrics        = _coerce_metrics(model_metrics)
        sanitized_features       = _coerce_features(model_features)

        return {
            "threats":         sanitized_threats,
            "risk_summary":    sanitized_risk_summary,
            "attack_types":    sanitized_attack_types,
            "geo_stats":       sanitized_geo_stats,
            "critical_alerts": sanitized_alerts,
            "features":        sanitized_features,
            "metrics":         sanitized_metrics,
        }

    # -----------------------------------------------------------------------
    # Internal Aggregators
    # -----------------------------------------------------------------------

    @classmethod
    async def _compute_risk_histogram(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Quantifies the distribution of severity levels.
        Uses DB-native aggregation; falls back to application-layer on failure.
        """
        db_handle = persistence_layer.get_db()

        if db_handle is not None:
            try:
                pipeline = [
                    {"$project": {
                        "severity_label": {
                            "$switch": {
                                "branches": [
                                    {"case": {"$gte": ["$risk_score", 80]}, "then": "Critical"},
                                    {"case": {"$gte": ["$risk_score", 60]}, "then": "High"},
                                    {"case": {"$gte": ["$risk_score", 30]}, "then": "Medium"},
                                ],
                                "default": "Low"
                            }
                        }
                    }},
                    {"$group": {"_id": "$severity_label", "count": {"$sum": 1}}}
                ]
                cursor  = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                docs    = await cursor.to_list(length=None)   # ← required await

                results: Dict[str, int] = {}
                for doc in docs:
                    bucket = doc.get("_id") or "Low"          # guard None _id
                    results[bucket] = doc.get("count", 0)

                # Zero-fill missing buckets
                for bucket in ["Critical", "High", "Medium", "Low"]:
                    results.setdefault(bucket, 0)

                return [{"name": k, "value": v} for k, v in results.items()]

            except Exception:
                logger.exception("Risk histogram DB aggregation failed — using fallback")

        # Strategy B: Application-Layer Aggregation (Fallback)
        buckets: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for event in (fallback_dataset or []):
            score = event.get("risk_score", 0) or 0
            if   score >= 80: buckets["Critical"] += 1
            elif score >= 60: buckets["High"]     += 1
            elif score >= 30: buckets["Medium"]   += 1
            else:             buckets["Low"]      += 1

        return [{"name": k, "value": v} for k, v in buckets.items()]

    @classmethod
    async def _compute_vector_histogram(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Quantifies attack vectors (Predicted Labels).
        """
        db_handle = persistence_layer.get_db()

        if db_handle is not None:
            try:
                pipeline = [{"$group": {"_id": "$predicted_label", "count": {"$sum": 1}}}]
                cursor   = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                docs     = await cursor.to_list(length=None)   # ← required await

                return [
                    {"name": doc.get("_id") or "Unknown", "value": doc.get("count", 0)}
                    for doc in docs
                    if doc.get("_id") is not None              # guard None _id
                ]
            except Exception:
                logger.exception("Vector histogram DB aggregation failed — using fallback")

        # Fallback
        counts: Dict[str, int] = {}
        for event in (fallback_dataset or []):
            label = event.get("predicted_label") or "Unknown"
            counts[label] = counts.get(label, 0) + 1
        return [{"name": k, "value": v} for k, v in counts.items()]

    @classmethod
    async def _compute_geo_distribution(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Aggregates events by source country.
        """
        db_handle = persistence_layer.get_db()

        if db_handle is not None:
            try:
                pipeline = [{"$group": {"_id": "$source_country", "count": {"$sum": 1}}}]
                cursor   = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                docs     = await cursor.to_list(length=None)   # ← required await

                return [
                    {"id": doc["_id"], "value": doc.get("count", 0)}
                    for doc in docs
                    if doc.get("_id")                          # skip None / empty country
                ]
            except Exception:
                logger.exception("Geo distribution DB aggregation failed — using fallback")

        # Fallback
        counts: Dict[str, int] = {}
        for event in (fallback_dataset or []):
            country = event.get("source_country") or "UNK"
            counts[country] = counts.get(country, 0) + 1
        return [{"id": k, "value": v} for k, v in counts.items()]

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _filter_priority_signals(stream: List[Dict], cap: int = 3) -> List[Dict]:
        """
        Identifies the most critical active incidents for immediate display.
        """
        signals: List[Dict] = []
        for event in (stream or []):
            if event.get("risk_score", 0) >= 80 and event.get("status") != "Resolved":
                signals.append(event)
                if len(signals) >= cap:
                    break
        return signals

    @staticmethod
    async def _retrieve_static_artifact(filepath: str, default_val: Any) -> Any:
        """Loads a JSON artifact from disk without blocking the event loop."""
        import json, os, asyncio
        try:
            if os.path.exists(filepath):
                def _read() -> Any:
                    with open(filepath, "r") as f:
                        return json.load(f)
                return await asyncio.to_thread(_read)   # ← non-blocking file I/O
        except Exception:
            logger.exception("Failed to load static artifact: %s", filepath)
        return default_val


# ---------------------------------------------------------------------------
# Singleton export (API gateway uses analytics_service.get_dashboard_summary())
# ---------------------------------------------------------------------------
analytics_service = MetricPipeline()
