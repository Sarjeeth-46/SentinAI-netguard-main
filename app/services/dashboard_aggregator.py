"""
Project: SentinAI NetGuard
Module: Dashboard Aggregator
Description:
    THE single source of truth for all dashboard metrics.

    Rules enforced:
      1. One data source — MongoDB only, no Redis mixing.
      2. One time window  — config.DASHBOARD_WINDOW_MINUTES (default 5).
      3. All KPIs derived from the SAME in-memory event list so values
         are mathematically consistent across every widget.
      4. Server-side assertion: total_threats == sum(risk_levels.values()).
         A mismatch is impossible by construction but is guarded and logged.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from app.db.connection import db as persistence_layer
from app.core.config import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk-scoring thresholds (must match frontend App.jsx logic exactly)
# ---------------------------------------------------------------------------
_CRITICAL_THRESHOLD = 80
_HIGH_THRESHOLD     = 60
_MEDIUM_THRESHOLD   = 30

# Maximum trend points returned to the frontend
_TREND_LIMIT = 60


def _classify_risk(risk_score: float) -> str:
    """Classify a risk_score into a bucket string."""
    if risk_score >= _CRITICAL_THRESHOLD:
        return "critical"
    if risk_score >= _HIGH_THRESHOLD:
        return "high"
    if risk_score >= _MEDIUM_THRESHOLD:
        return "medium"
    return "low"


class DashboardAggregator:
    """
    Computes all dashboard metrics from a single time-windowed DB query.

    Public API
    ----------
    get_overview()          → full unified response dict
    get_overview_from_events(events)  → pure helper (used by tests)
    """

    @classmethod
    async def get_overview(cls) -> Dict[str, Any]:
        """
        Entry point called by the API gateway.
        Fetches events then delegates to the pure computation helper.
        """
        try:
            events = await cls._fetch_windowed_events()
            return cls.get_overview_from_events(events)
        except Exception:
            logger.exception("DashboardAggregator.get_overview() failed — returning empty overview")
            return cls._empty_overview()

    # ------------------------------------------------------------------
    # Pure computation helper — no I/O, fully unit-testable
    # ------------------------------------------------------------------
    @classmethod
    def get_overview_from_events(cls, events: List[Dict]) -> Dict[str, Any]:
        """
        Compute the full dashboard overview from a list of event dicts.
        This is a **pure function** — no DB, no network. Safe to call in tests.
        """
        risk_levels: Dict[str, int] = {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "low":      0,
        }
        attack_type_distribution: Dict[str, int] = {}
        trend_points: List[Dict] = []

        for event in events:
            score = float(event.get("risk_score") or 0)
            bucket = _classify_risk(score)
            risk_levels[bucket] += 1

            label = str(event.get("predicted_label") or event.get("label") or "Unknown")
            attack_type_distribution[label] = attack_type_distribution.get(label, 0) + 1

        # total_threats is ALWAYS the sum of the risk buckets — never derived separately
        total_threats = sum(risk_levels.values())

        # --- Server-side mathematical consistency assertion ---
        _expected = (
            risk_levels["critical"]
            + risk_levels["high"]
            + risk_levels["medium"]
            + risk_levels["low"]
        )
        if total_threats != _expected:
            # This should be impossible, but guard defensively
            logger.error(
                "Dashboard consistency violation: total_threats=%d != sum(risk_levels)=%d",
                total_threats, _expected,
            )

        # Build traffic severity trend (latest _TREND_LIMIT events, chronological order)
        sorted_events = sorted(
            events,
            key=lambda e: cls._parse_ts(e.get("timestamp")),
        )
        for event in sorted_events[-_TREND_LIMIT:]:
            ts = event.get("timestamp")
            if ts:
                trend_points.append({
                    "timestamp": ts if isinstance(ts, str) else ts.isoformat(),
                    "risk_score": float(event.get("risk_score") or 0),
                })

        return {
            "total_threats":             total_threats,
            "risk_levels":               risk_levels,
            "attack_type_distribution":  attack_type_distribution,
            "traffic_severity_trend":    trend_points,
            # Metadata
            "window_minutes":            config.DASHBOARD_WINDOW_MINUTES,
            "computed_at":               datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal I/O helpers
    # ------------------------------------------------------------------
    @classmethod
    async def _fetch_windowed_events(cls) -> List[Dict]:
        """
        Fetch events from the DB that fall within the dashboard window.
        Uses MongoDB aggregate when available, falls back to in-app filtering.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=config.DASHBOARD_WINDOW_MINUTES
        )
        cutoff_iso = cutoff.isoformat()

        db_handle = persistence_layer.get_db()

        # --- Strategy A: MongoDB native query (preferred) ---
        if db_handle is not None:
            try:
                collection = db_handle[config.COLLECTION_NAME]
                # Support both datetime objects and ISO strings stored in DB
                query = {
                    "$or": [
                        {"timestamp": {"$gte": cutoff}},
                        {"timestamp": {"$gte": cutoff_iso}},
                    ]
                }
                cursor = collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(2000)
                docs = await cursor.to_list(length=2000)
                logger.info(
                    "DashboardAggregator: fetched %d events from DB (window=%dm)",
                    len(docs), config.DASHBOARD_WINDOW_MINUTES,
                )
                return docs
            except Exception:
                logger.exception("DashboardAggregator: DB query failed — falling back to fetch_data()")

        # --- Strategy B: Fetch all + filter in app (fallback) ---
        try:
            all_events = await persistence_layer.fetch_data(limit=2000) or []
            windowed = []
            for event in all_events:
                ts = cls._parse_ts(event.get("timestamp"))
                if ts >= cutoff:
                    windowed.append(event)
            logger.info(
                "DashboardAggregator (fallback): %d/%d events within window",
                len(windowed), len(all_events),
            )
            return windowed
        except Exception:
            logger.exception("DashboardAggregator: fallback fetch_data() failed — returning empty list")
            return []

    @staticmethod
    def _parse_ts(ts_value: Any) -> datetime:
        """Parse a timestamp field (datetime object, ISO string, or None) → datetime (UTC)."""
        if ts_value is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(ts_value, datetime):
            return ts_value if ts_value.tzinfo else ts_value.replace(tzinfo=timezone.utc)
        if isinstance(ts_value, str):
            try:
                # Handle both 'Z' suffix and '+00:00'
                normalized = ts_value.replace("Z", "+00:00")
                return datetime.fromisoformat(normalized)
            except ValueError:
                pass
        return datetime.min.replace(tzinfo=timezone.utc)

    @staticmethod
    def _empty_overview() -> Dict[str, Any]:
        return {
            "total_threats":            0,
            "risk_levels":              {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "attack_type_distribution": {},
            "traffic_severity_trend":   [],
            "window_minutes":           config.DASHBOARD_WINDOW_MINUTES,
            "computed_at":              datetime.now(timezone.utc).isoformat(),
        }


# Singleton export
dashboard_aggregator = DashboardAggregator()
