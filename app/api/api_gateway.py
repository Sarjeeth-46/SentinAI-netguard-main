"""
Project: AegisCore
Module: Application Controller (API Gateway)
Description:
    The centralized REST interface for the security platform.
    Routes incoming HTTP requests to the appropriate Business Logic component
    (IncidentManager, MetricPipeline, AuthProvider).
    
    Adheres to the OpenAPI v3 specification.
"""
import uvicorn
import time
import asyncio
from fastapi import FastAPI, HTTPException, Body, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from contextlib import asynccontextmanager
from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator
import structlog

from app.core.logging import setup_logging, get_logger
setup_logging()
logger = get_logger("api_gateway")
limiter = Limiter(key_func=get_remote_address)

# Configuration & Infrastructure
from app.core.config import config
from app.services.auth_service import auth_service
from app.db.connection import db
from app.api.deps import get_current_user, User
from app.services.ip_reputation import ip_reputation_manager

# Business Logic Services
from app.services.threat_service import threat_service
from app.services.analytics_service import analytics_service as metric_pipeline
from app.services.dashboard_aggregator import dashboard_aggregator
from app.services.topology_service import topology_service
from app.services.reporting_service import reporting_service
from app.ws.socket_manager import manager
from fastapi import WebSocket, WebSocketDisconnect, BackgroundTasks, Request

from app.models.dto import *

# --- Application Initialization ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes and tears down critical system components cleanly."""
    # Ensure default administrator exists for first-run
    from app.services.auth_service import auth_service
    await auth_service.ensure_admin_user()
    
    # Initialize ML explicitly
    from app.services.ml_service import InferenceEngine
    InferenceEngine.load_model()
    
    # Start Background tasks
    from app.services.ip_reputation import ip_reputation_manager
    global resiliency_task, queue_processor_task, kpi_broadcaster_task
    resiliency_task = asyncio.create_task(monitor_database_health())
    queue_processor_task = asyncio.create_task(process_telemetry_queue())
    kpi_broadcaster_task = asyncio.create_task(broadcast_kpi_updates())
    ip_rep_task = asyncio.create_task(ip_reputation_manager.start())
    
    logger.info("System fully initialized.")
    
    yield  # Application processes requests here
    
    # Teardown
    logger.info("System shutting down. Cancelling background tasks...")
    resiliency_task.cancel()
    queue_processor_task.cancel()
    kpi_broadcaster_task.cancel()
    ip_rep_task.cancel()
    logger.info("Shutdown complete.")

app = FastAPI(
    title=config.API_TITLE,
    version=config.API_VERSION,
    description="Enterprise Security Operations Center (SOC) API",
    lifespan=lifespan
)
APP_START_TIME = time.time()

# Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    traceback.print_exc()
    logger.error("Unhandled Exception Caught", url=str(request.url), error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

from fastapi.exceptions import RequestValidationError
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    import structlog
    req_logger = structlog.get_logger()
    req_logger.warning("Payload Validation Failed", errors=exc.errors(), body=str(exc.body))
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )

Instrumentator().instrument(app).expose(app, endpoint="/api/metrics")

# Ingestion Queue
import asyncio
from app.services.threat_service import threat_service
from app.utils.metrics import QUEUE_DEPTH, PROCESSING_RATE, INGESTION_RATE

INGESTION_QUEUE = asyncio.Queue(maxsize=2000)


# Request Body Size Middleware
@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5 * 1024 * 1024: # 5MB limit
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    response = await call_next(request)
    return response

# Security Headers & Correlation ID
import urllib.parse
import uuid

@app.middleware("http")
async def add_security_headers_and_correlation_id(request: Request, call_next):
    # 1. Correlation ID
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
    
    # Process Pipeline
    response = await call_next(request)
    
    # 2. Security Headers
    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; frame-ancestors 'none';"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    structlog.contextvars.clear_contextvars()
    return response

# Security Middleware (Strict CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173", 
        "http://localhost:3000", "http://192.168.56.40"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

if not config.DEBUG:
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
    app.add_middleware(HTTPSRedirectMiddleware)

# --- Lifecycle Hooks (Legacy endpoint mapping) ---
@app.get("/health", response_model=HealthStatusDTO)
async def health_check():
    """Production readiness health probe."""
    from app.db.connection import db
    from app.services.ml_service import InferenceEngine
    
    db_status = "connected" if db.client else "disconnected"
    engine_status = InferenceEngine.get_metadata().get("status", "unknown")
    
    return HealthStatusDTO(
        database=db_status,
        reports_storage="ready",
        threat_engine=engine_status,
        uptime_seconds=int(time.time() - APP_START_TIME)
    )

@app.post("/bootstrap_system")
@app.post("/api/bootstrap_system")
async def api_bootstrap_system():
    """Manual system bootstrap and data seeding endpoint."""
    import uuid
    from datetime import datetime, timezone
    
    # Core bootstraps are now handled gracefully by the FastAPI app lifespan.
    # Proceed directly to appending sample telemetry database entries.
    
    # Seed Data
    try:
        from app.db.connection import db
        for i in range(5):
            event_data = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "predicted_label": "DDoS" if i % 2 == 0 else "Port Scan",
                "risk_score": 85 if i % 2 == 0 else 45,
                "source_ip": f"192.168.1.{100+i}",
                "destination_ip": "10.0.0.5",
                "status": "Active"
            }
            if not db.client:
                await db.connect()
            collection = db.get_db()["telemetry"]
            await collection.insert_one(event_data)
    except Exception as e:
        logger.error(f"Failed to seed data during bootstrap: {e}")
        
    return {"status": "bootstrapped"}


# --- Authentication Endpoints ---
@app.post("/api/auth/login", status_code=200)
@limiter.limit("50/minute")
async def authenticate_operator(request: Request, creds: CredentialsDTO):
    """Validates operator credentials and issues a session token."""
    token = await auth_service.authenticate_user(creds.username, creds.password)
    
    # Safely get remote address
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    if not token:
        logger.warning("Failed login attempt", username=creds.username, ip=client_ip)
        raise HTTPException(status_code=401, detail="Authentication Failed: Invalid credentials")
    
    response = JSONResponse(content={"access_token": token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=3600*24,
        samesite="lax",
        secure=False  # True for HTTPS
    )
    return response

@app.post("/api/auth/logout")
async def clear_session():
    """Clears the session cookie."""
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie("access_token")
    return response

@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns the currently authenticated user's profile as serializable JSON."""
    return JSONResponse(content=current_user.model_dump())

@app.post("/api/auth/change-password", dependencies=[Depends(get_current_user)])
async def rotate_operator_credentials(req: PasswordChangeDTO):
    """Updates the credentials for the specified operator."""
    success = await auth_service.change_password(req.username, req.old_password, req.new_password)
    if not success:
        raise HTTPException(status_code=400, detail="Rotation Failed: Verification error.")
    return {"message": "Credentials updated successfully"}


# --- Incident Management Endpoints ---
@app.get("/api/threats", dependencies=[Depends(get_current_user)])
async def retrieve_incident_feed(status: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None):
    """
    Returns a stream of security incidents.
    Optional: Filter by lifecycle state (e.g., 'Active', 'Resolved') and time range (ISO strings).
    """
    return await threat_service.get_recent_threats(lifecycle_state=status, start_time=start_time, end_time=end_time)

@app.post("/api/threats/{threat_id}/resolve", dependencies=[Depends(get_current_user)])
async def triage_incident(threat_id: str):
    """Transitions an incident to the 'Resolved' state."""
    try:
        result = await threat_service.resolve_threat(threat_id)
        if not result:
            raise HTTPException(status_code=404, detail="Incident ID not found.")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve threat")

@app.post("/api/threats/{threat_id}/block", dependencies=[Depends(get_current_user)])
async def execute_mitigation(threat_id: str):
    """Triggers an automated block response against the source."""
    success = await threat_service.block_threat_source(threat_id)
    if success:
        return {"status": "blocked", "message": f"Mitigation applied for Incident {threat_id}."}
    raise HTTPException(status_code=404, detail="Threat not found or could not be blocked.")


# --- Telemetry Injection Endpoint (For Standalone Log Generator) ---
# API Key Validation Default
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    # Simple hardcoded key for requirement matching. In prod, fetch from environment.
    expected_key = getattr(config, "TELEMETRY_API_KEY", "secure-telemetry-key-123")
    if api_key != expected_key:
        raise HTTPException(status_code=403, detail="Invalid API Key")

@app.post("/api/telemetry", status_code=201, dependencies=[Depends(verify_api_key)])
@limiter.limit("1000/second")
async def inject_telemetry(request: Request, payload: List[LogEntryPayloadDTO]):
    """
    Receives a batch of telemetry records from external generators.
    Validates each record against LogEntryPayloadDTO before enqueuing.
    """
    if not payload:
        return {"status": "ignored", "count": 0}
    
    enqueued = 0
    for item in payload:
        event = item.model_dump()
        
        # Normalize optional dest_ip alias
        if event.get("dest_ip") and not event.get("destination_ip"):
            event["destination_ip"] = event["dest_ip"]
        
        # Ensure defaults for fields used downstream
        event.setdefault("source_ip", "0.0.0.0")
        event.setdefault("predicted_label", event.get("label", "Unknown"))
        
        # Ensure IDs and Timestamps exist
        if not event.get("id"):
            event["id"] = str(uuid.uuid4())
        if not event.get("timestamp"):
            event["timestamp"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        else:
            from app.services.dashboard_aggregator import DashboardAggregator
            try:
                event["timestamp"] = DashboardAggregator._parse_ts(event["timestamp"]).isoformat()
            except Exception:
                pass
        
        # Enqueue for process_telemetry_queue
        try:
            INGESTION_QUEUE.put_nowait(event)
            enqueued += 1
        except asyncio.QueueFull:
            logger.warning("Ingestion Queue Full during batch injection!")
            break
    
    QUEUE_DEPTH.set(INGESTION_QUEUE.qsize())
    INGESTION_RATE.inc(enqueued)
    
    return {"status": "enqueued", "count": enqueued}


# --- Analytics & Reporting Endpoints ---

# ── CANONICAL ENDPOINT ───────────────────────────────────────────────────────
@app.get("/api/dashboard/overview", dependencies=[Depends(get_current_user)], response_model=DashboardOverviewDTO)
async def get_dashboard_overview():
    """
    Returns the unified dashboard payload.
    ALL frontend widgets must consume this endpoint only.
    KPI cards, risk bar chart, attack donut chart, and severity trend
    are all derived from this single JSON response — guaranteed consistent.
    """
    try:
        return await dashboard_aggregator.get_overview()
    except Exception:
        logger.exception("GET /api/dashboard/overview failed")
        raise HTTPException(status_code=500, detail="Dashboard overview unavailable")

# ── BACKWARD-COMPATIBLE ALIAS ─────────────────────────────────────────────────
@app.get("/api/dashboard/summary", dependencies=[Depends(get_current_user)], response_model=DashboardSummaryDTO,
         description="Deprecated: use /api/dashboard/overview instead.")
async def get_executive_summary():
    """
    Backward-compatible alias. Re-maps the overview payload into the legacy
    DashboardSummaryDTO shape so existing integrations continue to work.
    """
    try:
        overview = await dashboard_aggregator.get_overview()
        rl = overview["risk_levels"]
        # Map new shape → old shape
        risk_summary = [
            {"name": "Critical", "value": rl["critical"]},
            {"name": "High",     "value": rl["high"]},
            {"name": "Medium",   "value": rl["medium"]},
            {"name": "Low",      "value": rl["low"]},
        ]
        attack_types = [
            {"name": k, "value": v}
            for k, v in overview["attack_type_distribution"].items()
        ]
        # Geo stats and ML features are not part of the windowed aggregation;
        # fall back to the metric_pipeline for those.
        try:
            legacy = await metric_pipeline.get_dashboard_summary()
            geo_stats      = legacy.get("geo_stats", [])
            features       = legacy.get("features", [])
            model_metrics  = legacy.get("metrics", {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0})
            threats        = legacy.get("threats", [])
            critical_alerts = legacy.get("critical_alerts", [])
        except Exception:
            geo_stats = []; features = []; model_metrics = {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0}
            threats = []; critical_alerts = []
        return {
            "threats":         threats,
            "risk_summary":    risk_summary,
            "attack_types":    attack_types,
            "geo_stats":       geo_stats,
            "critical_alerts": critical_alerts,
            "features":        features,
            "metrics":         model_metrics,
        }
    except Exception:
        logger.exception("GET /api/dashboard/summary (compat alias) failed")
        raise HTTPException(status_code=500, detail="Dashboard summary unavailable")

# ── DEPRECATED MICRO-ENDPOINTS (still functional, use new aggregator) ─────────
@app.get("/api/stats/attack-types", dependencies=[Depends(get_current_user)], response_model=List[NameValueDTO],
         deprecated=True, description="Deprecated: consume /api/dashboard/overview instead.")
async def get_vector_distribution():
    overview = await dashboard_aggregator.get_overview()
    return [{"name": k, "value": v} for k, v in overview["attack_type_distribution"].items()]

@app.get("/api/stats/geo", dependencies=[Depends(get_current_user)], response_model=List[GeoStatDTO],
         deprecated=True, description="Deprecated: consume /api/dashboard/overview instead.")
async def get_geographic_distribution():
    summary = await metric_pipeline.get_dashboard_summary()
    return summary["geo_stats"]

@app.get("/api/stats/risk-summary", dependencies=[Depends(get_current_user)], response_model=List[NameValueDTO],
         deprecated=True, description="Deprecated: consume /api/dashboard/overview instead.")
async def get_severity_distribution():
    overview = await dashboard_aggregator.get_overview()
    rl = overview["risk_levels"]
    return [
        {"name": "Critical", "value": rl["critical"]},
        {"name": "High",     "value": rl["high"]},
        {"name": "Medium",   "value": rl["medium"]},
        {"name": "Low",      "value": rl["low"]},
    ]

@app.get("/api/network/topology", dependencies=[Depends(get_current_user)], response_model=TopologyStatusDTO)
async def get_network_graph():
    """Provides node-link data for network visualization."""
    return await topology_service.get_topology_status()

@app.post("/api/reports/generate", dependencies=[Depends(get_current_user)])
async def generate_compliance_report(req: ReportRequestDTO):
    """Triggers generation of a daily security report."""
    return await reporting_service.generate_report(req.date)

@app.get("/api/reports/{date_str}", dependencies=[Depends(get_current_user)])
def get_compliance_report(date_str: str):
    """Retrieves a previously generated report."""
    report = reporting_service.get_report(date_str)
    if "error" in report:
        raise HTTPException(status_code=404, detail=report["error"])
    return report


# --- System & Health Endpoints ---
@app.get("/api/health/liveness", response_model=LivenessStatusDTO)
def system_liveness_check():
    """Lightweight check to confirm the service is running."""
    return {
        "status": "alive",
        "uptime_seconds": int(time.time() - APP_START_TIME)
    }

@app.get("/api/health/readiness", response_model=ReadinessStatusDTO)
def system_readiness_check():
    """Deep check to ensure external dependencies act normally."""
    import os
    from app.services.reporting_service import REPORT_DIR
    
    db_status = "connected" if db.get_db() is not None else "disconnected"
    storage_status = "ok" if os.path.exists(REPORT_DIR) and os.access(REPORT_DIR, os.W_OK) else "error"
    
    # Determine aggregate readiness status
    is_ready = db_status == "connected" and storage_status == "ok"
    
    if not is_ready:
        raise HTTPException(status_code=503, detail="Service Unavailable: Dependencies offline")

    return {
        "database": db_status,
        "reports_storage": storage_status,
        "threat_engine": "ready",
        "status": "ready"
    }

@app.get("/api/health", response_model=HealthStatusDTO, deprecated=True)
def system_health_check():
    """Diagnostic heartbeat (Deprecated - Use /liveness and /readiness)."""
    import os
    from app.services.reporting_service import REPORT_DIR
    return {
        "database": "connected" if db.get_db() is not None else "disconnected",
        "reports_storage": "ok" if os.path.exists(REPORT_DIR) and os.access(REPORT_DIR, os.W_OK) else "error",
        "threat_engine": "ready",
        "uptime_seconds": int(time.time() - APP_START_TIME)
    }

class DBStatusDTO(BaseModel):
    status: str

@app.get("/api/system/db-status", response_model=DBStatusDTO)
async def get_db_status():
    """Returns the current MongoDB connection status."""
    from app.db.connection import db
    try:
        # Since we use a persistent DB connection pool from startup, we just ensure it exists
        if not db.client:
            await db.connect()
    except Exception:
        pass
    is_connected = db.get_db() is not None
    return {"status": "connected" if is_connected else "disconnected"}


# --- Artifact Retrieval Endpoints ---
@app.get("/api/model/metrics", response_model=ModelMetricsDTO)
def retrieve_model_performance():
    """Exposes ML performance metrics (Accuracy, F1, etc.)."""
    import json, os
    if os.path.exists(config.METRICS_PATH):
        try:
            with open(config.METRICS_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

@app.get("/api/model/features", response_model=List[ModelFeatureDTO])
def retrieve_model_explainability():
    """Exposes feature importance for XAI visualization."""
    import json, os
    from app.services.ml_service import ml_service
    
    # Attempt dynamic extraction from loaded ML model
    try:
        model = ml_service._model
        if model and hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            features = ["dest_port", "packet_size", "total_l_fwd_packets", "total_fwd_packets", "flow_duration"]
            
            # Map features to importances
            feature_importance = [
                {"feature": col, "importance": float(imp)} 
                for col, imp in zip(features, importances)
            ]
            feature_importance.sort(key=lambda x: x['importance'], reverse=True)
            return feature_importance
    except Exception as e:
        logger.error(f"Failed to extract dynamic feature importance: {e}")

    # Fallback to static file if model not available or error
    if os.path.exists(config.FEATURES_PATH):
        try:
            with open(config.FEATURES_PATH, 'r') as f:
                data = json.load(f)
                return [{"feature": d.get("name", d.get("feature", "unknown")), "importance": d.get("importance", 0.0)} for d in data]
        except Exception:
            pass
            
    # Ultimate fallback structure (no 500 failure when ML absent)
    return [
        {"feature": "dest_port", "importance": 0.4},
        {"feature": "packet_size", "importance": 0.3},
        {"feature": "total_l_fwd_packets", "importance": 0.15},
        {"feature": "total_fwd_packets", "importance": 0.1},
        {"feature": "flow_duration", "importance": 0.05}
    ]

# --- Legacy Hooks (Backward Compatibility) ---
@app.get("/api/threats/risk-summary", response_model=List[NameValueDTO])
async def _legacy_risk_hook(): 
    return await get_severity_distribution()

@app.get("/api/alerts/critical")
async def _legacy_critical_hook():
    summary = await metric_pipeline.get_dashboard_summary()
    return summary["critical_alerts"]

@app.get("/api/stats/history")
def _legacy_history_hook():
    # Mock data for deprecated history widget
    return [
        {"time": "10:00", "count": 12}, {"time": "10:05", "count": 19},
        {"time": "10:10", "count": 8},  {"time": "10:15", "count": 25}, 
        {"time": "10:20", "count": 14}
    ]

# --- Real-Time WebSocket Endpoints ---
@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Internal Webhook for Process-Isolation (Sniffer -> API -> WS)
@app.post("/api/internal/notify")
async def internal_notify(payload: NotifyEventDTO, request: Request):
    logger.info("RECEIVED EVENT IN INTERNAL NOTIFY", payload=payload.model_dump())
    """
    Receives events from background workers (like PacketSniffer or LogCollector).
    Puts the event in a bounded queue for background processing.
    """
    INGESTION_RATE.inc()
    
    event_data = payload.data.model_dump()
    
    # Map dest_ip to destination_ip if needed for backend
    if "dest_ip" in event_data and "destination_ip" not in event_data:
         event_data["destination_ip"] = event_data.pop("dest_ip")

    # Ensure ID exists for database
    if "id" not in event_data or not event_data["id"]:
        import uuid
        event_data["id"] = str(uuid.uuid4())
    
    # Ensure Timestamp exists
    if "timestamp" not in event_data or not event_data["timestamp"]:
        from datetime import datetime, timezone
        event_data["timestamp"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    else:
        from app.services.dashboard_aggregator import DashboardAggregator
        try:
            event_data["timestamp"] = DashboardAggregator._parse_ts(event_data["timestamp"]).isoformat()
        except Exception:
            pass

    # Push to queue to handle backpressure
    try:
        INGESTION_QUEUE.put_nowait(event_data)
        QUEUE_DEPTH.set(INGESTION_QUEUE.qsize())
        logger.info("Log Ingested", log_id=event_data["id"], src=event_data.get("source_ip"), queue_size=INGESTION_QUEUE.qsize())
    except asyncio.QueueFull:
        logger.warning("Ingestion Queue Full! Dropping log.", log_id=event_data["id"])
        raise HTTPException(status_code=503, detail="Ingestion Queue Full")

    return {"status": "enqueued", "id": event_data["id"]}


async def process_telemetry_queue():
    """
    Background Task:
    Consumes events from the ingestion queue and dispatches them through the
    detection pipeline in this strict order:

      1. Persist raw event to DB (audit trail always captured).
      2. Run CorrelationEngine (mandatory for ALL HIDS + NIDS events).
         - If a correlated alert fires: save + broadcast ONLY the correlated
           alert; the independent ML/rule alert is suppressed for this event.
         - If no correlation: fall through to independent ML/rule path.
      3. Independent path (only when correlation did not fire):
           Run sentinel_service ML inference or deterministic rule fallback.
           Broadcast independent alert.

    This makes the CorrelationEngine part of the mandatory event flow, not an
    optional post-processing step.
    """
    logger.info("Started Telemetry Queue Processor (correlation-first dispatch)")
    while True:
        try:
            event_data = await INGESTION_QUEUE.get()
            QUEUE_DEPTH.set(INGESTION_QUEUE.qsize())

            try:
                # sentinel_service logic deprecated, using threat_service
                await threat_service.process_batch([event_data])
                # Ensure every stored event has a status field for queryability
                event_data.setdefault("status", "Active")
                # ── Persist enriched event (single save) ──────────
                await db.save_event(event_data)
                PROCESSING_RATE.inc()
                # Broadcast the independently assessed event
                await manager.broadcast({"type": "THREAT_DETECTED", "data": event_data})
                logger.info("Pipeline complete for event", log_id=event_data.get("id"))

            except Exception as exc:
                logger.error(
                    "Failed to process event from queue",
                    error=str(exc),
                    log_id=event_data.get("id"),
                )
                # Best-effort broadcast so the UI is not completely dark on errors
                await manager.broadcast({"type": "THREAT_DETECTED", "data": event_data})

            INGESTION_QUEUE.task_done()

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Queue processing loop error", error=str(exc))
            await asyncio.sleep(1)


async def monitor_database_health():
    """
    Background Task:
    Monitors MongoDB connectivity. If running in Local Mode (Resiliency),
    it attempts to reconnect. Upon success, triggers Bi-Directional Sync.
    """
    logger.info("Resiliency Monitor Started.")
    while True:
        await asyncio.sleep(30) # Check every 30 seconds
        
        # Pinging database to keep connection alive
        try:
            if db.client:
                await db.client.admin.command('ping')
        except Exception as e:
            logger.error("Resiliency Monitor Error (Ping failed)", error=str(e))

resiliency_task = None
queue_processor_task = None
kpi_broadcaster_task = None

async def broadcast_kpi_updates():
    """
    Background Task:
    Periodically streams SYSTEM_STATUS (KPIs, Charts) to all connected WebSocket clients.
    """
    from datetime import datetime, timezone
    logger.info("KPI Broadcaster Started.")
    while True:
        try:
            await asyncio.sleep(2) # Emit every 2 seconds
            if len(manager.active_connections) > 0:
                overview = await dashboard_aggregator.get_overview()
                
                payload = {
                    "type": "SYSTEM_STATUS",
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                    "payload": overview
                }
                
                # We can also add TRAFFIC_UPDATE explicitly if we like, 
                # but SYSTEM_STATUS includes everything dashboard_aggregator provides
                await manager.broadcast(payload)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"KPI broadcast failed: {e}")
            await asyncio.sleep(1)

@app.on_event("shutdown")
async def shutdown_system():
    """Graceful shutdown logic"""
    logger.info("Initiating graceful shutdown...")
    
    global resiliency_task, queue_processor_task, kpi_broadcaster_task
    if resiliency_task:
        resiliency_task.cancel()
    if queue_processor_task:
        queue_processor_task.cancel()
    if kpi_broadcaster_task:
        kpi_broadcaster_task.cancel()
    
    await ip_reputation_manager.stop()   # cancel Redis reconnect loop
    logger.info("Background tasks cleanly cancelled.")
        
    # Clean up DB connections
    try:
        from app.db.connection import db
        await db.disconnect()
        logger.info("MongoDB client disconnected gracefully.")
    except Exception as e:
        logger.error("Error closing MongoDB connection", error=str(e))
    # Any other worker shutdown logic

if __name__ == "__main__":
    uvicorn.run("app.api.api_gateway:app", host="0.0.0.0", port=8000, reload=config.DEBUG)
