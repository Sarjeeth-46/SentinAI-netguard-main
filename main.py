import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import config
from app.api.api_gateway import app as api_router
from app.db.connection import db
from app.services.ml_service import ml_service

# Note: Using the core structlog setup
import structlog
logger = structlog.get_logger("main")

# Create Main FastAPI Instance
app = FastAPI(title=config.API_TITLE, version=config.API_VERSION, description="Enterprise Security Operations Center (SOC) API")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Expandable base on config
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instrument Metrics
Instrumentator().instrument(app).expose(app, endpoint="/api/metrics")

import asyncio
from app.api.api_gateway import monitor_database_health, process_telemetry_queue, broadcast_kpi_updates

@app.on_event("startup")
async def startup():
    logger.info("system_bootstrapping", title=config.API_TITLE, version=config.API_VERSION)
    await db.connect()
    ml_service.load_model()
    
    # Re-initialize queue inside the active event loop to prevent broken routing
    import app.api.api_gateway as ag
    ag.INGESTION_QUEUE = asyncio.Queue(maxsize=2000)
    
    # Start background ingestion and broadcasting tasks
    global resiliency_task, queue_processor_task, kpi_broadcaster_task
    resiliency_task = asyncio.create_task(ag.monitor_database_health())
    queue_processor_task = asyncio.create_task(ag.process_telemetry_queue())
    kpi_broadcaster_task = asyncio.create_task(ag.broadcast_kpi_updates())
    logger.info("background_workers_started")

@app.on_event("shutdown")
async def shutdown():
    logger.info("system_shutdown")
    await db.close()

# Include Sub-Routers
app.mount("/", api_router) # Since currently api_gateway declares an entire app instead of APIRouter, we mount it directly for compatibility, or refactor to APIRouter later.

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=False)
