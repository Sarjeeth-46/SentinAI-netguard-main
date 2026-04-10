import multiprocessing

# ── Bind to loopback ONLY — Nginx is the public face ──────────────────────────
# Port 8001 matches main.py (uvicorn.run port=8001) and Nginx proxy_pass.
# NEVER use "0.0.0.0:8000" — that exposes the port directly to the internet.
bind = "127.0.0.1:8001"

# ── Worker strategy — correct for async FastAPI ────────────────────────────────
# Formula: (2 × vCPU) + 1
# t2.micro = 1 vCPU → 3 workers | t3.micro = 2 vCPU → 5 workers
worker_class = "uvicorn.workers.UvicornWorker"
workers = (2 * multiprocessing.cpu_count()) + 1
worker_connections = 500     # WS connections per worker (conservative for t2.micro)

# ── Timeouts ───────────────────────────────────────────────────────────────────
timeout = 60             # ML inference ~2s; 60s is safe headroom
keepalive = 5
graceful_timeout = 30    # Allow in-flight requests to finish on reload

# ── Memory optimisation — share ML model across workers ────────────────────────
# model_real.pkl loads once in the master process and is shared via copy-on-write.
# Saves ~150MB RAM on a t2.micro (1GB total).
preload_app = True

# ── Logging — warning level keeps free-tier CloudWatch log quota sane ──────────
accesslog = "-"          # stdout → captured by systemd
errorlog  = "-"          # stderr → captured by systemd
loglevel  = "warning"

# ── Trust X-Forwarded-For from Nginx (loopback only) ──────────────────────────
forwarded_allow_ips = "127.0.0.1"
