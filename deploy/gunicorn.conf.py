import multiprocessing

# Bind
bind = "0.0.0.0:8000"

# Workers
# FastAPI recommended worker class is uvicorn.workers.UvicornWorker
worker_class = "uvicorn.workers.UvicornWorker"
workers = 2

# Timeout
timeout = 120

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
