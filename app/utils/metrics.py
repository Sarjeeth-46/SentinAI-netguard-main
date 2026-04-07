from prometheus_client import Counter, Histogram, Gauge

# Packet Sniffer Metrics
PACKETS_PROCESSED_TOTAL = Counter(
    "packets_processed_total", "Total packets processed by the sniffer"
)
PACKETS_DROPPED_TOTAL = Counter(
    "packets_dropped_total", "Total packets dropped due to queue backpressure"
)

# Log Collector Metrics
SSH_EVENTS_DETECTED = Counter(
    "ssh_events_detected", "Total SSH anomalous events detected"
)
REDIS_RECONNECT_ATTEMPTS = Counter(
    "redis_reconnect_attempts", "Total redis reconnect attempts"
)

# API Gateway Metrics
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
REQUEST_LATENCY_SECONDS = Histogram(
    "request_latency_seconds", "HTTP request latency in seconds", ["endpoint"]
)
ACTIVE_WEBSOCKET_CONNECTIONS = Gauge(
    "active_websocket_connections", "Number of currently active websocket connections"
)
QUEUE_DEPTH = Gauge(
    "queue_depth", "Current size of the ingestion queue"
)
PROCESSING_RATE = Counter(
    "processing_rate", "Number of logs processed by the worker"
)
INGESTION_RATE = Counter(
    "ingestion_rate", "Number of logs ingested into the queue"
)
