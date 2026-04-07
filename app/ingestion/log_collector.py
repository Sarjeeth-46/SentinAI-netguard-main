import re
import logging
import asyncio
import asyncssh
import aiohttp
from datetime import datetime
from app.core.config import config, get_redis_client
from app.services.ip_reputation import ip_reputation_manager
from app.services.detection_engine import (
    EventParser,
    DuplicateFilter,
    SSHBruteForceAggregator,
    RiskScorer,
    SessionTracker,
    SshEventType,
)
from app.utils.metrics import SSH_EVENTS_DETECTED
import structlog
from app.core.logging import setup_logging

# Configure Logging
logger = structlog.get_logger()

class LogCollector:
    def __init__(self):
        self.host       = config.TARGET_SERVER_IP
        self.user       = config.TARGET_SSH_USER
        self.key_path   = getattr(config, "TARGET_SSH_KEY_PATH", "~/.ssh/id_rsa")
        self.password   = getattr(config, "TARGET_SSH_PASSWORD", None)

        # Build an independent Redis connection for the log collector
        try:
            _redis = get_redis_client()
            _redis.ping()
        except:
            _redis = None

        # Detection engine layers — share Redis client; both degrade independently
        self._dedup      = DuplicateFilter(redis_client=_redis)
        self._aggregator = SSHBruteForceAggregator(redis_client=_redis)
        self._scorer     = RiskScorer(redis_client=_redis)
        self._session_tracker = SessionTracker(redis_client=_redis)
        self._parser     = EventParser(session_tracker=self._session_tracker)

        # Session is None until open() is called — never created in __init__
        self._session: aiohttp.ClientSession | None = None

    # ── Session lifecycle ─────────────────────────────────────────────────

    async def open(self) -> None:
        """
        Create the shared ClientSession exactly once.
        Must be called before start() and within the running event loop.
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=5.0)
            self._session = aiohttp.ClientSession(timeout=timeout)
            logger.info("aiohttp ClientSession opened.")

    async def shutdown(self) -> None:
        """
        Close the shared session cleanly.
        Must be called within the same event loop as open().
        """
        if self._session is not None and not self._session.closed:
            await self._session.close()
            logger.info("aiohttp ClientSession closed.")
        self._session = None

    # ── Log processing pipeline ───────────────────────────────────────────

    async def process_line(self, line: str) -> None:
        """
        5-step pipeline:
          1. Parse raw line → typed SshEvent
          2. Deduplicate — drop if seen within DEDUP_TTL_S
          3 & 4. Correlate + Score → optional alert dict
          5. Dispatch alert if generated
        """
        line = line.strip()
        if not line:
            return

        # [1] Parse
        event = self._parser.parse(line)
        SSH_EVENTS_DETECTED.inc()

        # [2] Deduplicate — identical failures within TTL are suppressed
        # We only deduplicate SSH_FAILED; dropping a SUCCESS or SUDO event is too risky
        if event.event_type == SshEventType.SSH_FAILED:
            if await self._dedup.is_duplicate(line):
                logger.debug("Duplicate failed log line suppressed.", event_type=event.event_type.name)
                return

        # [3+4] Classify and score
        alert = await self._classify(event)

        # [5] Dispatch
        if alert:
            await self.push_alert(alert)

    async def _classify(self, event) -> dict | None:
        """
        Stateful classification:
          SSH_FAILED  → record attempt; alert only when threshold crossed
          SSH_SUCCESS → check correlation; alert only on confirmed compromise
          SSH_SUDO    → always alert (privilege escalation, no correlation needed)
          UNKNOWN     → info log, no alert
        """
        if event.event_type == SshEventType.SSH_FAILED:
            triggered, count = self._aggregator.check_attempt(event.source_ip)
            risk = self._scorer.score(
                SshEventType.SSH_FAILED, 
                ip=event.source_ip,
                fail_count=count if triggered else 0
            ) 
            if risk.should_alert:
                logger.warning(
                    f"Brute force threshold reached (tier {risk.risk_score}).",
                    ip=event.source_ip, count=count,
                )
                return self._build_alert(event, risk, f"Cumulative failures: {count}")
            logger.info(
                "SSH failed login recorded.",
                ip=event.source_ip, user=event.username, count=count,
            )
            return None

        if event.event_type == SshEventType.SSH_SUCCESS:
            is_compromise, fail_count = self._aggregator.check_compromise(event.source_ip)
            risk = self._scorer.score(
                SshEventType.SSH_SUCCESS,
                ip=event.source_ip,
                is_compromise=is_compromise,
                fail_count=fail_count,
            )
            if risk.should_alert:
                logger.critical(
                    "Brute force compromise detected!",
                    ip=event.source_ip, user=event.username, prior_failures=fail_count,
                )
                return self._build_alert(
                    event, risk,
                    f"Successful login after {fail_count} failed attempts within window.",
                )
            # Normal login — informational only, no alert
            logger.info(
                "NORMAL_LOGIN",
                ip=event.source_ip, user=event.username,
            )
            return None

        if event.event_type == SshEventType.SSH_SUDO:
            risk = self._scorer.score(SshEventType.SSH_SUDO)
            return self._build_alert(event, risk, event.raw_line)

        # UNKNOWN
        if "sshd" in event.raw_line:
            logger.debug("Unclassified log line.", raw=event.raw_line[:80])
        return None

    @staticmethod
    def _build_alert(event, risk, details: str) -> dict:
        return {
            "label":       risk.label,
            "risk_score":  risk.risk_score,
            "severity":    risk.severity,
            "details":     details,
            "attacker_ip": event.source_ip,
            "target_user": event.username,
            "target_port": event.port,
        }

    async def push_alert(self, alert_data):
        """
        Push alert to the backend API.
        Reuses the single shared session created in open().
        Only replaces the session if it was closed by a network error —
        never creates a brand-new session per attempt.
        """
        import uuid
        request_id = str(uuid.uuid4())

        telemetry = {
            "id":               request_id,
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "source_ip":        alert_data.get("attacker_ip", "Unknown"),
            "destination_ip":   self.host,
            "protocol":         "SYSLOG",
            "packet_size":      0,
            "dest_port":        22,
            "label":            alert_data["label"],
            "predicted_label":  alert_data["label"],
            "risk_score":       alert_data["risk_score"],
            "confidence":       1.0,
            "attack_probability": 1.0,
            "metadata": {
                "log_line": alert_data["details"],
                "source":   "HIDS",
                "username": alert_data.get("target_user", "Unknown"),
                "port":     alert_data.get("target_port", 0),
            },
        }

        max_retries = 3
        base_delay  = 1.0

        for attempt in range(max_retries):
            try:
                if attempt == 0:
                    logger.warning(
                        "ALERT: Threat Detected",
                        label=alert_data["label"],
                        req_id=request_id,
                    )

                # Ensure session is open — re-open only if it was closed by
                # a previous network error, not on every attempt.
                if self._session is None or self._session.closed:
                    await self.open()

                async with self._session.post(
                    "http://127.0.0.1:8000/api/internal/notify",
                    json={"type": "THREAT_DETECTED", "data": telemetry},
                    headers={"X-Request-ID": request_id},
                ) as response:
                    if response.status == 503:
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status,
                            message="Queue Full / Service Unavailable",
                        )
                    response.raise_for_status()
                    return  # success

            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                delay = base_delay * (2 ** attempt)
                logger.error(
                    "Failed to push alert. Retrying…",
                    attempt=attempt + 1, max=max_retries,
                    delay=delay, error=str(e), req_id=request_id,
                )
                # Close the broken session — open() will create a fresh one
                # on the next iteration, not here, to avoid double-open.
                if self._session and not self._session.closed:
                    await self._session.close()
                self._session = None

                if attempt < max_retries - 1:
                    await asyncio.sleep(delay)
                else:
                    logger.critical(
                        "Failed to push alert after max retries. Dropping.",
                        req_id=request_id,
                    )

            except Exception as e:
                logger.error(
                    "Unrecoverable error pushing alert.",
                    error_type=type(e).__name__, msg=str(e), req_id=request_id,
                )
                break

    # ── Main loop ─────────────────────────────────────────────────────────

    async def start(self):
        """Main Loop: Resilient Asynchronous SSH log tailing."""
        logger.info("Starting Async Log Collector", target=self.host)

        from prometheus_client import start_http_server
        start_http_server(9002)

        while True:
            try:
                connect_kwargs = {
                    "host":        self.host,
                    "username":    self.user,
                    "known_hosts": None,
                }
                if self.password:
                    connect_kwargs["password"] = self.password
                elif self.key_path:
                    connect_kwargs["client_keys"] = [self.key_path]

                async with asyncssh.connect(**connect_kwargs) as conn:
                    logger.info("SSH Connection Established (Async).")
                    async with conn.create_process("tail -F /var/log/auth.log") as process:
                        logger.info("Tailing started…")
                        async for line in process.stdout:
                            await self.process_line(line)

            except asyncssh.Error as e:
                logger.error("SSH Connection Error", error=str(e))
            except Exception as e:
                logger.error("Runtime Error", error=str(e))

            logger.warning("Reconnecting in 5s…")
            await asyncio.sleep(5)

    # ── Entrypoint ────────────────────────────────────────────────────────

    async def run(self):
        """
        Single async entry point — opens session, runs start(), closes session.
        Ensures open() and shutdown() share the same event loop,
        eliminating 'Unclosed client session' warnings.
        """
        await self.open()
        try:
            await self.start()
        finally:
            await self.shutdown()   # always runs, even on KeyboardInterrupt


if __name__ == "__main__":
    collector = LogCollector()
    try:
        # run() manages the full session lifecycle within one event loop.
        # Do NOT call asyncio.run(collector.shutdown()) separately —
        # that would open a second loop for a session from the first loop.
        asyncio.run(collector.run())
    except KeyboardInterrupt:
        logger.info("Collector stopped by user.")

