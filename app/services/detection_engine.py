"""
Project: SentinAI NetGuard
Module: Detection Engine
Description:
    Stateful, layered SSH threat detection pipeline.

    Layers (in order):
      1. EventParser       – classifies raw log lines into typed SshEvent objects
                             IPv4 & IPv6 supported via unified _RE_IP extraction
      2. SessionTracker    – maps sshd PID → source IP for pam_unix session correlation
      3. AlertDeduplicator – suppresses repeated identical *alerts* (not raw lines)
      4. SSHBruteForceAggregator – sliding-window failure tracker per IP (Redis ZSET)
      5. DistributedBruteForceTracker – cross-IP failure tracker per (user,port)
      6. RiskScorer        – maps (event_type, context) → (risk_score, label, severity)

    All Redis-backed components degrade gracefully to in-process fallbacks when
    Redis is unavailable — no blocking, no exceptions surfacing to callers.

    Key design invariants:
      - Every failure attempt ALWAYS increments the aggregation window counter.
      - Deduplication is applied ONLY at alert-emission time, never at ingestion.
      - The same telemetry input always produces the same detection outcome.
      - IPv4 and IPv6 addresses are handled identically throughout.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

import structlog

logger = structlog.get_logger()

# ── Configurable thresholds (override via env vars) ──────────────────────────
BRUTE_FORCE_THRESHOLD      = int(os.getenv("BRUTE_FORCE_THRESHOLD",      "5"))
BRUTE_FORCE_WINDOW_S       = int(os.getenv("BRUTE_FORCE_WINDOW_S",       "300"))   # 5 minutes
DIST_BRUTE_FORCE_THRESHOLD = int(os.getenv("DIST_BRUTE_FORCE_THRESHOLD", "20"))    # cross-IP
DEDUP_TTL_S                = int(os.getenv("DEDUP_TTL_S",                "60"))    # alert dedup window
SESSION_TTL_S              = int(os.getenv("SESSION_TTL_S",              "60"))    # PID→IP TTL

# Comma-separated CIDRs to exempt from brute-force alerting (NAT egress, etc.)
_TRUSTED_NAT_RANGES_RAW = os.getenv("TRUSTED_NAT_RANGES", "")
TRUSTED_NAT_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
for _cidr in _TRUSTED_NAT_RANGES_RAW.split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            TRUSTED_NAT_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            pass  # malformed entry; log at import to avoid repeated warnings


# ─────────────────────────────────────────────────────────────────────────────
# 0. Shared IP utilities
# ─────────────────────────────────────────────────────────────────────────────

# IPv4: classic dotted-decimal
_RE_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
# IPv6: full / compressed forms + IPv4-mapped (::ffff:1.2.3.4)
_RE_IPV6 = (
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"           # full
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"                         # ::x…
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                         # end ::
    r"|::"                                                   # loopback
    r"|(?:[0-9a-fA-F]{1,4}:){6}" + _RE_IPV4 +              # IPv4-mapped
    r"|::(?:ffff(?::0{1,4})?:)?" + _RE_IPV4 +
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}:" + _RE_IPV4 +
    r")"
)
_RE_IP_COMBINED = re.compile(r"(?P<ip>" + _RE_IPV6 + r"|" + _RE_IPV4 + r")")


def _normalize_ip(raw: str) -> str:
    """
    Canonical-form IP string via Python's ipaddress module.
    IPv4-mapped IPv6 (::ffff:1.2.3.4) is unwrapped to plain IPv4.
    Falls back to the raw string if parsing fails.
    """
    try:
        obj = ipaddress.ip_address(raw)
        if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
            return str(obj.ipv4_mapped)
        return str(obj)
    except ValueError:
        return raw


def _is_trusted_nat(ip: str) -> bool:
    """Return True if ip falls within any configured TRUSTED_NAT_RANGES."""
    if not TRUSTED_NAT_NETWORKS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in TRUSTED_NAT_NETWORKS)
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Event Types
# ─────────────────────────────────────────────────────────────────────────────

class SshEventType(Enum):
    SSH_FAILED       = auto()   # Failed password / invalid user attempt
    SSH_SUCCESS      = auto()   # Accepted password / publickey (IP embedded)
    SSH_SESSION_OPEN = auto()   # pam_unix session opened (no IP; resolved via PID)
    SSH_SUDO         = auto()   # Privilege escalation via sudo
    UNKNOWN          = auto()   # Anything else — pass-through, no alert


@dataclass
class SshEvent:
    event_type:  SshEventType
    source_ip:   str = "Unknown"
    username:    str = "Unknown"
    port:        int = 0
    pid:         Optional[int] = None    # sshd process ID extracted from syslog prefix
    raw_line:    str = ""


# ─────────────────────────────────────────────────────────────────────────────
# 2. SessionTracker  (Redis SETEX + in-process fallback)
# ─────────────────────────────────────────────────────────────────────────────

class SessionTracker:
    """
    Correlates sshd PID → source IP so that pam_unix(sshd:session) events —
    which carry no source IP — can be attributed to the originating Accepted
    password/publickey event.

    Flow:
        1. EventParser sees "Accepted …" → calls record_auth(pid, ip).
        2. EventParser sees "session opened …" → calls resolve_session_ip(pid)
           to retrieve the previously stored IP.

    Storage: Redis SETEX with SESSION_TTL_S expiry; falls back to an in-process
    dict bounded to 5,000 entries.
    """

    _FALLBACK_MAX = 5_000

    def __init__(self, redis_client=None, ttl: int = SESSION_TTL_S):
        self._redis = redis_client
        self._ttl   = ttl
        self._local: dict[int, str] = {}

    def _key(self, pid: int) -> str:
        return f"session:pid:{pid}"

    def record_auth(self, pid: int, ip: str) -> None:
        """Store PID → normalized-IP mapping (called for Accepted … events)."""
        norm = _normalize_ip(ip)
        if self._redis is not None:
            try:
                self._redis.setex(self._key(pid), self._ttl, norm)
                return
            except Exception as exc:
                logger.debug("SessionTracker Redis set error, fallback", error=str(exc))
                self._redis = None
        # In-process fallback
        if len(self._local) >= self._FALLBACK_MAX:
            self._local.clear()
        self._local[pid] = norm

    def resolve_session_ip(self, pid: int) -> str:
        """Return the IP for a PID, or 'Unknown' if not found / expired."""
        if pid is None:
            return "Unknown"
        if self._redis is not None:
            try:
                val = self._redis.get(self._key(pid))
                return val if val else "Unknown"
            except Exception as exc:
                logger.debug("SessionTracker Redis get error, fallback", error=str(exc))
                self._redis = None
        return self._local.get(pid, "Unknown")

    def update_redis(self, redis_client) -> None:
        self._redis = redis_client


# ─────────────────────────────────────────────────────────────────────────────
# 3. EventParser  (pure, stateless — IP extraction now covers IPv4 + IPv6)
# ─────────────────────────────────────────────────────────────────────────────

# Unified IP group embedded into all patterns
_IP = r"(?P<ip>" + _RE_IPV6 + r"|" + _RE_IPV4 + r")"

# Pre-compiled patterns — compiled once at import time
_FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + _IP),
    re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*rhost=" + _IP + r"(?:\s+user=(?P<user>\S+))?"),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from " + _IP),
    re.compile(r"Disconnecting authenticating user (?P<user>\S+) " + _IP),
]

_SUCCESS_WITH_IP_PATTERNS = [
    re.compile(r"Accepted password for (?P<user>\S+) from " + _IP),
    re.compile(r"Accepted publickey for (?P<user>\S+) from " + _IP),
]

# Session-open has no IP — resolved via SessionTracker PID lookup
_SESSION_OPEN_PATTERN = re.compile(
    r"pam_unix\(sshd:session\): session opened for user (?P<user>\S+)"
)

_SUDO_PATTERNS = [
    re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND="),
    re.compile(r"pam_unix\(sudo:session\): session opened for user root by (?P<user>\S+)?"),
]

_RE_PORT = re.compile(r"port (\d+)")
_RE_PID  = re.compile(r"\w+\[(\d+)\]:")   # e.g. "sshd[12345]:"


class EventParser:
    """
    Converts a raw syslog line into a typed SshEvent.
    Pure function — no I/O.

    IPv4 and IPv6 source addresses are both handled via the unified _IP pattern.
    Extracted IPs are normalized (compressed IPv6, IPv4-mapped unwrapped).
    """

    def __init__(self, session_tracker: Optional[SessionTracker] = None):
        """
        session_tracker is optional; if provided, SSH_SESSION_OPEN events are
        enriched with a resolved source IP from prior auth events.
        """
        self._tracker = session_tracker

    def parse(self, line: str) -> SshEvent:
        # Hard-ignore patterns — CRON/systemd noise
        ignore_strings = [
            "CRON", "systemd-logind", "Session logged out",
            "Removed session", "Disconnected from user"
        ]
        if any(s in line for s in ignore_strings):
            return SshEvent(SshEventType.UNKNOWN, raw_line=line)

        port_m = _RE_PORT.search(line)
        port   = int(port_m.group(1)) if port_m else 0

        pid_m = _RE_PID.search(line)
        pid   = int(pid_m.group(1)) if pid_m else None

        # ── SSH_FAILED ───────────────────────────────────────────────────────
        for p in _FAILED_PATTERNS:
            m = p.search(line)
            if m:
                d = m.groupdict()
                raw_ip = d.get("ip", "Unknown") or "Unknown"
                return SshEvent(
                    SshEventType.SSH_FAILED,
                    source_ip=_normalize_ip(raw_ip),
                    username=d.get("user", "Unknown") or "Unknown",
                    port=port,
                    pid=pid,
                    raw_line=line,
                )

        # ── SSH_SUCCESS (Accepted …)  — IP embedded ──────────────────────────
        for p in _SUCCESS_WITH_IP_PATTERNS:
            m = p.search(line)
            if m:
                d   = m.groupdict()
                raw_ip = d.get("ip", "Unknown") or "Unknown"
                norm   = _normalize_ip(raw_ip)
                # Record PID→IP so that subsequent session-open events are resolved
                if self._tracker and pid is not None:
                    self._tracker.record_auth(pid, norm)
                return SshEvent(
                    SshEventType.SSH_SUCCESS,
                    source_ip=norm,
                    username=d.get("user", "Unknown") or "Unknown",
                    port=port,
                    pid=pid,
                    raw_line=line,
                )

        # ── SSH_SESSION_OPEN  — resolve IP via PID ───────────────────────────
        m = _SESSION_OPEN_PATTERN.search(line)
        if m:
            d   = m.groupdict()
            ip  = "Unknown"
            if self._tracker and pid is not None:
                ip = self._tracker.resolve_session_ip(pid)
            return SshEvent(
                SshEventType.SSH_SESSION_OPEN,
                source_ip=ip,
                username=d.get("user", "Unknown") or "Unknown",
                port=port,
                pid=pid,
                raw_line=line,
            )

        # ── SSH_SUDO ─────────────────────────────────────────────────────────
        for p in _SUDO_PATTERNS:
            m = p.search(line)
            if m:
                d = m.groupdict()
                return SshEvent(
                    SshEventType.SSH_SUDO,
                    source_ip="Unknown",
                    username=d.get("user", "Unknown") or "Unknown",
                    port=0,
                    pid=pid,
                    raw_line=line,
                )

        return SshEvent(SshEventType.UNKNOWN, pid=pid, raw_line=line)


# ─────────────────────────────────────────────────────────────────────────────
# 4. AlertDeduplicator  (replaces raw-line DuplicateFilter for dedup)
#    NOTE: Raw-line deduplication is intentionally REMOVED from ingestion path.
#          Every log line is parsed and counted. Only alert emission is throttled.
# ─────────────────────────────────────────────────────────────────────────────

class AlertDeduplicator:
    """
    Suppresses repeated *alerts* (not raw log lines) within DEDUP_TTL_S seconds.

    Key format: alert_dedup:{label}:{normalized_ip}:{tier}
    Uses Redis SETEX with NX flag; falls back to in-process set bounded at 10,000.

    This guarantees:
      - Every failed auth ALWAYS increments the aggregation counter.
      - Identical alerts (same IP advancing the same risk tier) are not re-emitted
        until the TTL expires.
    """

    _FALLBACK_MAX = 10_000

    def __init__(self, redis_client=None, ttl: int = DEDUP_TTL_S):
        self._redis = redis_client
        self._ttl   = ttl
        self._seen:  set[str] = set()

    def _key(self, label: str, ip: str, tier: int) -> str:
        raw = f"{label}:{_normalize_ip(ip)}:{tier}"
        return "alert_dedup:" + hashlib.sha256(raw.encode()).hexdigest()

    async def is_duplicate_alert(self, label: str, ip: str, tier: int) -> bool:
        """Returns True if this (label, ip, tier) alert was already emitted recently."""
        key = self._key(label, ip, tier)

        if self._redis is not None:
            try:
                added = await asyncio.to_thread(
                    self._redis.set, key, "1", self._ttl, None, True
                )
                return added is None
            except Exception as exc:
                logger.debug("AlertDeduplicator Redis error, fallback", error=str(exc))
                self._redis = None

        # In-process fallback
        if key in self._seen:
            return True
        if len(self._seen) >= self._FALLBACK_MAX:
            self._seen.clear()
        self._seen.add(key)
        return False

    def update_redis(self, redis_client) -> None:
        self._redis = redis_client


# Backward-compatibility alias (in case any code imported DuplicateFilter)
class DuplicateFilter(AlertDeduplicator):
    """
    DEPRECATED: DuplicateFilter operated on raw log lines.
    This alias now delegates to AlertDeduplicator (alert-level dedup).
    Kept for backward compatibility only.
    """
    async def is_duplicate(self, line: str) -> bool:
        """Legacy API: treats raw line as its own label/tier for backward compat."""
        h = hashlib.sha256(line.encode()).hexdigest()[:8]
        return await self.is_duplicate_alert("raw", h, 0)


# ─────────────────────────────────────────────────────────────────────────────
# 5. SSHBruteForceAggregator  (Redis ZSET + in-process fallback)
# ─────────────────────────────────────────────────────────────────────────────

class SSHBruteForceAggregator:
    """
    Tracks SSH failed login attempts per source IP using a sliding time window.

    Redis implementation: ZADD + ZREMRANGEBYSCORE + ZCARD on key "ssh:fail:{ip}".
    In-process fallback: list of timestamps per IP, pruned on each access.

    Public API:
        check_attempt(ip, ts=None)    → (triggered: bool, count: int)
        check_compromise(ip, ts=None) → (is_compromise: bool, fail_count: int)
        reset(ip)                     → clears the failure window for an IP

    IPv6 note: IPs are normalized before use as Redis keys. IPv6 colons are valid
    in Redis key names and do not require escaping.
    """

    def __init__(
        self,
        redis_client=None,
        threshold:      int = BRUTE_FORCE_THRESHOLD,
        window_seconds: int = BRUTE_FORCE_WINDOW_S,
    ):
        self._redis         = redis_client
        self.threshold      = threshold
        self.window_seconds = window_seconds
        self._windows: defaultdict[str, list[float]] = defaultdict(list)

    # ── Redis helpers ──────────────────────────────────────────────────────

    def _redis_key(self, ip: str) -> str:
        return f"ssh:fail:{_normalize_ip(ip)}"

    def _redis_add(self, ip: str, ts: float) -> int:
        """Add ts, prune old entries, return current count. Returns -1 on error."""
        try:
            key    = self._redis_key(ip)
            cutoff = ts - self.window_seconds
            pipe   = self._redis.pipeline()
            pipe.zadd(key, {str(ts): ts})
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zcard(key)
            pipe.expire(key, self.window_seconds + 10)
            results = pipe.execute()
            return results[2]   # ZCARD result
        except Exception as exc:
            logger.debug("BruteForceAggregator Redis error", error=str(exc))
            self._redis = None
            return -1

    def _redis_count(self, ip: str, ts: float) -> int:
        """Current failure count within window. Returns -1 on error."""
        try:
            key    = self._redis_key(ip)
            cutoff = ts - self.window_seconds
            return self._redis.zcount(key, cutoff, "+inf")
        except Exception as exc:
            logger.debug("BruteForceAggregator Redis count error", error=str(exc))
            self._redis = None
            return -1

    def _redis_delete(self, ip: str) -> None:
        try:
            self._redis.delete(self._redis_key(ip))
        except Exception:
            pass

    # ── In-process fallback helpers ────────────────────────────────────────

    def _local_add(self, ip: str, ts: float) -> int:
        norm   = _normalize_ip(ip)
        cutoff = ts - self.window_seconds
        window = [t for t in self._windows[norm] if t > cutoff]
        window.append(ts)
        self._windows[norm] = window
        return len(window)

    def _local_count(self, ip: str, ts: float) -> int:
        norm   = _normalize_ip(ip)
        cutoff = ts - self.window_seconds
        return sum(1 for t in self._windows[norm] if t > cutoff)

    # ── Public API ─────────────────────────────────────────────────────────

    def check_attempt(self, ip: str, ts: Optional[float] = None) -> tuple[bool, int]:
        """
        Record a failed login attempt for `ip`.
        Returns (triggered, count) where triggered=True when count ≥ threshold.

        NAT exemption: IPs in TRUSTED_NAT_RANGES are never triggered.
        """
        ts = ts or time.time()

        if _is_trusted_nat(ip):
            logger.debug("NAT-exempt IP skipped for brute-force tracking", ip=ip)
            return False, 0

        if self._redis is not None:
            count = self._redis_add(ip, ts)
        else:
            count = -1

        if count == -1:
            count = self._local_add(ip, ts)

        return count >= self.threshold, count

    def check_compromise(self, ip: str, ts: Optional[float] = None) -> tuple[bool, int]:
        """
        Called when a *successful* login is observed from `ip`.
        Returns (is_compromise, fail_count).
        If is_compromise=True, the failure window is reset (attack cycle is over).
        """
        ts = ts or time.time()

        if self._redis is not None:
            fail_count = self._redis_count(ip, ts)
        else:
            fail_count = -1

        if fail_count == -1:
            fail_count = self._local_count(ip, ts)

        if fail_count >= self.threshold:
            self.reset(ip)
            return True, fail_count

        return False, fail_count

    def reset(self, ip: str) -> None:
        """Clear the failure window for `ip`."""
        if self._redis is not None:
            self._redis_delete(ip)
        self._windows.pop(_normalize_ip(ip), None)

    def update_redis(self, redis_client) -> None:
        self._redis = redis_client


# ─────────────────────────────────────────────────────────────────────────────
# 6. DistributedBruteForceTracker  (cross-IP per username/port)
# ─────────────────────────────────────────────────────────────────────────────

class DistributedBruteForceTracker:
    """
    Detects low-and-slow distributed brute force where many source IPs each
    contribute a small number of failures against the same (username, port).

    Redis key: ssh:dist_fail:{username}:{port}
    Threshold: DIST_BRUTE_FORCE_THRESHOLD (env, default 20 attempts total)
    Window: BRUTE_FORCE_WINDOW_S (shared with per-IP aggregator)
    """

    def __init__(
        self,
        redis_client=None,
        threshold:      int = DIST_BRUTE_FORCE_THRESHOLD,
        window_seconds: int = BRUTE_FORCE_WINDOW_S,
    ):
        self._redis         = redis_client
        self.threshold      = threshold
        self.window_seconds = window_seconds
        self._windows: defaultdict[str, list[float]] = defaultdict(list)

    def _redis_key(self, username: str, port: int) -> str:
        safe_user = username.replace(":", "_")   # colons safe but keep keys clean
        return f"ssh:dist_fail:{safe_user}:{port}"

    def check_attempt(
        self, username: str, port: int, ts: Optional[float] = None
    ) -> tuple[bool, int]:
        """Record a failure; returns (triggered, cross_ip_count)."""
        ts = ts or time.time()

        if self._redis is not None:
            try:
                key    = self._redis_key(username, port)
                cutoff = ts - self.window_seconds
                pipe   = self._redis.pipeline()
                pipe.zadd(key, {str(ts): ts})
                pipe.zremrangebyscore(key, "-inf", cutoff)
                pipe.zcard(key)
                pipe.expire(key, self.window_seconds + 10)
                results = pipe.execute()
                count   = results[2]
                return count >= self.threshold, count
            except Exception as exc:
                logger.debug("DistBruteForce Redis error", error=str(exc))
                self._redis = None

        # In-process fallback
        key    = f"{username}:{port}"
        cutoff = ts - self.window_seconds
        window = [t for t in self._windows[key] if t > cutoff]
        window.append(ts)
        self._windows[key] = window
        count = len(window)
        return count >= self.threshold, count

    def update_redis(self, redis_client) -> None:
        self._redis = redis_client


# ─────────────────────────────────────────────────────────────────────────────
# 7. RiskScorer  (stateful, alert-level dedup integrated)
# ─────────────────────────────────────────────────────────────────────────────

import math


@dataclass
class RiskScore:
    risk_score: Optional[int]   # None means "log only, no alert"
    label:      Optional[str]
    severity:   Optional[str]

    @property
    def should_alert(self) -> bool:
        return self.risk_score is not None


_NO_ALERT = RiskScore(None, None, None)


class RiskScorer:
    """
    Stateful risk evaluation mapping from (event_type, context) → RiskScore.
    Tracks previous risk tiers in Redis to prevent alert storms.

    AlertDeduplicator is consulted at *return time* — after the tier is computed —
    which means the aggregation counter is always incremented before dedup fires.
    """

    def __init__(self, redis_client=None, timeout_s=BRUTE_FORCE_WINDOW_S,
                 alert_deduplicator: Optional[AlertDeduplicator] = None):
        self._redis        = redis_client
        self._ttl          = timeout_s
        self._local_tiers: dict[str, int] = {}
        self._dedup        = alert_deduplicator

    def _get_last_tier(self, ip: str) -> int:
        norm = _normalize_ip(ip)
        if self._redis:
            try:
                val = self._redis.get(f"ssh:risk:{norm}")
                if val:
                    return int(val)
            except Exception as exc:
                logger.debug("RiskScorer Redis get error", error=str(exc))
                self._redis = None
        return self._local_tiers.get(norm, 0)

    def _set_last_tier(self, ip: str, tier: int) -> None:
        norm = _normalize_ip(ip)
        if self._redis:
            try:
                self._redis.setex(f"ssh:risk:{norm}", self._ttl, str(tier))
            except Exception as exc:
                logger.debug("RiskScorer Redis set error", error=str(exc))
                self._redis = None
        self._local_tiers[norm] = tier

    def _clear_tier(self, ip: str) -> None:
        norm = _normalize_ip(ip)
        if self._redis:
            try:
                self._redis.delete(f"ssh:risk:{norm}")
            except Exception:
                pass
        self._local_tiers.pop(norm, None)

    def update_redis(self, redis_client) -> None:
        self._redis = redis_client

    def calculate_bruteforce_risk(self, fail_count: int) -> int:
        base  = 70
        scale = min(25, int(math.log(max(fail_count, 1), 2) * 5))
        return min(95, base + scale)

    def score(
        self,
        event_type:    SshEventType,
        ip:            str = "Unknown",
        fail_count:    int = 0,
        is_compromise: bool = False,
    ) -> RiskScore:

        if event_type == SshEventType.SSH_FAILED:
            if fail_count >= BRUTE_FORCE_THRESHOLD:
                new_risk = self.calculate_bruteforce_risk(fail_count)
                new_tier = (new_risk // 10) * 10
                prev_tier = self._get_last_tier(ip)

                candidate: Optional[RiskScore] = None

                # Initial alert → explicit 70
                if fail_count == BRUTE_FORCE_THRESHOLD and prev_tier == 0:
                    self._set_last_tier(ip, 70)
                    candidate = RiskScore(70, "SSH_BRUTEFORCE_ACTIVE", "High")

                # Tier escalation alert
                elif new_tier > max(prev_tier, 70):
                    self._set_last_tier(ip, new_tier)
                    candidate = RiskScore(new_tier, "SSH_BRUTEFORCE_ACTIVE", "High")

                if candidate is not None:
                    return candidate

            return _NO_ALERT

        if event_type in (SshEventType.SSH_SUCCESS, SshEventType.SSH_SESSION_OPEN):
            if is_compromise:
                self._clear_tier(ip)
                return RiskScore(95, "SSH_BRUTEFORCE_SUCCESS", "Critical")
            return _NO_ALERT

        if event_type == SshEventType.SSH_SUDO:
            return RiskScore(60, "Privilege Escalation (Sudo)", "Medium")

        return _NO_ALERT   # UNKNOWN → no alert
