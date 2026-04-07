import os
import asyncio
import structlog
from app.db.connection import db

logger = structlog.get_logger("IPReputation")

class IPReputationManager:
    """Optional Redis-backed IP scoring system."""
    
    def __init__(self, alert_threshold: int = 10, silence_duration: int = 300):
        self.alert_threshold = alert_threshold
        self.silence_duration = silence_duration

    async def start(self):
        # Redis connection is managed by db.connect() in main.py
        pass

    async def stop(self):
        pass

    async def apply_score(self, ip: str, points: int) -> tuple[bool, int]:
        """
        Increments the IP threat score.
        Returns (should_alert, current_score).
        """
        if db.redis is None:
            return False, 0
            
        score_key = f"ip:score:{ip}"
        silence_key = f"ip:silence:{ip}"

        try:
            if await db.redis.exists(silence_key):
                score = await db.redis.get(score_key)
                return False, int(score) if score else 0

            current_score = await db.redis.incrby(score_key, points)
            await db.redis.expire(score_key, 3600)

            if current_score >= self.alert_threshold:
                await db.redis.setex(silence_key, self.silence_duration, "1")
                return True, current_score

            return False, current_score
        except Exception as exc:
            logger.error("redis_apply_score_failed", ip=ip, error=str(exc))
            return False, 0

ip_reputation_manager = IPReputationManager()
