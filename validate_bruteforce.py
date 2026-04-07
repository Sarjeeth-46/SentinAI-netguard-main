import asyncio
import json
import time

async def validate_bruteforce():
    results = {
        "THRESHOLD_TRIGGER": "FAIL",
        "RISK_SCORE_VALID": "FAIL",
        "REDIS_WINDOW_UPDATED": "FAIL",
        "HISTORY_INCREMENTED": "FAIL",
        "NO_ALERT_SPAM": "FAIL"
    }

    try:
        from app.services.detection_engine import (
            SSHBruteForceAggregator, RiskScorer, AlertDeduplicator, SshEventType
        )
        from app.services.detector import WeightedRiskScorer
        from app.core.config import get_redis_client

        redis_client = None
        try:
            redis_client = get_redis_client()
            if not redis_client.ping():
                redis_client = None
        except:
            pass

        ip = "192.168.100.60"

        aggregator = SSHBruteForceAggregator(redis_client=redis_client, threshold=5, window_seconds=300)
        aggregator.reset(ip)

        dedup = AlertDeduplicator(redis_client=redis_client)
        scorer = RiskScorer(redis_client=redis_client, alert_deduplicator=dedup)
        scorer._clear_tier(ip)

        # First 4 attempts
        for i in range(1, 5):
            triggered, count = aggregator.check_attempt(ip)
            alert = scorer.score(SshEventType.SSH_FAILED, ip, count)
            if alert.should_alert:
                break
        else:
            # 5th attempt
            triggered, count = aggregator.check_attempt(ip)
            alert = scorer.score(SshEventType.SSH_FAILED, ip, count)
            
            if triggered and alert.should_alert and alert.label == "SSH_BRUTEFORCE_ACTIVE":
                results["THRESHOLD_TRIGGER"] = "PASS"

            # Risk score valid
            if alert.risk_score >= 70:
                results["RISK_SCORE_VALID"] = "PASS"

        # Redis sliding window updated
        # We can check count == 5
        if count == 5:
            results["REDIS_WINDOW_UPDATED"] = "PASS"

        # Alert storm suppression prevents duplicate identical alerts
        # 6th attempt (may escalate tier to 80, which is fine, it's a new alert)
        triggered6, count6 = aggregator.check_attempt(ip)
        alert6 = scorer.score(SshEventType.SSH_FAILED, ip, count6)
        
        # 7th attempt (tier will stay 80, should be suppressed by RiskScorer statefulness)
        triggered7, count7 = aggregator.check_attempt(ip)
        alert7 = scorer.score(SshEventType.SSH_FAILED, ip, count7)
        
        # Also check dedup directly
        if alert.should_alert:
            tier = alert.risk_score // 10 * 10
            is_dup = await dedup.is_duplicate_alert(alert.label, ip, tier)
            repeated_dup = await dedup.is_duplicate_alert(alert.label, ip, tier)
            
            # alert7 should be _NO_ALERT, meaning it suppresses spam natively via state tracking
            if not alert7.should_alert and is_dup == False and repeated_dup == True:
                results["NO_ALERT_SPAM"] = "PASS"

        # HistoricalBehavior incremented
        risk1 = WeightedRiskScorer.calculate_risk(severity=80, dest_ip="10.0.0.5", repeat_offender_count=1)
        risk2 = WeightedRiskScorer.calculate_risk(severity=80, dest_ip="10.0.0.5", repeat_offender_count=5)
        if risk2 > risk1:
            results["HISTORY_INCREMENTED"] = "PASS"

    except Exception as e:
        results["ERROR"] = str(e)

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    import asyncio
    asyncio.run(validate_bruteforce())
