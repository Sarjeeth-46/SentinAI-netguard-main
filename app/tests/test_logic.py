
import unittest
import time
import asyncio
import re
import sys
import os
sys.path.append('/app')
from app.services.detection_engine import (
    SSHBruteForceAggregator,
    SessionTracker,
    AlertDeduplicator,
    EventParser,
    SshEventType,
    DistributedBruteForceTracker,
    _normalize_ip,
    _is_trusted_nat,
    TRUSTED_NAT_NETWORKS,
    BRUTE_FORCE_THRESHOLD,
)
import ipaddress

class TestProtectionLogic(unittest.TestCase):
    
    def test_aggregator_sliding_window(self):
        print("\n[Test] Aggregator Sliding Window")
        agg = SSHBruteForceAggregator(threshold=5, window_seconds=2)
        
        # 1. Simulate 4 attempts (Should NOT trigger)
        ip = "192.168.1.100"
        for i in range(4):
            triggered, count = agg.check_attempt(ip, time.time())
            print(f"Attempt {i+1}: Triggered={triggered}, Count={count}")
            self.assertFalse(triggered)
            
        # 2. 5th attempt (Should TRIGGER)
        triggered, count = agg.check_attempt(ip, time.time())
        print(f"Attempt 5: Triggered={triggered}, Count={count}")
        self.assertTrue(triggered)
        
        # 3. 6th attempt (Should STILL trigger, because threshold was not reset)
        triggered, count = agg.check_attempt(ip, time.time())
        print(f"Attempt 6: Triggered={triggered}, Count={count}")
        self.assertTrue(triggered)

    def test_aggregator_expiry(self):
        print("\n[Test] Aggregator Window Expiry")
        agg = SSHBruteForceAggregator(threshold=2, window_seconds=1)
        ip = "10.0.0.5"
        
        agg.check_attempt(ip, time.time())
        time.sleep(1.1) # Wait for window to expire
        
        # Should be counted as 1st new attempt, not 2nd
        triggered, count = agg.check_attempt(ip, time.time())
        print(f"After Delay: Triggered={triggered}, Count={count}")
        self.assertFalse(triggered)
        self.assertEqual(count, 1)

    def test_event_parser(self):
        print("\n[Test] Event Parser Regex Extraction")
        from app.services.detection_engine import EventParser, SshEventType
        
        test_cases = [
            # pam_unix auth failure
            (
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root",
                SshEventType.SSH_FAILED, "1.2.3.4", "root"
            ),
            # max auth attempts exceeded
            (
                "error: maximum authentication attempts exceeded for root from 11.22.33.44 port 22 ssh2 [preauth]",
                SshEventType.SSH_FAILED, "11.22.33.44", "root"
            ),
            # Disconnecting authenticating user
            (
                "Disconnecting authenticating user testuser 9.9.9.9 port 22 [preauth]",
                SshEventType.SSH_FAILED, "9.9.9.9", "testuser"
            ),
            # pam_unix session opened
            (
                "pam_unix(sshd:session): session opened for user admin by (uid=0)",
                SshEventType.SSH_SESSION_OPEN, "Unknown", "admin"
            ),
            # sudo command execution
            (
                "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                SshEventType.SSH_SUDO, "Unknown", "admin"
            ),
            # CRON noise is ignored
            (
                "pam_unix(cron:session): session opened for user root by (uid=0)",
                SshEventType.UNKNOWN, "Unknown", "Unknown"
            )
        ]
        
        parser = EventParser()
        for line, expected_type, expected_ip, expected_user in test_cases:
            event = parser.parse(line)
            print(f"Log: {line[:40]}... -> {event.event_type.name} / IP: {event.source_ip} / User: {event.username}")
            self.assertEqual(event.event_type, expected_type)
            self.assertEqual(event.source_ip, expected_ip)
            self.assertEqual(event.username, expected_user)

import asyncio
from app.services.detection_engine import (
    DuplicateFilter,
    RiskScorer,
    SshEventType,
    RiskScore,
)

class TestDetectionEngine(unittest.TestCase):
    def test_duplicate_filter(self):
        print("\n[Test] DuplicateFilter fallback logic")
        filter = DuplicateFilter(redis_client=None, ttl=60)
        
        async def run_dedup():
            line = "Jul 15 12:00:00 server sshd[123]: Failed password for root"
            
            # First time -> not a duplicate
            is_dup = await filter.is_duplicate(line)
            self.assertFalse(is_dup)
            
            # Second time -> is a duplicate
            is_dup = await filter.is_duplicate(line)
            self.assertTrue(is_dup)
            
            # Different line -> not a duplicate
            is_dup = await filter.is_duplicate(line + " diff")
            self.assertFalse(is_dup)
            
        asyncio.run(run_dedup())

    def test_risk_scorer_failed_login(self):
        print("\n[Test] RiskScorer - Failed Login Adaptive Scaling")
        from app.services.detection_engine import RiskScorer, SshEventType
        
        scorer = RiskScorer()
        ip = "10.0.0.1"
        
        # Below threshold -> No alert
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=4)
        self.assertFalse(risk.should_alert)
        
        # At threshold (count=5) -> Explicitly triggers Risk 70 and sets tier 70
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=5)
        self.assertTrue(risk.should_alert)
        self.assertEqual(risk.risk_score, 70)
        self.assertEqual(risk.label, "SSH_BRUTEFORCE_ACTIVE")
        self.assertEqual(scorer._get_last_tier(ip), 70)
        
        # count=6 -> math risk 82, tier 80 -> >70 -> Fires!
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=6)
        self.assertTrue(risk.should_alert)
        self.assertEqual(risk.risk_score, 80)
        self.assertEqual(scorer._get_last_tier(ip), 80)

        # count=7 -> math risk 84, tier 80 -> NOT > 80 -> SUPPRESSED
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=7)
        self.assertFalse(risk.should_alert)
        
        # count=15 -> math risk 89, tier 80 -> NOT > 80 -> SUPPRESSED
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=15)
        self.assertFalse(risk.should_alert)

        # count=30 -> math risk 94, tier 90 -> > 80 -> FIRES!
        risk = scorer.score(SshEventType.SSH_FAILED, ip=ip, fail_count=30)
        self.assertTrue(risk.should_alert)
        self.assertEqual(risk.risk_score, 90)
        self.assertEqual(scorer._get_last_tier(ip), 90)

    def test_risk_scorer_successful_login(self):
        print("\n[Test] RiskScorer - Successful Login")
        # No prior failures -> no alert (informational only)
        from app.services.detection_engine import RiskScorer, SshEventType
        scorer = RiskScorer()
        ip = "10.0.0.2"

        risk = scorer.score(SshEventType.SSH_SUCCESS, ip=ip, is_compromise=False)
        self.assertFalse(risk.should_alert)
        
        # Success after failures -> Critical alert
        scorer._set_last_tier(ip, 80)
        risk = scorer.score(SshEventType.SSH_SUCCESS, ip=ip, is_compromise=True, fail_count=6)
        self.assertTrue(risk.should_alert)
        self.assertEqual(risk.severity, "Critical")
        self.assertEqual(risk.label, "SSH_BRUTEFORCE_SUCCESS")
        self.assertEqual(risk.risk_score, 95)
        self.assertEqual(scorer._get_last_tier(ip), 0)

    def test_risk_scorer_sudo(self):
        print("\n[Test] RiskScorer - Sudo Usage")
        from app.services.detection_engine import RiskScorer, SshEventType
        scorer = RiskScorer()
        risk = scorer.score(SshEventType.SSH_SUDO)
        self.assertTrue(risk.should_alert)
        self.assertEqual(risk.severity, "Medium")
        self.assertEqual(risk.label, "Privilege Escalation (Sudo)")

    def test_aggregator_compromise_detection(self):
        print("\n[Test] Aggregator Compromise Logic")
        agg = SSHBruteForceAggregator(threshold=3, window_seconds=10)
        ip = "10.10.10.10"
        
        # 1. Provide success immediately (0 prior fails). Should not trigger.
        is_comp, count = agg.check_compromise(ip, time.time())
        self.assertFalse(is_comp)
        self.assertEqual(count, 0)
        
        # 2. Add 3 fails (hits threshold)
        for _ in range(3):
            agg.check_attempt(ip, time.time())
            
        # 3. Successful login now triggers compromise and resets count
        is_comp, count = agg.check_compromise(ip, time.time())
        self.assertTrue(is_comp)
        self.assertEqual(agg._local_count(ip, time.time()), 0) # Count is 0 because the COMPROMISE alert reset it

        # --- Re-test compromise with a modified sequence to ensure fail_count is passed correctly ---
        agg2 = SSHBruteForceAggregator(threshold=5, window_seconds=10)
        ip2 = "20.20.20.20"
        
        # Add 4 fails (below threshold)
        for _ in range(4):
            agg2.check_attempt(ip2, time.time())
            
        # Success login happens while 4 fails exist (not quite a compromise but close)
        is_comp, count = agg2.check_compromise(ip2, time.time())
        self.assertFalse(is_comp)
        self.assertEqual(count, 4)


class TestDashboardConsistency(unittest.TestCase):
    """
    Verifies that the DashboardAggregator's pure computation helper
    always produces a mathematically consistent response:

        total_threats == sum(risk_levels.values())

    This test is DB-free and network-free — runs entirely in-process.
    """

    def _make_event(self, risk_score: float, label: str) -> dict:
        from datetime import datetime, timezone
        return {
            "id": str(id(object())),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.0.1",
            "risk_score": risk_score,
            "predicted_label": label,
        }

    def test_dashboard_consistency_basic(self):
        print("\n[Test] DashboardAggregator - KPI ↔ Chart consistency")
        from app.services.dashboard_aggregator import DashboardAggregator

        mock_events = [
            # critical (>=80)
            self._make_event(95, "SSH_BRUTEFORCE_SUCCESS"),
            self._make_event(82, "SSH_BRUTEFORCE_ACTIVE"),
            self._make_event(88, "SSH_BRUTEFORCE_SUCCESS"),
            # high (>=60, <80)
            self._make_event(75, "SSH_BRUTEFORCE_ACTIVE"),
            self._make_event(62, "PORT_SCAN"),
            # medium (>=30, <60)
            self._make_event(45, "PORT_SCAN"),
            self._make_event(30, "SSH_BRUTEFORCE_ACTIVE"),
            # low (<30)
            self._make_event(10, "NORMAL"),
            self._make_event(0,  "NORMAL"),
            self._make_event(5,  "NORMAL"),
        ]

        result = DashboardAggregator.get_overview_from_events(mock_events)

        total_threats = result["total_threats"]
        rl = result["risk_levels"]
        atd = result["attack_type_distribution"]

        # ── Invariant: total_threats == sum of all risk buckets ──────────
        bucket_sum = rl["critical"] + rl["high"] + rl["medium"] + rl["low"]
        print(f"  total_threats={total_threats}, bucket_sum={bucket_sum}")
        print(f"  risk_levels={rl}")
        self.assertEqual(
            total_threats, bucket_sum,
            f"KPI mismatch: total_threats={total_threats} != bucket_sum={bucket_sum}"
        )

        # ── Bucket values are correct ─────────────────────────────────────
        self.assertEqual(rl["critical"], 3)
        self.assertEqual(rl["high"],     2)
        self.assertEqual(rl["medium"],   2)
        self.assertEqual(rl["low"],      3)
        self.assertEqual(total_threats,  10)

        # ── Attack distribution sums match total_threats ─────────────────
        dist_sum = sum(atd.values())
        print(f"  attack_type_distribution={atd}, dist_sum={dist_sum}")
        self.assertEqual(
            dist_sum, total_threats,
            f"Attack distribution sum {dist_sum} != total_threats {total_threats}"
        )

        # ── Expected label counts ─────────────────────────────────────────
        self.assertEqual(atd.get("SSH_BRUTEFORCE_SUCCESS", 0), 2)
        self.assertEqual(atd.get("SSH_BRUTEFORCE_ACTIVE",  0), 3)
        self.assertEqual(atd.get("PORT_SCAN",              0), 2)
        self.assertEqual(atd.get("NORMAL",                 0), 3)

        print("  ✔ All consistency assertions passed.")

    def test_dashboard_empty_events(self):
        print("\n[Test] DashboardAggregator - Empty event list")
        from app.services.dashboard_aggregator import DashboardAggregator

        result = DashboardAggregator.get_overview_from_events([])
        self.assertEqual(result["total_threats"], 0)
        self.assertEqual(sum(result["risk_levels"].values()), 0)
        self.assertEqual(len(result["attack_type_distribution"]), 0)
        print("  ✔ Empty event list handled correctly.")

    def test_high_risk_kpi_matches_chart(self):
        """
        Simulates the frontend assertion:
            KPI 'High Risk' = risk_levels.critical + risk_levels.high
        And verifies this equals the sum of critical + high bars in the chart.
        """
        print("\n[Test] DashboardAggregator - High Risk KPI == (Critical + High) bar values")
        from app.services.dashboard_aggregator import DashboardAggregator

        mock_events = [
            self._make_event(90, "SSH_BRUTEFORCE_SUCCESS"),  # critical
            self._make_event(85, "SSH_BRUTEFORCE_SUCCESS"),  # critical
            self._make_event(70, "SSH_BRUTEFORCE_ACTIVE"),   # high
            self._make_event(65, "SSH_BRUTEFORCE_ACTIVE"),   # high
            self._make_event(25, "NORMAL"),                  # low
        ]
        result = DashboardAggregator.get_overview_from_events(mock_events)
        rl = result["risk_levels"]

        kpi_high_risk  = rl["critical"] + rl["high"]   # what frontend computes
        chart_critical = rl["critical"]                 # Critical bar
        chart_high     = rl["high"]                     # High bar

        print(f"  KPI High Risk={kpi_high_risk}, chart Critical={chart_critical}, chart High={chart_high}")
        # If the spec says "High Risk = 58" → both the KPI and the sum of bars must be 58
        self.assertEqual(kpi_high_risk, chart_critical + chart_high)
        self.assertEqual(kpi_high_risk, 4)  # 2 critical + 2 high
        print("  ✔ High Risk KPI matches bar chart values.")


class TestIPv6Support(unittest.TestCase):

    def test_ipv6_normalize(self):
        """IPv4-mapped IPv6 is unwrapped; compressed forms are stable."""
        print("\n[Test] _normalize_ip")
        self.assertEqual(_normalize_ip("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(_normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")
        self.assertEqual(_normalize_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(_normalize_ip("not-an-ip"), "not-an-ip")

    def test_ipv6_parser(self):
        """EventParser extracts IPv6 from auth lines."""
        print("\n[Test] EventParser IPv6 extraction")
        parser = EventParser()
        cases = [
            ("Failed password for root from 2001:db8::1 port 22 ssh2", SshEventType.SSH_FAILED, "2001:db8::1", "root"),
            ("Accepted publickey for admin from fe80::1 port 22 ssh2", SshEventType.SSH_SUCCESS, "fe80::1", "admin"),
        ]
        for line, exp_type, exp_ip, exp_user in cases:
            ev = parser.parse(line)
            self.assertEqual(ev.event_type, exp_type)
            self.assertEqual(ev.source_ip, exp_ip)
            self.assertEqual(ev.username, exp_user)

    def test_ipv6_aggregator(self):
        """IPv6 IPs increment the failure counter."""
        print("\n[Test] SSHBruteForceAggregator with IPv6 IP")
        agg = SSHBruteForceAggregator(threshold=3, window_seconds=10)
        ip = "2001:db8::dead:beef"
        for _ in range(2):
            trig, _ = agg.check_attempt(ip, time.time())
            self.assertFalse(trig)
        trig, count = agg.check_attempt(ip, time.time())
        self.assertTrue(trig)
        self.assertEqual(count, 3)

class TestSessionTracker(unittest.TestCase):
    def test_session_tracker_resolution(self):
        print("\n[Test] SessionTracker PID resolution")
        tracker = SessionTracker()
        tracker.record_auth(pid=1234, ip="1.2.3.4")
        self.assertEqual(tracker.resolve_session_ip(1234), "1.2.3.4")
        self.assertEqual(tracker.resolve_session_ip(9999), "Unknown")
        self.assertEqual(tracker.resolve_session_ip(None), "Unknown")

class TestAlertDeduplicator(unittest.TestCase):
    def test_alert_dedup(self):
        print("\n[Test] AlertDeduplicator")
        dedup = AlertDeduplicator()
        async def run():
            self.assertFalse(await dedup.is_duplicate_alert("SSH_BRUTEFORCE_ACTIVE", "1.2.3.4", 70))
            self.assertTrue(await dedup.is_duplicate_alert("SSH_BRUTEFORCE_ACTIVE", "1.2.3.4", 70))
            self.assertFalse(await dedup.is_duplicate_alert("SSH_BRUTEFORCE_ACTIVE", "1.2.3.4", 80))
        asyncio.run(run())

if __name__ == '__main__':
    unittest.main()
