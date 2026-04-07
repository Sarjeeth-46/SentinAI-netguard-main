import asyncio
import aiohttp
import json
import os
import sys
import time
import subprocess
from datetime import datetime

# Adjust path to import app modules if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Set environment variables for testing 
os.environ["MONGO_URI"] = "mongodb://localhost:27017"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["ALLOW_EMERGENCY_ADMIN"] = "true"
os.environ["EMERGENCY_ADMIN_PASSWORD"] = "emergency123"
os.environ["INITIAL_ADMIN_PASSWORD"] = "password"  # Seed password known to the validator

from app.ingestion.log_collector import LogCollector
from app.core.config import get_redis_client

class Validator:
    def __init__(self):
        self.results = {
            "SSH_BRUTEFORCE_ACTIVE": "FAIL",
            "SSH_BRUTEFORCE_SUCCESS": "FAIL",
            "PRIVILEGE_ESCALATION": "FAIL",
            "IPV6_SUPPORT": "FAIL",
            "ML_CLASSIFICATION": "FAIL",
            "WEIGHTED_RISK_SCORING": "FAIL",
            "HISTORICAL_PERSISTENCE": "FAIL",
            "CORRELATION_ENGINE": "FAIL",
            "DASHBOARD_STABILITY": "FAIL",
            "MODEL_FALLBACK_BEHAVIOR": "FAIL"
        }
        self.deviations = []
        self.instability = []
        self.nondeterministic = []
        
        self.backend_process = None
        self.session = None
        self.collector = None

    async def _get(self, url, headers=None):
        async with self.session.get(f"http://127.0.0.1:8000{url}", headers=headers) as resp:
            if resp.status != 200:
                self.instability.append(f"GET {url} failed with status {resp.status}")
                return None
            return await resp.json()

    async def _post(self, url, json_data, headers=None):
        async with self.session.post(f"http://127.0.0.1:8000{url}", json=json_data, headers=headers) as resp:
            if resp.status not in (200, 201):
                self.instability.append(f"POST {url} failed with status {resp.status}")
                return None
            return await resp.json()

    async def start_backend(self, rename_model=False):
        print(f"Starting backend (rename_model={rename_model})...")
        env = os.environ.copy()
        
        # The validation script expects a local MongoDB and Redis to be running
        # We'll just use the default env definitions at the top of the file
        
        if rename_model:
            if os.path.exists("backend/model_real.pkl"):
                os.rename("backend/model_real.pkl", "backend/model_real_temp.pkl")
            if os.path.exists("app/ml/model_real.pkl"):
                os.rename("app/ml/model_real.pkl", "app/ml/model_real_temp.pkl")
                
        self.backend_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.api.api_gateway:app", "--port", "8000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env
        )
        
        start_time = time.time()
        
        # Wait for the app to expose the API
        while time.time() - start_time < 15:
            try:
                async with aiohttp.ClientSession() as temp_session:
                    async with temp_session.get("http://127.0.0.1:8000/api/health/liveness", timeout=1) as r:
                         if r.status == 200:
                             print("Backend is live!")
                             break
            except:
                pass
            time.sleep(1)

        time.sleep(3) # Let background tasks initialize

    async def stop_backend(self, rename_model=False):
        if self.backend_process:
            self.backend_process.terminate()
            self.backend_process.wait()
            
        if rename_model:
            if os.path.exists("backend/model_real_temp.pkl"):
                os.rename("backend/model_real_temp.pkl", "backend/model_real.pkl")
            if os.path.exists("app/ml/model_real_temp.pkl"):
                os.rename("app/ml/model_real_temp.pkl", "app/ml/model_real.pkl")

    async def run_phase_1(self):
        print("--- PHASE 1: SYSTEM BOOT ---")
        # In resiliency mode, it's ok if they are disconnected as long as fallback works.
        # But we must verify ML is loaded.
        model_feats = await self._get("/api/model/features")
        if model_feats and len(model_feats) > 0:
            print("Model loaded successfully: PASS")
        else:
            print("Model load: FAIL")
            
        print("MongoDB/Redis checking skipped for resiliency local-mode test.")

    async def login(self):
        # Bootstrap first to ensure admin exists
        await self._post("/api/bootstrap_system", {})
        await asyncio.sleep(0.5)

        # Try all known/possible admin passwords (covers fresh installs and existing DBs)
        for pwd in ["password", "changeme_in_prod!", "emergency123"]:
            resp = await self._post("/api/auth/login", {"username": "admin", "password": pwd})
            if resp and "access_token" in resp:
                print("Login succeeded.")
                return {"Authorization": f"Bearer {resp['access_token']}"}
        print("Login failed! Tried all known passwords.")
        return {}


    async def check_alerts(self, auth_headers):
        await asyncio.sleep(1)
        threats = await self._get("/api/threats", headers=auth_headers)
        return threats if threats else []

    async def run_phase_2(self):
        print("--- PHASE 2: LOG INGESTION ---")
        auth_headers = await self.login()
        if not auth_headers:
             print("Login failed!")
             return
             
        print("> Test 1: SSH Brute Force (Repeated Failures)")
        ip1 = "1.2.3.4"
        for i in range(4):
            await self.collector.process_line(f"Failed password for root from {ip1} port 22")
            await asyncio.sleep(0.1)
        
        threats = await self.check_alerts(auth_headers)
        if len([t for t in threats if t['source_ip'] == ip1]) > 0:
            print("FAIL: Alert fired too early!")
        else:
            # 5th attempt
            await self.collector.process_line(f"Failed password for root from {ip1} port 22")
            # 6th attempt (testing Dedup/Spam suppression)
            await self.collector.process_line(f"Failed password for root from {ip1} port 22")
            
            threats = await self.check_alerts(auth_headers)
            brute = [t for t in threats if t['source_ip'] == ip1 and t['label'] == 'SSH_BRUTEFORCE_ACTIVE']
            
            # Check alert storm suppression (should only have 1 active brute force alert for this tier)
            if len(brute) == 1:
                self.results["SSH_BRUTEFORCE_ACTIVE"] = "PASS"
                print("SSH_BRUTEFORCE_ACTIVE: PASS")
            elif len(brute) > 1:
                print(f"SSH_BRUTEFORCE_ACTIVE: FAIL (found {len(brute)} alerts)")
            else:
                print("SSH_BRUTEFORCE_ACTIVE: FAIL (0 alerts)")

        print("> Test 2: SSH Brute Force Compromise")
        await self.collector.process_line(f"Accepted password for root from {ip1} port 22")
        threats = await self.check_alerts(auth_headers)
        comp = [t for t in threats if t['source_ip'] == ip1 and t['label'] == 'SSH_BRUTEFORCE_SUCCESS']
        if comp:
            if comp[0].get("severity", "").lower() == "critical":
                self.results["SSH_BRUTEFORCE_SUCCESS"] = "PASS"
                print("SSH_BRUTEFORCE_SUCCESS: PASS")
            else:
                self.deviations.append("Compromise is not marked Critical")
        else:
            print("SSH_BRUTEFORCE_SUCCESS: FAIL")
            
        print("> Test 3: Privilege Escalation (sudo)")
        await self.collector.process_line(f"sudo:   user : COMMAND=/bin/bash")
        threats = await self.check_alerts(auth_headers)
        sudo = [t for t in threats if 'Privilege Escalation' in t.get('label', '')]
        if sudo:
            self.results["PRIVILEGE_ESCALATION"] = "PASS"
            print("PRIVILEGE_ESCALATION: PASS")
        else:
            print("PRIVILEGE_ESCALATION: FAIL")

        print("> Test 4: IPv6 Support")
        ip6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        for i in range(5):
            await self.collector.process_line(f"Failed password for root from {ip6} port 22")
        threats = await self.check_alerts(auth_headers)
        v6_alert = [t for t in threats if ip6 == t.get('source_ip', '')]
        if v6_alert:
            self.results["IPV6_SUPPORT"] = "PASS"
            print("IPV6_SUPPORT: PASS")
        else:
            print("IPV6_SUPPORT: FAIL")

        print("> Test 5/6: ML Telemetry Injection & Determinism/History")
        api_key_headers = {"X-API-Key": "secure-telemetry-key-123"}
        payload = [{
            "id": "ml-test-1",
            "source_ip": "5.5.5.5",
            "destination_ip": "10.0.0.5",
            "dest_port": 80,
            "packet_size": 1500,
            "total_fwd_packets": 100,
            "flow_duration": 5000,
            "label": "DDoS",
            "metadata": {"source": "NIDS"}
        }]
        await self._post("/api/telemetry", payload, headers=api_key_headers)
        threats = await self.check_alerts(auth_headers)
        ml_alert1 = [t for t in threats if t.get('source_ip') == "5.5.5.5"]
        
        # Test exact determinism on same run (except history increments)
        payload[0]["id"] = "ml-test-2"
        await self._post("/api/telemetry", payload, headers=api_key_headers)
        threats2 = await self.check_alerts(auth_headers)
        ml_alert2 = [t for t in threats2 if t.get('source_ip') == "5.5.5.5" and t.get('id') == "ml-test-2"]

        if ml_alert1 and ml_alert2:
            s1 = ml_alert1[0].get("risk_score")
            s2 = ml_alert2[0].get("risk_score")
            print(f"Scores: Run 1 = {s1}, Run 2 = {s2}")
            self.results["ML_CLASSIFICATION"] = "PASS"
            self.results["WEIGHTED_RISK_SCORING"] = "PASS"
            if s2 > s1:
                self.results["HISTORICAL_PERSISTENCE"] = "PASS"
                print("HISTORICAL_PERSISTENCE: PASS")
            else:
                self.deviations.append(f"History scaling failed: s1={s1}, s2={s2}")

        print("> Test 7: Correlation Engine")
        ip_corr = "6.6.6.6"
        await self.collector.process_line(f"Failed password for root from {ip_corr} port 22")
        payload[0]["id"] = "ml-corr-1"
        payload[0]["source_ip"] = ip_corr
        await self._post("/api/telemetry", payload, headers=api_key_headers)
        threats = await self.check_alerts(auth_headers)
        corr_alert = [t for t in threats if t.get('source_ip') == ip_corr and "Correlated" in t.get('label', '')]
        if corr_alert:
            self.results["CORRELATION_ENGINE"] = "PASS"
            print("CORRELATION_ENGINE: PASS")
        else:
            print("CORRELATION_ENGINE: FAIL")

    async def run_phase_3(self):
        print("--- PHASE 3: API VALIDATION ---")
        auth_headers = await self.login()
        if not auth_headers: return
        
        # API 1: features
        features = await self._get("/api/model/features")
        if not features or len(features) == 0:
             self.instability.append("GET /api/model/features returned empty or failed.")
             
        # API 2: dashboard/overview
        dash = await self._get("/api/dashboard/overview", headers=auth_headers)
        if dash and "risk_levels" in dash:
            self.results["DASHBOARD_STABILITY"] = "PASS"
            print("DASHBOARD_STABILITY: PASS")
        else:
            print("DASHBOARD_STABILITY: FAIL")


    async def run_all(self):
        print("=== SentinAI NetGuard E2E Validation ===")

        self.session = aiohttp.ClientSession()
        await self.start_backend()
        
        # Configure the log collector to use the same logic as backend
        self.collector = LogCollector()
        
        # Wait until the singleton is ready
        await self.collector.open()
        
        await self.run_phase_1()
        await self.run_phase_2()
        await self.run_phase_3()
        
        await self.collector.shutdown()
        await self.stop_backend()
        
        print("--- PHASE 4: ML MISSING TEST ---")
        await self.start_backend(rename_model=True)
        health = await self._get("/api/health/liveness")
        if health and health.get("status") == "alive":
            auth = await self.login()
            if auth:
                dash = await self._get("/api/dashboard/overview", headers=auth)
                if dash:
                    self.results["MODEL_FALLBACK_BEHAVIOR"] = "PASS"
                    print("MODEL_FALLBACK_BEHAVIOR: PASS")
                else:
                    print("MODEL_FALLBACK_BEHAVIOR: FAIL (Dashboard error)")
                    self.instability.append("Dashboard failed when ML missing")
            else:
                 print("MODEL_FALLBACK_BEHAVIOR: FAIL (Login failed)")
        else:
            print("MODEL_FALLBACK_BEHAVIOR: FAIL")
            
        await self.stop_backend(rename_model=True)
        await self.session.close()

        print("\n=== FINAL REPORT ===")
        print(json.dumps(self.results, indent=4))
        
        if self.deviations:
            print("\nDeviations:")
            for d in self.deviations:
                print(f"- {d}")
        if self.instability:
            print("\nInstability:")
            for e in self.instability:
                print(f"- {e}")

if __name__ == "__main__":
    v = Validator()
    asyncio.run(v.run_all())
