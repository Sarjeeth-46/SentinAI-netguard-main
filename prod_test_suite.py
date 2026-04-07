"""
SentinAI NetGuard - Production Grade Test Suite (Windows-safe, ASCII-only output)
All results written to qa_report.json for reliable reading.
"""
import requests, json, uuid, time, sys, traceback
from datetime import datetime, timezone

BASE = "http://127.0.0.1:8000"
TELEMETRY_KEY = "secure-telemetry-key-123"

passed = failed = warned = 0
results = []

def check(name, condition, detail=""):
    global passed, failed
    status = "PASS" if condition else "FAIL"
    msg = f"  [{status}]  {name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append({"name": name, "status": status, "detail": detail})
    if condition:
        passed += 1
    else:
        failed += 1
    return condition

def warn(name, detail=""):
    global warned
    print(f"  [WARN]  {name}  ({detail})")
    results.append({"name": name, "status": "WARN", "detail": detail})
    warned += 1

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def safe_get(session, path, **kwargs):
    try:
        t0 = time.time()
        r  = session.get(f"{BASE}{path}", timeout=10, **kwargs)
        return r, round(time.time() - t0, 3)
    except Exception as e:
        return None, 0.0

def safe_post(session, path, **kwargs):
    try:
        t0 = time.time()
        r  = session.post(f"{BASE}{path}", timeout=10, **kwargs)
        return r, round(time.time() - t0, 3)
    except Exception as e:
        return None, 0.0

def check_r(name, r, expected=200, detail=""):
    if r is None:
        return check(name, False, "connection error")
    fail_msg = f" (got {r.status_code})" if r.status_code != expected else ""
    return check(name, r.status_code == expected, f"{detail}{fail_msg}".strip())

def check_in(name, r, codes=(200,), detail=""):
    if r is None:
        return check(name, False, "connection error")
    fail_msg = f" (got {r.status_code})" if r.status_code not in codes else ""
    return check(name, r.status_code in codes, f"{detail}{fail_msg}".strip())


# ── PHASE 1: Health & Liveness ────────────────────────────────
section("PHASE 1 - Health & Liveness")

s = requests.Session()

r, dt = safe_get(s, "/api/health/liveness")
check_r("GET /api/health/liveness -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    b = r.json()
    check("liveness status='alive'",     b.get("status") == "alive")
    check("liveness has uptime_seconds", "uptime_seconds" in b)

r, dt = safe_get(s, "/api/health/readiness")
check_in("GET /api/health/readiness -> 200 or 503", r, (200, 503), f"{dt}s")

r, dt = safe_get(s, "/api/health")
check_r("GET /api/health (legacy) -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    b = r.json()
    check("health threat_engine=ready", b.get("threat_engine") == "ready")
    if dt > 2.0:
        warn("Health endpoint slow", f"{dt}s")

# ── PHASE 2: Authentication ───────────────────────────────────
section("PHASE 2 - Authentication")

token = None
for pwd in ["changeme_in_prod!", "Admin@123", "admin", "password"]:
    r, _ = safe_post(s, "/api/auth/login", json={"username": "admin", "password": pwd})
    if r and r.status_code == 200:
        token = r.json().get("access_token") or r.cookies.get("access_token")
        check(f"Login with password ok", bool(token), f"len={len(token) if token else 0}")
        break

if not token:
    # Try bootstrap
    safe_post(s, "/bootstrap_system", json={})
    r, _ = safe_post(s, "/api/auth/login", json={"username": "admin", "password": "changeme_in_prod!"})
    if r and r.status_code == 200:
        token = r.json().get("access_token")
    check("Login succeeded after bootstrap", bool(token))

auth = {"Authorization": f"Bearer {token}"} if token else {}

r, _ = safe_post(s, "/api/auth/login", json={"username": "admin", "password": "WRONG_PASS_XYZ"})
check_r("Login bad password -> 401",  r, 401)

r, _ = safe_post(s, "/api/auth/login", json={"username": "admin"})
check_r("Login missing password -> 422", r, 422)

r, _ = safe_post(s, "/api/auth/login", json={})
check_r("Login empty body -> 422",    r, 422)

r, dt = safe_get(s, "/api/auth/me", headers=auth)
check_r("GET /api/auth/me (auth) -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    me = r.json()
    check("me.username = admin",  me.get("username") == "admin")
    check("me.role present",      "role" in me)

# Use fresh sessions (no cookies) for auth boundary checks
unauth = requests.Session()
r, _ = safe_get(unauth, "/api/auth/me")
check_r("GET /api/auth/me (no token) -> 401", r, 401)

# ── PHASE 3: Dashboard APIs ───────────────────────────────────
section("PHASE 3 - Dashboard APIs")

r, dt = safe_get(s, "/api/dashboard/overview", headers=auth)
check_r("GET /api/dashboard/overview -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    ov = r.json()
    total = ov.get("total_threats", -1)
    rl    = ov.get("risk_levels", {})
    check("overview has total_threats (int)", isinstance(total, int) and total >= 0)
    check("overview has risk_levels",         "risk_levels" in ov)
    check("overview has attack_type_distribution", "attack_type_distribution" in ov)
    check("overview has window_minutes",      "window_minutes" in ov)
    check("overview has computed_at",         "computed_at" in ov)
    derived = sum(rl.get(k, 0) for k in ["critical", "high", "medium", "low"])
    check("total_threats == sum(risk_levels)", total == derived, f"total={total} derived={derived}")
    if dt > 2.0:
        warn("overview slow", f"{dt}s")

r, _ = safe_get(unauth, "/api/dashboard/overview")
check_r("Dashboard overview without auth -> 401", r, 401)

r, dt = safe_get(s, "/api/dashboard/summary", headers=auth)
check_in("GET /api/dashboard/summary (compat) -> 200/404", r, (200, 404), f"{dt}s")

# ── PHASE 4: Threats Endpoint ─────────────────────────────────
section("PHASE 4 - Threats Endpoint")

r, dt = safe_get(s, "/api/threats", headers=auth)
check_r("GET /api/threats -> 200", r, 200, f"{dt}s")
threat_list = []
if r and r.status_code == 200:
    threat_list = r.json()
    check("threats is a list",           isinstance(threat_list, list))
    check("threats count > 0 (has data)",len(threat_list) > 0, f"count={len(threat_list)}")
    if threat_list:
        t0 = threat_list[0]
        check("threat has id",           "id" in t0)
        check("threat has source_ip",    "source_ip" in t0)
        check("threat has risk_score",   "risk_score" in t0)
        check("threat has timestamp",    "timestamp" in t0)
        rs = t0.get("risk_score", -1)
        check("risk_score in [0,100]",   0 <= rs <= 100, f"got {rs}")
    if dt > 2.0:
        warn("Threats endpoint slow", f"{dt}s")

today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
r, dt = safe_get(s, "/api/threats", headers=auth, params={
    "start_time": f"{today}T00:00:00+00:00",
    "end_time":   f"{today}T23:59:59+00:00",
})
check_r("GET /api/threats (date filtered today) -> 200", r, 200, f"{dt}s count={len(r.json()) if r and r.status_code==200 else '?'}")
if r and r.status_code == 200:
    check("date-filtered threats count > 0", len(r.json()) > 0, f"count={len(r.json())}")

r, _ = safe_get(unauth, "/api/threats")
check_r("GET /api/threats (no auth) -> 401", r, 401)

# ── PHASE 5: Telemetry Ingestion ──────────────────────────────
section("PHASE 5 - Telemetry Ingestion")

tel = {"X-API-Key": TELEMETRY_KEY}
test_id = str(uuid.uuid4())
payload = [{
    "id":           test_id,
    "source_ip":    "11.22.33.44",
    "destination_ip":"10.0.5.50",
    "protocol":     "TCP",
    "packet_size":  3050,
    "dest_port":    80,
    "label":        "DDoS",
    "risk_score":   87.5,
    "confidence":   0.92,
}]
r, dt = safe_post(s, "/api/telemetry", json=payload, headers=tel)
check_r("POST /api/telemetry (valid) -> 201", r, 201, f"{dt}s")
if r and r.status_code == 201:
    b = r.json()
    check("telemetry status=enqueued",  b.get("status") == "enqueued")
    check("telemetry count=1",          b.get("count") == 1)

r, _ = safe_post(s, "/api/telemetry", json=payload, headers={"X-API-Key": "WRONG_KEY"})
check_r("POST /api/telemetry (bad key) -> 403", r, 403)

r, _ = safe_post(s, "/api/telemetry", json=payload)
check_r("POST /api/telemetry (no key) -> 403",  r, 403)

r, _ = safe_post(s, "/api/telemetry", json=[], headers=tel)
check_r("POST /api/telemetry (empty batch) -> 201", r, 201)
if r and r.status_code == 201:
    check("empty batch status=ignored", r.json().get("status") == "ignored")

time.sleep(5)  # give pipeline time to process and persist

r, _ = safe_get(s, "/api/threats", headers=auth)
if r and r.status_code == 200:
    found = any(t.get("id") == test_id or t.get("source_ip") == "11.22.33.44"
                for t in r.json())
    check("Ingested event appears in /api/threats", found)

# ── PHASE 6: ML Model Endpoints ───────────────────────────────
section("PHASE 6 - ML Model Endpoints")

r, dt = safe_get(s, "/api/model/metrics")
check_r("GET /api/model/metrics -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    m = r.json()
    check("metrics has accuracy",      "accuracy" in m)
    acc = m.get("accuracy", -1)
    check("accuracy in [0,1]",         0.0 <= acc <= 1.0, f"acc={acc}")

r, dt = safe_get(s, "/api/model/features")
check_r("GET /api/model/features -> 200", r, 200, f"{dt}s")
if r and r.status_code == 200:
    feats = r.json()
    check("features is non-empty list", isinstance(feats, list) and len(feats) > 0, f"count={len(feats)}")
    if feats:
        f0 = feats[0]
        check("feature has 'feature' key",    "feature" in f0)
        check("feature has 'importance' key", "importance" in f0)

# ── PHASE 7: Reports ──────────────────────────────────────────
section("PHASE 7 - Report Generation")

rpt_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
r, dt = safe_post(s, "/api/reports/generate", json={"date": rpt_date}, headers=auth)
check_in("POST /api/reports/generate -> 200 or 201", r, (200, 201), f"{dt}s")

r, dt = safe_get(s, f"/api/reports/{rpt_date}", headers=auth)
check_r("GET /api/reports/{today} -> 200", r, 200, f"{dt}s")

r, _ = safe_get(s, "/api/reports/1999-01-01", headers=auth)
check_r("GET /api/reports/1999-01-01 (missing) -> 404", r, 404)

# ── PHASE 8: Threat Actions ───────────────────────────────────
section("PHASE 8 - Threat Actions")

real_id = threat_list[0].get("id") if threat_list else None

if real_id:
    r, dt = safe_post(s, f"/api/threats/{real_id}/resolve", headers=auth)
    check_r(f"POST /api/threats/{{id}}/resolve -> 200", r, 200, f"{dt}s")

    r, dt = safe_post(s, f"/api/threats/{real_id}/block", headers=auth)
    check_in(f"POST /api/threats/{{id}}/block -> 200 or 404", r, (200, 404), f"{dt}s")
else:
    warn("Threat actions skipped", "No threats in list")

fake_id = str(uuid.uuid4())
r, _ = safe_post(s, f"/api/threats/{fake_id}/resolve", headers=auth)
check_r("Resolve non-existent threat -> 404", r, 404)

r, _ = safe_post(unauth, f"/api/threats/{fake_id}/resolve")
check_r("Resolve (no auth) -> 401", r, 401)

# ── PHASE 9: Security Validation ──────────────────────────────
section("PHASE 9 - Security Validation")

r, _ = safe_get(s, "/api/reports/1' OR '1'='1", headers=auth)
check("SQLi in URL path -> not 500", r is None or r.status_code != 500, f"got {r.status_code if r else 'none'}")

r, _ = safe_post(s, "/api/reports/generate", json={"date": "<script>alert(1)</script>"}, headers=auth)
check("XSS payload in body -> not 500", r is None or r.status_code not in (500,), f"got {r.status_code if r else 'none'}")

for endpoint in ["/api/threats", "/api/dashboard/overview"]:
    r2, _ = safe_get(unauth, endpoint)
    check_r(f"Unauthenticated {endpoint} -> 401", r2, 401)

r, _ = safe_get(s, "/api/threats", headers={"Authorization": "Bearer tampered.invalid.jwt.token"})
check_r("Tampered JWT -> 401", r, 401)

# Security headers check
r, _ = safe_get(s, "/api/health/liveness")
if r:
    lower_headers = {k.lower(): v for k, v in r.headers.items()}
    check("X-Content-Type-Options header",  "x-content-type-options" in lower_headers,
          lower_headers.get("x-content-type-options", "MISSING"))

# ── PHASE 10: Network Topology ────────────────────────────────
section("PHASE 10 - Network Topology")

r, dt = safe_get(s, "/api/network/topology", headers=auth)
check_in("GET /api/network/topology -> 200 or 404", r, (200, 404), f"{dt}s")
if r and r.status_code == 200:
    topo = r.json()
    check("topology has nodes", "nodes" in topo)
    check("topology has links", "links" in topo)

# ── PHASE 11: System Mode ─────────────────────────────────────
section("PHASE 11 - System Mode")

r, dt = safe_get(s, "/api/system/mode")
check_in("GET /api/system/mode -> 200 or 404", r, (200, 404), f"{dt}s")
if r and r.status_code == 200:
    check("mode is local or cloud", r.json().get("mode") in ("local", "cloud"))

r, _ = safe_post(s, "/api/system/mode", json={"mode": "invalid_mode"})
check("POST /api/system/mode (invalid) -> not 200", r is None or r.status_code != 200)

# ── PHASE 12: Edge Cases ──────────────────────────────────────
section("PHASE 12 - Edge Cases & Robustness")

r, _ = safe_post(s, "/api/telemetry",
    json=[{"source_ip": "99.88.77.66", "label": "Port Scan"}],
    headers=tel)
check_r("Telemetry minimal fields -> 201", r, 201)

r, _ = safe_get(s, "/api/nonexistent_endpoint_xyz_abc")
check("Unknown endpoint -> 404", r is None or r.status_code == 404, f"got {r.status_code if r else 'none'}")

r, _ = safe_get(s, f"/api/reports/{'x'*200}", headers=auth)
check("Very long path -> not 500", r is None or r.status_code != 500, f"got {r.status_code if r else 'none'}")

# Concurrent requests stress (5 parallel health checks via sequential approx)
latencies = []
for _ in range(5):
    r, dt = safe_get(s, "/api/health/liveness")
    if r and r.status_code == 200:
        latencies.append(dt)
avg_lat = sum(latencies) / len(latencies) if latencies else 0
check("5x health check all 200",         len(latencies) == 5, f"ok={len(latencies)}")
check("avg health latency < 1s",         avg_lat < 1.0, f"avg={avg_lat:.3f}s")

# ── FINAL SUMMARY ─────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  FINAL RESULTS")
print(f"{'='*60}")
print(f"  PASSED: {passed}")
print(f"  FAILED: {failed}")
print(f"  WARNED: {warned}")
print(f"  Total : {passed + failed + warned}")
overall = "PASS" if failed == 0 else "FAIL"
print(f"  Overall: {overall}")
print(f"{'='*60}\n")

report = {
    "overall": overall, "passed": passed, "failed": failed,
    "warned": warned, "timestamp": datetime.now().isoformat(), "tests": results
}
with open("qa_report.json", "w") as f:
    json.dump(report, f, indent=2)
print("  Report saved to qa_report.json")
sys.exit(0 if failed == 0 else 1)
