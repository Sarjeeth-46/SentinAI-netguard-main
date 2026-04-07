import requests
import time
import json
import uuid

BASE_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:58935"

report = {
    "overall_status": "PASS",
    "tested_endpoints": [],
    "failures": [],
    "security_issues": [],
    "performance_warnings": [],
    "recommendations": []
}

def log_result(phase, endpoint, status, time_taken, error=None, expected_status=200):
    report["tested_endpoints"].append(endpoint)
    if time_taken > 2.0:
         report["performance_warnings"].append(f"[{phase}] {endpoint} took {time_taken:.2f}s")
         
    if status != expected_status:
        # Check if it was expected to be a different status
        if status not in [expected_status]:
            report["failures"].append({"phase": phase, "endpoint": endpoint, "status": status, "error": error or f"Expected {expected_status}, got {status}"})
            report["overall_status"] = "FAIL"
            print(f"FAIL: [{phase}] {endpoint} returned {status}")
            return False
    print(f"PASS: [{phase}] {endpoint} (time: {time_taken:.2f}s)")
    return True

print("=== Starting QA Automation & Security Validation ===")

# Phase 1: System Bootstrap
try:
    start = time.time()
    res = requests.post(f"{BASE_URL}/bootstrap_system")
    dur = time.time() - start
    # The prompt expects 200 OK.
    log_result("Bootstrap", "/bootstrap_system", res.status_code, dur, expected_status=200)
except Exception as e:
    report["failures"].append({"phase": "Bootstrap", "endpoint": "/bootstrap_system", "error": str(e)})

# Start session
session = requests.Session()
token = None

# Phase 2: Authentication
print("\n--- Phase 2: Authentication ---")
try:
    # 1. Valid Credentials
    start = time.time()
    res = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "changeme_in_prod!"})
    dur = time.time() - start
    if res.status_code == 200:
        token = res.cookies.get("access_token") or res.json().get("access_token")
        if token:
            session.headers.update({"Authorization": f"Bearer {token}"})
    log_result("Auth", "/api/auth/login (Valid)", res.status_code, dur, expected_status=200)
    
    # 2. Invalid Password
    res_inv = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    log_result("Auth", "/api/auth/login (Invalid Pass)", res_inv.status_code, 0, expected_status=401)
    
    # 3. Missing Fields
    res_miss = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin"})
    log_result("Auth", "/api/auth/login (Missing Fields)", res_miss.status_code, 0, expected_status=422)

except Exception as e:
    report["failures"].append({"phase": "Auth", "endpoint": "/api/auth/login", "error": str(e)})


# Phase 3: Core Functional APIs
print("\n--- Phase 3: Core Functional APIs ---")
try:
    # Get Exec Summary
    start = time.time()
    res = session.get(f"{BASE_URL}/api/dashboard/summary")
    dur = time.time() - start
    log_result("Core", "/api/dashboard/summary", res.status_code, dur, expected_status=200)

    # Mitigation (Mock Threat ID)
    start = time.time()
    threat_id = str(uuid.uuid4())
    res_m1 = session.post(f"{BASE_URL}/api/threats/{threat_id}/block")
    dur = time.time() - start
    # Might be 404 or success depending on implementation, let's allow 200
    log_result("Core", f"/api/threats/{threat_id}/block (Valid)", res.status_code, dur, expected_status=200)
    
    # Generate Report
    start = time.time()
    date_str = "2024-05-10"
    res_gr = session.post(f"{BASE_URL}/api/reports/generate", json={"date": date_str})
    dur = time.time() - start
    log_result("Core", "/api/reports/generate (Valid)", res_gr.status_code, dur, expected_status=200)
    
    # Get Report
    start = time.time()
    res_get = session.get(f"{BASE_URL}/api/reports/{date_str}")
    dur = time.time() - start
    log_result("Core", f"/api/reports/{date_str} (Valid)", res_get.status_code, dur, expected_status=200)

    # Get non-existent report
    res_get_miss = session.get(f"{BASE_URL}/api/reports/1999-01-01")
    log_result("Core", "/api/reports/1999-01-01 (Missing)", res_get_miss.status_code, 0, expected_status=404)

except Exception as e:
    report["failures"].append({"phase": "Core APIs", "endpoint": "Multiple", "error": str(e)})


# Phase 7: Health Check
print("\n--- Phase 7: Health Check ---")
try:
    start = time.time()
    res_health = requests.get(f"{BASE_URL}/api/health")
    dur = time.time() - start
    
    log_result("Health", "/api/health", res_health.status_code, dur, expected_status=200)
    
    if res_health.status_code == 200:
        h_data = res_health.json()
        if "uptime_seconds" not in h_data or h_data.get("threat_engine") != "ready":
             report["failures"].append({"phase": "Health", "endpoint": "/api/health", "error": "Health payload not matching required schema", "status": res_health.status_code})
except Exception as e:
    report["failures"].append({"phase": "Health", "endpoint": "/api/health", "error": str(e)})


# Phase 5: Security Validation
print("\n--- Phase 5: Security Validation ---")
try:
    # SQLi Payload
    res_sqli = session.get(f"{BASE_URL}/api/reports/1' OR '1'='1")
    log_result("Security", "SQLi Payload Test", res_sqli.status_code, 0, expected_status=404) # Or 422, but not 500
    if res_sqli.status_code >= 500:
        report["security_issues"].append("Possible SQLi or unhandled 500 on SQL payload in /api/reports/{date}")

    # XSS Payload
    res_xss = session.post(f"{BASE_URL}/api/threats/<script>alert(1)<%2Fscript>/block")
    log_result("Security", "XSS Payload Test", res_xss.status_code, 0, expected_status=404)
    if res_xss.status_code >= 500:
        report["security_issues"].append("Unhandled exception on XSS payload in /api/threats/{id}/block")

    # Unauthorized Access
    unauth_session = requests.Session()
    res_unauth = unauth_session.get(f"{BASE_URL}/api/dashboard/summary")
    log_result("Security", "Unauthorized Access Test", res_unauth.status_code, 0, expected_status=401)
    if res_unauth.status_code == 200:
         report["security_issues"].append("Metrics endpoint accessible without authentication token")
except Exception as e:
    report["failures"].append({"phase": "Security", "endpoint": "Multiple", "error": str(e)})


# Phase 4 & 6 Check Logs & Performance
# Handled within log_result during iterations above.
if len(report["failures"]) > 0 or len(report["security_issues"]) > 0:
    report["overall_status"] = "FAIL"

with open("qa_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("Tests completed. Checking results:")
print(f"Status: {report['overall_status']}")
if report['failures']:
    print(f"Failures ({len(report['failures'])}):")
    for f in report['failures']:
        print(f"  - {f['endpoint']}: {f.get('status', 'ERROR')} {f.get('error','')}")
if report['security_issues']:
    print(f"Security Issues ({len(report['security_issues'])}):")
    for s in report['security_issues']:
        print(f"  - {s}")
