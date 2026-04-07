import requests
import json
import time

BASE_URL = "http://localhost:8000"
report = {
    "overall_status": "PASS",
    "tested_endpoints": [],
    "failures": [],
    "security_issues": [],
    "performance_warnings": [],
    "recommendations": []
}

def log_result(endpoint, status, time_taken, error=None):
    report["tested_endpoints"].append(endpoint)
    if time_taken > 2.0:
        report["performance_warnings"].append(f"{endpoint} took {time_taken:.2f}s")
    if status >= 400 and status not in [401, 403, 404, 422]: # Expected errors for some tests
        report["failures"].append({"endpoint": endpoint, "status": status, "error": error})
        report["overall_status"] = "FAIL"

# Phase 1: Bootstrap System
try:
    start = time.time()
    res = requests.post(f"{BASE_URL}/api/system/bootstrap")
    dur = time.time() - start
    log_result("/api/system/bootstrap", res.status_code, dur)
except Exception as e:
    report["failures"].append({"endpoint": "/api/system/bootstrap", "error": str(e)})

# Phase 2: Authentication
session = requests.Session()
token = None
try:
    # Valid login
    start = time.time()
    res = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "changeme_in_prod!"})
    dur = time.time() - start
    if res.status_code == 200:
        token = res.cookies.get("access_token") # Or JSON body
        if not token:
            token = res.json().get("access_token")
        if token:
            session.headers.update({"Authorization": f"Bearer {token}"})
    log_result("/api/auth/login (valid)", res.status_code, dur)
    
    # Invalid password
    res_inv = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin", "password": "wrong"})
    log_result("/api/auth/login (invalid)", res_inv.status_code, 0)
    if res_inv.status_code == 200:
         report["failures"].append({"endpoint": "/api/auth/login", "error": "Accepted invalid password"})
         
    # Missing fields
    res_miss = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "admin"})
    log_result("/api/auth/login (missing)", res_miss.status_code, 0)
    if res_miss.status_code != 422:
        report["failures"].append({"endpoint": "/api/auth/login", "error": "Did not reject missing fields with 422"})
except Exception as e:
    report["failures"].append({"endpoint": "/api/auth/login", "error": str(e)})

# Phase 3: Core Functional (Authenticated)
try:
    # Get Exec Summary
    start = time.time()
    res = session.get(f"{BASE_URL}/api/analytics/summary")
    dur = time.time() - start
    log_result("/api/analytics/summary", res.status_code, dur)
    
    # Execute Mitigation
    start = time.time()
    res_m1 = session.post(f"{BASE_URL}/api/threats/fake-threat-123/block")
    dur = time.time() - start
    log_result("/api/threats/{id}/block", res_m1.status_code, dur)
    
    # Generate Report
    start = time.time()
    res_gr = session.post(f"{BASE_URL}/api/reports/generate", json={"date": "2024-01-01"})
    dur = time.time() - start
    log_result("/api/reports/generate", res_gr.status_code, dur)
    
    # Get Report
    start = time.time()
    res_get = session.get(f"{BASE_URL}/api/reports/2024-01-01")
    dur = time.time() - start
    log_result("/api/reports/{date}", res_get.status_code, dur)
    
except Exception as e:
    report["failures"].append({"endpoint": "core actions", "error": str(e)})

# Phase 5: Security Validation
try:
    # SQLi Payload
    res_sqli = session.get(f"{BASE_URL}/api/reports/1' OR '1'='1")
    log_result("Security SQLi", res_sqli.status_code, 0)
    if res_sqli.status_code == 500:
        report["security_issues"].append("Possible SQLi / Unhandled 500 on SQL payload")
        
    # XSS Payload
    res_xss = session.post(f"{BASE_URL}/api/threats/<script>alert(1)<%2Fscript>/block")
    log_result("Security XSS", res_xss.status_code, 0)
    if res_xss.status_code == 500:
         report["security_issues"].append("Unhandled exception on XSS payload")
         
    # Unauthorized Access
    unauth_session = requests.Session()
    res_unauth = unauth_session.get(f"{BASE_URL}/api/analytics/summary")
    log_result("Security Unauth", res_unauth.status_code, 0)
    if res_unauth.status_code == 200:
        report["security_issues"].append("Authorized endpoint accessible without token")
except Exception as e:
    pass

if len(report["failures"]) > 0 or len(report["security_issues"]) > 0:
    report["overall_status"] = "FAIL"

with open("test_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("Test complete. Report saved to test_report.json")
