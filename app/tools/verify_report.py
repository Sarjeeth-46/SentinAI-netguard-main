import requests
import json
import time

try:
    # 1. Trigger Generation
    url = "http://localhost:8000/api/reports/generate"
    print(f"Requesting report from {url}...")
    res = requests.post(url, json={})
    
    if res.status_code != 200:
        print(f"Failed: {res.status_code} - {res.text}")
        exit(1)
        
    report = res.json()
    print("Report Generated Successfully!")
    
    # 2. Verify Fields
    summary = report.get('summary', {})
    print("\n--- Summary Verification ---")
    print(f"Total Incidents: {summary.get('total_incidents')}")
    print(f"Resolved Count:  {summary.get('resolved_incidents')} (Expected field)")
    print(f"Affected Targets: {list(summary.get('top_targets', {}).keys())} (Expected field)")
    
    detailed = report.get('detailed_log', [])
    print(f"\n--- Detailed Log Verification ---")
    print(f"Log Entries: {len(detailed)}")
    if detailed:
        print(f"Sample Entry Keys: {list(detailed[0].keys())}")
        
    # 3. Validation
    if 'resolved_incidents' in summary and 'top_targets' in summary and 'detailed_log' in report:
        print("\n[PASS] Report structure matches requirements.")
    else:
        print("\n[FAIL] Missing required fields.")

except Exception as e:
    print(f"Error: {e}")
