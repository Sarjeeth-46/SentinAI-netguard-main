import sys
import socket
import requests
import argparse
import platform
import subprocess

def ping_host(host):
    """Pings a host."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def check_port(host, port, timeout=2):
    """Checks if a TCP port is open."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception as e:
        logger.error(f"Cannot decode feature map: {e}", exc_info=True)

def check_http(url):
    """Checks if an HTTP endpoint is reachable."""
    try:
        response = requests.get(url, timeout=3)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Cannot decode feature map: {e}", exc_info=True)

def run_diagnostics(role, target_ip):
    print(f"=== NetGuard Connectivity Verifier ({role}) ===")
    print(f"Target Server IP: {target_ip}")
    print("-" * 40)

    # 1. Ping Test
    print(f"[ICMP] Pinging {target_ip}...", end=" ")
    if ping_host(target_ip):
        print("✅ REACHABLE")
    else:
        print("❌ UNREACHABLE (Check VPN/Bridge Network)")

    # 2. Service Checks
    if role in ["desktop", "kali"]:
        # Check Backend Port
        print(f"[TCP] Connecting to Backend ({target_ip}:8000)...", end=" ")
        if check_port(target_ip, 8000):
            print("✅ OPEN")
        else:
            print("❌ CLOSED (Check Firewall/UFW)")

        # Check API Health
        api_url = f"http://{target_ip}:8000/api/health"
        print(f"[HTTP] Checking API Health ({api_url})...", end=" ")
        if check_http(api_url):
            print("✅ ONLINE")
        else:
            print("❌ OFFLINE")

    if role == "server":
        # Check Database (Self or External)
        mongo_port = 27017
        print(f"[TCP] Checking Local MongoDB (localhost:{mongo_port})...", end=" ")
        if check_port("localhost", mongo_port):
            print("✅ RUNNING")
        else:
            print("⚠️ NOT DETECTED (Ignore if using Cloud Atlas)")

    print("-" * 40)
    print("Diagnostics Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify NetGuard 3-VM Connectivity")
    parser.add_argument("--role", choices=["server", "desktop", "kali"], required=True, help="Current VM Role")
    parser.add_argument("--target", required=True, help="IP Address of the Server Node (or self if Server)")
    
    args = parser.parse_args()
    run_diagnostics(args.role, args.target)
