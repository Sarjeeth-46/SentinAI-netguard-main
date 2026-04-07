import asyncio
import aiohttp
import time
import random
import numpy as np
import argparse
from datetime import datetime, timezone

# --- Domain Constants ---
class ThreatSignature:
    BENIGN = 'Normal'
    VOLUMETRIC_DDOS = 'DDoS'
    AUTH_BRUTE_FORCE = 'Brute Force'
    RECON_SCAN = 'Port Scan'
    DATA_EXFILTRATION = 'Exfiltration'

EXTERNAL_THREAT_POOL = [f'45.33.{i}.{j}' for i in range(10, 20) for j in range(1, 50)]
INTERNAL_ASSET_POOL = [f'10.0.5.{i}' for i in range(10, 100)]
COUNTRY_CODES = ["USA", "CHN", "RUS", "BRA", "IND", "DEU", "GBR", "FRA", "JPN", "KOR"]

TRAFFIC_FINGERPRINTS = {
    ThreatSignature.BENIGN: [80, 443, 53, 22, 21, 8080],
    ThreatSignature.VOLUMETRIC_DDOS: [80, 443, 8443],
    ThreatSignature.AUTH_BRUTE_FORCE: [22, 3389, 5432],
    ThreatSignature.RECON_SCAN: [],
    ThreatSignature.DATA_EXFILTRATION: [443, 8080]
}

class AegisTelemetryFabric:
    def __init__(self):
        self._entropy_source = random.SystemRandom()

    def _calculate_chaos_factor(self):
        t = time.time()
        temporal_fluctuation = (np.sin(t / 1000) + 1) / 2
        return 0.05 + (temporal_fluctuation * 0.25)

    def _select_port(self, category):
        if category == ThreatSignature.RECON_SCAN:
            return self._entropy_source.randint(1, 65535)
        target_ports = TRAFFIC_FINGERPRINTS.get(category)
        if target_ports:
            return self._entropy_source.choice(target_ports)
        return 80

    def _derive_packet_size(self, category):
        if category == ThreatSignature.VOLUMETRIC_DDOS:
            return self._entropy_source.randint(3000, 3100)
        elif category == ThreatSignature.DATA_EXFILTRATION:
            return int(np.random.normal(4096, 512))
        elif category == ThreatSignature.AUTH_BRUTE_FORCE:
            return self._entropy_source.randint(2000, 2100)
        elif category == ThreatSignature.RECON_SCAN:
             return 0
        raw_size = int(max(40, np.random.lognormal(mean=6, sigma=1)))
        return min(1500, raw_size)

    def synthesize_artifact(self):
        timestamp_iso = datetime.now(timezone.utc).isoformat()
        origin = self._entropy_source.choice(EXTERNAL_THREAT_POOL)
        target = self._entropy_source.choice(INTERNAL_ASSET_POOL)
        proto = self._entropy_source.choice(["TCP", "UDP", "ICMP", "SCTP"])
        country = self._entropy_source.choice(COUNTRY_CODES)

        current_cf = self._calculate_chaos_factor()
        roll = self._entropy_source.random()
        
        if roll > current_cf:
            category = ThreatSignature.BENIGN
        else:
            attack_roll = self._entropy_source.random()
            if attack_roll < 0.4: category = ThreatSignature.VOLUMETRIC_DDOS
            elif attack_roll < 0.7: category = ThreatSignature.AUTH_BRUTE_FORCE
            elif attack_roll < 0.9: category = ThreatSignature.RECON_SCAN
            else: category = ThreatSignature.DATA_EXFILTRATION

        dest_port = self._select_port(category)
        pkt_size = self._derive_packet_size(category)

        # ML Features specific to backend SentinAI requirements
        flow_duration = 0
        total_fwd_packets = 1
        total_l_fwd_packets = pkt_size if category != ThreatSignature.RECON_SCAN else 0

        return {
            'timestamp': timestamp_iso,
            'source_ip': origin,
            'destination_ip': target,
            'protocol': proto,
            'packet_size': pkt_size,
            'dest_port': dest_port,
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_l_fwd_packets': total_l_fwd_packets,
            'label': category,
            'metadata': {
                'chaos_factor': current_cf,
                'source_country': country,
                'entropy_flag': True 
            }
        }

async def generate_and_send_logs(target_url, api_key, batch_size=20, delay=1.0, output_file=None, input_file=None):
    headers = {'X-API-Key': api_key, 'Content-Type': 'application/json'}
    
    if input_file:
        import json
        import os
        print(f"Replaying logs from {input_file} to {target_url}")
        if not os.path.exists(input_file):
            print(f"Error: {input_file} does not exist.")
            return

        async with aiohttp.ClientSession() as session:
            with open(input_file, 'r') as f:
                logs = [json.loads(line.strip()) for line in f if line.strip()]
            
            print(f"Loaded {len(logs)} logs. Starting broadcast...")
            for i in range(0, len(logs), batch_size):
                payload = logs[i:i + batch_size]
                try:
                    async with session.post(target_url, json=payload, headers=headers) as response:
                        if response.status in (200, 201):
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Pushed {len(payload)} logs from file. Status: {response.status}")
                        else:
                            text = await response.text()
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {response.status} - {text}")
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Exception occurred: {e}")
                
                await asyncio.sleep(delay)
        print("Replay complete.")
        return

    fabric = AegisTelemetryFabric()
    
    if output_file:
        print(f"Generating synthetic logs and saving to {output_file}...")
        print(f"Batch Size: {batch_size} logs/interval, Delay: {delay}s")
        import json
        import os
        
        mode = 'a' if os.path.exists(output_file) else 'w'
        
        while True:
            try:
                payload = [fabric.synthesize_artifact() for _ in range(batch_size)]
                
                with open(output_file, mode) as f:
                    for log in payload:
                        f.write(json.dumps(log) + '\n')
                mode = 'a'
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Saved next {batch_size} logs to {output_file}")
                await asyncio.sleep(delay)
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Exception occurred: {e}")
                
    else:
        print(f"Starting auto-generation telemetry streaming to {target_url}")
        print(f"Batch Size: {batch_size} logs/interval, Delay: {delay}s")
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    payload = [fabric.synthesize_artifact() for _ in range(batch_size)]
                    
                    async with session.post(target_url, json=payload, headers=headers) as response:
                        if response.status in (200, 201):
                            data = await response.json()
                            enqueued = data.get('count', '?')
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Successfully sent {enqueued} logs. Status: {response.status}")
                        else:
                            text = await response.text()
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {response.status} - {text}")
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Exception occurred: {e}")
                
                await asyncio.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="SentinAI EC2 Log Generator")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/telemetry", help="Target API Telemetry URL")
    parser.add_argument("--key", default="secure-telemetry-key-123", help="API Key for Authorization")
    parser.add_argument("--batch", type=int, default=20, help="Number of logs per batch")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between batches in seconds")
    parser.add_argument("--output", type=str, default=None, help="Save to local file instead of sending over HTTP")
    parser.add_argument("--input", type=str, default=None, help="Replay a local JSON file over HTTP instead of generating new logs")
    
    args = parser.parse_args()
    
    try:
        asyncio.run(generate_and_send_logs(args.url, args.key, args.batch, args.delay, args.output, args.input))
    except KeyboardInterrupt:
        print("\nTelemetry generation stopped.")

if __name__ == "__main__":
    main()
