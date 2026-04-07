"""
Project: SentinAI NetGuard
Module: Traffic Generator
Description: Implements a stochastic network traffic simulation using a Non-Homogeneous Poisson Process (NHPP).
             This module generates synthetic network telemetry to emulate realistic enterprise traffic patterns,
             including benign background noise and sporadic attack vectors.
License: MIT / Academic Use Only
"""
import random
import time
import numpy as np
from datetime import datetime
from typing import Dict, Any

class NetworkTrafficGenerator:
    """
    Simulates network traffic generation using stochastic modeling.
    
    Methodology:
    The inter-arrival time of packets is modeled using an exponential distribution (Poisson Process),
    simulating the random nature of user requests. Attack vectors are injected based on a 
    probabilistic model triggered by specific thresholds.
    """
    
    # Static mapping of simulated internal assets
    ASSET_MAP = {
        "10.0.0.5": "Database_Server_Primary",
        "10.0.0.10": "Application_Server_Cluster",
        "10.0.0.15": "Workstation_Subnet_A",
        "10.0.0.1": "Core_Router_Gateway"
    }
    
    # External IP pool with associated geo-locations (Simulated)
    EXTERNAL_SOURCES = [
        "45.33.22.11", "103.45.12.99", "185.22.11.44",
        "192.168.1.100", "203.0.113.55", "198.51.100.23",
        "14.23.11.105", "88.12.4.99"
    ]
    
    def __init__(self, lambda_rate: float = 0.5):
        """
        Initializes the generator.
        
        Args:
           lambda_rate (float): The rate parameter (lambda) for the Poisson distribution, 
                                representing average arrival rate.
        """
        self.lambda_rate = lambda_rate

    def _get_next_inter_arrival_time(self) -> float:
        """
        Calculates the time until the next packet using Exponential Distribution.
        Formula: f(x; lambda) = lambda * e^(-lambda * x)
        """
        return np.random.exponential(1/self.lambda_rate)

    @staticmethod
    def generate_telemetry_payload() -> Dict[str, Any]:
        """
        Constructs a single unit of network telemetry (packet log).
        """
        source_ip = random.choice(NetworkTrafficGenerator.EXTERNAL_SOURCES)
        dest_ip = random.choice(list(NetworkTrafficGenerator.ASSET_MAP.keys()))
        
        # Protocol selection based on common internet traffic distribution
        protocol = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.8, 0.15, 0.05])
        
        return {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "dest_port": int(np.random.choice([80, 443, 22, 3306, 8080, 53], p=[0.4, 0.4, 0.05, 0.05, 0.05, 0.05])),
            "timestamp": datetime.now().isoformat(),
            "packet_size": int(np.random.normal(loc=500, scale=200)), # Normal distribution for packet size
            "protocol": protocol,
            "flag_syn": random.choice([0, 1]) if protocol == "TCP" else 0
        }

if __name__ == "__main__":
    print("[Simulation] Initializing Stochastic Traffic Generator...")
    sim = NetworkTrafficGenerator(lambda_rate=2.0)
    
    # Basic interactive loop if run directly
    while True:
        packet = sim.generate_telemetry_payload()
        delay = sim._get_next_inter_arrival_time()
        
        print(f"[Generator] Event Produced -> IP: {packet['source_ip']} (Next in {delay:.2f}s)")
        # In a real system, this would post to an input queue or detector
        time.sleep(delay)
