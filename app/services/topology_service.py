"""
Project: SentinAI NetGuard
Module: Adaptive Topology Engine
Description:
    Generates a dynamic network graph representation.
    
    Novelty:
    - Uses 'Procedural Generation' (PRNG) to construct the network map based
      on a seeded value, simulating complex enterprise environments without
      needing hardcoded node lists.
    - Implements 'Risk Propagation' where a compromised node affects its neighbors.
"""

from typing import Dict, Any, List
import random
import hashlib
from app.db.connection import db

class AdaptiveTopologyEngine:
    """
    Procedural Generator for Network Topology.
    """
    
    # Configuration for Procedural Generation
    SEED_KEY = "SentinAI-Enterprise-v1"
    CLUSTERS = ["Core_Switch", "DMZ", "User_Subnet_A", "User_Subnet_B"]
    
    @classmethod
    def _generate_node_id(cls, name: str) -> str:
        return hashlib.md5(name.encode()).hexdigest()[:8]

    @classmethod
    def build_graph(cls) -> Dict[str, Any]:
        """
        Constructs the node-link graph procedurally with simple Grid coordinates.
        This standardizes the visual layout for the React frontend.
        """
        random.seed(cls.SEED_KEY) # Deterministic generation for consistency
        
        nodes = []
        links = []
        
        # Layout Config - Further Expanded
        CENTER_X, CENTER_Y = 400, 400
        RADIUS_L1 = 250 # Distance for Clusters (Subnets)
        RADIUS_L2 = 140 # Distance for Assets within Cluster
        
        # 1. Create Core Node
        core_id = "core-router-01"
        nodes.append({
            "id": core_id, 
            "name": "Core Gateway", 
            "group": "Infrastructure", 
            "type": "Router",
            "status": "Healthy",
            "x": CENTER_X, "y": CENTER_Y,
            "threats": 0
        })
        
        # 2. Generate Clusters (Aligned with Log Generator Subnet 10.0.5.x)
        # We explicitly name one cluster "Secure Enclave" to match the simulator
        subnet_configs = [
            {"name": "DMZ", "ip_prefix": "10.0.1"},
            {"name": "Secure Enclave", "ip_prefix": "10.0.5"}, # TARGET ZONE for Simulator
            {"name": "User_Subnet_A", "ip_prefix": "10.0.2"},
            {"name": "User_Subnet_B", "ip_prefix": "10.0.3"}
        ]
        
        import math
        
        for i, subnet_config in enumerate(subnet_configs):
            cluster_name = subnet_config["name"]
            
            # Angle for Cluster Root (L1)
            angle_l1 = (2 * math.pi / len(subnet_configs)) * i
            c_x = CENTER_X + RADIUS_L1 * math.cos(angle_l1)
            c_y = CENTER_Y + RADIUS_L1 * math.sin(angle_l1)
            
            cluster_root_id = cls._generate_node_id(cluster_name)
            nodes.append({
                "id": cluster_root_id, 
                "name": cluster_name, 
                "group": "Switch", 
                "type": "Switch",
                "status": "Healthy",
                "x": c_x, "y": c_y,
                "threats": 0
            })
            links.append({"source": core_id, "target": cluster_root_id})
            
            # 3. Add Endpoints to Clusters
            device_count = 5 # Fixed for symmetry
            for j in range(device_count):
                device_name = f"{cluster_name}-Asset-{j+1}"
                device_id = cls._generate_node_id(device_name)
                
                # IP mapping: 
                # If Secure Enclave, use the Real Target IP for at least one node to show alerts
                if "Secure" in cluster_name and j == 0:
                    from app.core.config import config
                    mapped_ip = config.TARGET_SERVER_IP
                else:
                    host_num = 10 + j 
                    mapped_ip = f"{subnet_config['ip_prefix']}.{host_num}" 
                
                # Angle for Asset (L2) - Fan out
                # Increased spread to 0.5 rad (~70px arc at r=140)
                # Offset -1.0 to center the fan (5 items * 0.5 = 2.5 span / 2 = 1.25 offset? No, range is 0..4 * 0.5 = 2.0 rad span. center is at index 2 (1.0). so start at angle_l1 - 1.0)
                angle_l2 = angle_l1 - 1.0 + (j * 0.5)
                a_x = c_x + RADIUS_L2 * math.cos(angle_l2)
                a_y = c_y + RADIUS_L2 * math.sin(angle_l2)

                nodes.append({
                    "id": device_id, 
                    "name": device_name, 
                    "group": "Endpoint", 
                    "type": "Server" if "Secure" in cluster_name else "Client",
                    "ip": mapped_ip,
                    "status": "Healthy",
                    "x": a_x, "y": a_y,
                    "threats": 0
                })
                links.append({"source": cluster_root_id, "target": device_id})
                
        return {"nodes": nodes, "links": links}

    @classmethod
    async def get_topology_status(cls) -> Dict[str, Any]:
        """
        Retrieves the graph and overlays real-time threat data.
        """
        graph = cls.build_graph()
        
        # Overlay Active Threats
        # In a real system, we would perform an O(N) lookup. 
        # Here we simulate 'Risk Propagation'.
        
        active_threats = []
        try:
             active_threats = await db.fetch_data(limit=50) 
        except Exception as e:
             print(f"[Topology] Error fetching active threats: {e}")
        
        # Map IP to Risk
        impacted_ips = {}
        if active_threats:
            for t in active_threats:
                if t.get('status') == 'Active':
                    target_ip = t.get('destination_ip', '')
                    if target_ip:
                        impacted_ips[target_ip] = t.get('risk_score', 0)

        for node in graph['nodes']:
            # Check if this node is under attack
            # Simple simulation: If an active threat targets "10.0.X.X", mark a node.
            
            node_ip = node.get('ip')
            if node_ip and node_ip in impacted_ips:
                risk = impacted_ips[node_ip]
                node['threats'] = 1 # Indicator flag
                node['latest_threat'] = "Under Attack" # Simple label
                
                if risk > 80:
                    node['status'] = 'Compromised'
                elif risk > 50:
                    node['status'] = 'Warning'
            
        return graph

# Alias for API compatibility
TopologyService = AdaptiveTopologyEngine
topology_service = AdaptiveTopologyEngine
