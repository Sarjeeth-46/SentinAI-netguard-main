"""
Project: AegisCore
Module: Incident Management Service
Description:
    Orchestrates the lifecycle of Security Incidents (Alerts).
    Provides capability to Retrieve, Triage (Resolve), and Mitigate (Block)
    detected anomalies.
"""

from typing import List, Optional, Dict
from app.db.connection import db as persistence_gateway

class IncidentLifecycleManager:
    """
    Business Logic Layer for Security Operations.
    """

    class Status:
        ACTIVE = 'Active'
        RESOLVED = 'Resolved'
        ALL = 'All'

    @classmethod
    async def retrieve_incident_feed(cls, limit: int = 500, lifecycle_state: Optional[str] = None, start_time: str = None, end_time: str = None) -> List[Dict]:
        """
        Fetches the operational event feed with optional state filtering and time range.
        """
        # Fetch raw telemetry from persistence layer
        if start_time and end_time:
            raw_telemetry = await persistence_gateway.query_security_events_by_timerange(start_time, end_time)
        else:
            raw_telemetry = await persistence_gateway.fetch_data(limit=limit)
        
        # Helper: Normalize filter input
        target_state = lifecycle_state.lower() if lifecycle_state else 'all'
        
        if target_state == 'all':
            return raw_telemetry
            
        # Determine strict filter criterion
        is_searching_resolved = (target_state == 'resolved')
        
        from app.services.dashboard_aggregator import DashboardAggregator
        filtered_events = []
        for event in raw_telemetry:
            # Normalize event status (Default to Active if field missing)
            event_status = event.get('status', cls.Status.ACTIVE)
            
            ts = event.get('timestamp')
            if ts:
                event['timestamp'] = DashboardAggregator._parse_ts(ts).isoformat()
            
            if is_searching_resolved:
                if event_status == cls.Status.RESOLVED:
                    filtered_events.append(event)
            else:
                # 'Active' implies anything NOT Resolved
                if event_status != cls.Status.RESOLVED:
                    filtered_events.append(event)
                    
        return filtered_events

    @classmethod
    async def triage_incident(cls, incident_id: str) -> Optional[Dict]:
        """
        Transitions an incident state from Active -> Resolved.
        """
        # Retrieve full dataset to locate the record
        # In a production SQL/NoSQL env, this would be `UPDATE ... WHERE id = ...`
        dataset = await persistence_gateway.fetch_data(limit=None)
        
        target_record = None
        mutation_occurred = False
        
        for record in dataset:
            if record.get('id') == incident_id:
                # Apply State Transition
                record['status'] = cls.Status.RESOLVED
                target_record = record
                mutation_occurred = True
                break
        
        if mutation_occurred:
            # BUG FIX: was `await persistence_gateway.save_fallback(dataset)` which only
            # writes to the local JSON file, bypassing MongoDB. After a server restart (or
            # in cloud mode) the event would reappear as Active.
            # save_event() correctly upserts to MongoDB with local-JSON fallback.
            await persistence_gateway.save_event(target_record)
            return target_record
            
        return None

    @classmethod
    async def invoke_mitigation_protocol(cls, incident_id: str) -> bool:
        """
        Executing active countermeasures (e.g. Firewall Rules).
        Currently simulated.
        """
        # TODO: Integrate with Palo Alto / Cisco ASA APIs
        # For prototype scope, acknowledge the command was received.
        return True

# Singleton Export with Legacy Compatibility Name
threat_service = IncidentLifecycleManager()

threat_service.get_recent_threats = IncidentLifecycleManager.retrieve_incident_feed
threat_service.resolve_threat = IncidentLifecycleManager.triage_incident
threat_service.block_threat_source = IncidentLifecycleManager.invoke_mitigation_protocol

async def process_batch(batch: List[Dict]):
    from app.services.ml_service import ml_service
    import pandas as pd
    
    # Feature column names matching the model's training schema
    FEATURE_COLUMNS = ['dest_port', 'packet_size', 'total_l_fwd_packets', 'total_fwd_packets', 'flow_duration']
    
    for event_data in batch:
        origin = event_data.get("metadata", {}).get("origin")
        label = event_data.get("label")
        
        # Fast path: skip ML entirely for trusted shipper events to avoid warnings and save CPU
        if origin == "aws-ec2-shipper" and label:
            event_data["predicted_label"] = label
            event_data["confidence"] = 0.99 if label != "Normal" else 1.0
            event_data["risk_score"] = 85 if label != "Normal" else 10
            continue
        
        # Real ML path: pass a named DataFrame to suppress sklearn feature-name warnings
        feature_row = {
            'dest_port':             float(event_data.get('dest_port', 80)),
            'packet_size':           float(event_data.get('packet_size', 50)),
            'total_l_fwd_packets':   float(event_data.get('total_l_fwd_packets', 1)),
            'total_fwd_packets':     float(event_data.get('total_fwd_packets', 1)),
            'flow_duration':         float(event_data.get('flow_duration', 100)),
        }
        features_df = pd.DataFrame([feature_row], columns=FEATURE_COLUMNS)
        prediction, confidence = ml_service.predict(features_df)
        
        event_data["predicted_label"] = prediction
        event_data["confidence"] = confidence
        event_data["risk_score"] = 85 if prediction != "Normal" else 10

threat_service.process_batch = process_batch
