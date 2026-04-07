from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class ThreatEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    packet_size: int
    dest_port: int
    source_country: str = "Unknown"
    label: str
    predicted_label: Optional[str] = None
    risk_score: int
    confidence: float
    attack_probability: float
    metadata: Dict[str, Any] = {}

class IPReputationResult(BaseModel):
    ip: str
    score: int
    should_alert: bool
    is_silenced: bool
