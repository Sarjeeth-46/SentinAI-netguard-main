from pydantic import BaseModel, Field
from typing import Optional, List

class ReportRequestDTO(BaseModel):
    date: Optional[str] = None # YYYY-MM-DD

class CredentialsDTO(BaseModel):
    username: str
    password: str

class PasswordChangeDTO(BaseModel):
    username: str
    old_password: str
    new_password: str

class NameValueDTO(BaseModel):
    name: str
    value: int

class GeoStatDTO(BaseModel):
    id: str
    value: int

class ModelMetricsDTO(BaseModel):
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

class ModelFeatureDTO(BaseModel):
    feature: str
    importance: float

class RiskLevelsDTO(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class DashboardOverviewDTO(BaseModel):
    total_threats: int
    risk_levels: RiskLevelsDTO
    attack_type_distribution: dict
    traffic_severity_trend: List[dict]
    window_minutes: int
    computed_at: str

class DashboardSummaryDTO(BaseModel):
    threats: List[dict]
    risk_summary: List[NameValueDTO]
    attack_types: List[NameValueDTO]
    geo_stats: List[GeoStatDTO]
    critical_alerts: List[dict]
    features: List[ModelFeatureDTO]
    metrics: ModelMetricsDTO

class TopologyNodeDTO(BaseModel):
    id: str
    name: str
    group: str
    type: str
    status: str
    x: float
    y: float
    threats: int
    ip: Optional[str] = None
    latest_threat: Optional[str] = None

class TopologyLinkDTO(BaseModel):
    source: str
    target: str
    value: Optional[int] = None

class TopologyStatusDTO(BaseModel):
    nodes: List[TopologyNodeDTO]
    links: List[TopologyLinkDTO]

class HealthStatusDTO(BaseModel):
    database: str
    reports_storage: str
    threat_engine: str
    uptime_seconds: int

class LivenessStatusDTO(BaseModel):
    status: str
    uptime_seconds: int

class ReadinessStatusDTO(BaseModel):
    database: str
    reports_storage: str
    threat_engine: str
    status: str

class DBStatusDTO(BaseModel):
    status: str

class LogEntryPayloadDTO(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: str
    destination_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = "SYSLOG"
    packet_size: Optional[int] = 0
    dest_port: Optional[int] = 0
    label: str
    predicted_label: Optional[str] = None
    risk_score: Optional[float] = 0.0
    confidence: Optional[float] = 1.0
    attack_probability: Optional[float] = 1.0
    metadata: Optional[dict] = {}
    
class NotifyEventDTO(BaseModel):
    type: str
    data: LogEntryPayloadDTO
