from enum import Enum
from typing import List, Optional, Dict, Union, Any
from pydantic import BaseModel, Field
from datetime import datetime

# Enum definitions
class EntityType(str, Enum):
    IP = "IP"
    USER = "USER"
    HOST = "HOST"
    
class LogType(str, Enum):
    NETWORK = "NETWORK"
    AUTH = "AUTH"
    ENDPOINT = "ENDPOINT"

class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"

# Base models
class BaseDBModel(BaseModel):
    """Base database model"""
    id: Optional[str] = Field(None, alias="_id")

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        
# User models
class UserInDB(BaseDBModel):
    """User database model"""
    name: str
    email: str
    password_hash: str
    role: UserRole
    createdAt: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    """User creation model"""
    name: str
    email: str
    password: str
    role: UserRole

class UserResponse(BaseModel):
    """User response model"""
    id: str
    name: str
    email: str
    role: UserRole
    createdAt: datetime

# Log models
class NetworkLog(BaseDBModel):
    """Network log model"""
    timestamp: datetime
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    action: str
    bytes_sent: int
    bytes_received: int
    label: Optional[str] = None

class AuthLog(BaseDBModel):
    """Authentication log model"""
    timestamp: datetime
    username: str
    src_ip: str
    dest_host: str
    status: str
    auth_method: str

class EndpointLog(BaseDBModel):
    """Endpoint log model"""
    timestamp: datetime
    host: str
    event_type: str
    user: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# Asset models
class Asset(BaseDBModel):
    """Asset model"""
    host: str
    ip_address: str
    owner: str
    criticality: int

# Threat intel models
class ThreatIntel(BaseDBModel):
    """Threat intelligence model"""
    indicator: str
    type: str
    threat_level: int
    source: str
    first_seen: datetime
    last_seen: datetime

# Alert models
class Alert(BaseDBModel):
    """Alert model"""
    timestamp: datetime
    title: str
    description: str
    source_log_id: Optional[str] = None
    log_type: Optional[LogType] = None
    severity: AlertSeverity
    status: str = "NEW"
    entities: List[Dict[str, str]] = []
    tactic: Optional[str] = None
    technique: Optional[str] = None
    metadata: Dict[str, Any] = {}

# Risk models
class EntityRiskScore(BaseDBModel):
    """Entity risk score model"""
    entity_id: str
    entity_type: EntityType
    risk_score: float
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    risk_factors: List[Dict[str, Union[str, float]]] = []
    metadata: Dict[str, Any] = {}

# Graph models
class GraphSummary(BaseDBModel):
    """Graph summary model"""
    timestamp: datetime
    node_count: int
    edge_count: int
    top_central_entities: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}
