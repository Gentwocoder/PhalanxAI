"""
Pydantic schemas for API request/response models.
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime


class NetworkFlowInput(BaseModel):
    """Input schema for network flow analysis."""
    
    # Basic flow info
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source port")
    dst_port: Optional[int] = Field(None, alias="Destination Port", description="Destination port")
    protocol: Optional[str] = Field(None, description="Protocol (TCP, UDP, etc.)")
    
    # Flow features - using aliases to match dataset column names
    flow_duration: Optional[float] = Field(0, alias="Flow Duration")
    total_fwd_packets: Optional[int] = Field(0, alias="Total Fwd Packets")
    total_bwd_packets: Optional[int] = Field(0, alias="Total Backward Packets")
    total_length_fwd_packets: Optional[float] = Field(0, alias="Total Length of Fwd Packets")
    total_length_bwd_packets: Optional[float] = Field(0, alias="Total Length of Bwd Packets")
    
    # Packet length stats
    fwd_packet_length_max: Optional[float] = Field(0, alias="Fwd Packet Length Max")
    fwd_packet_length_min: Optional[float] = Field(0, alias="Fwd Packet Length Min")
    fwd_packet_length_mean: Optional[float] = Field(0, alias="Fwd Packet Length Mean")
    fwd_packet_length_std: Optional[float] = Field(0, alias="Fwd Packet Length Std")
    bwd_packet_length_max: Optional[float] = Field(0, alias="Bwd Packet Length Max")
    bwd_packet_length_min: Optional[float] = Field(0, alias="Bwd Packet Length Min")
    bwd_packet_length_mean: Optional[float] = Field(0, alias="Bwd Packet Length Mean")
    bwd_packet_length_std: Optional[float] = Field(0, alias="Bwd Packet Length Std")
    
    # Flow rates
    flow_bytes_per_s: Optional[float] = Field(0, alias="Flow Bytes/s")
    flow_packets_per_s: Optional[float] = Field(0, alias="Flow Packets/s")
    
    # IAT features
    flow_iat_mean: Optional[float] = Field(0, alias="Flow IAT Mean")
    flow_iat_std: Optional[float] = Field(0, alias="Flow IAT Std")
    flow_iat_max: Optional[float] = Field(0, alias="Flow IAT Max")
    flow_iat_min: Optional[float] = Field(0, alias="Flow IAT Min")
    
    # Flags
    syn_flag_count: Optional[int] = Field(0, alias="SYN Flag Count")
    fin_flag_count: Optional[int] = Field(0, alias="FIN Flag Count")
    rst_flag_count: Optional[int] = Field(0, alias="RST Flag Count")
    psh_flag_count: Optional[int] = Field(0, alias="PSH Flag Count")
    ack_flag_count: Optional[int] = Field(0, alias="ACK Flag Count")
    
    # Additional features dict for flexibility
    additional_features: Optional[Dict[str, float]] = Field(
        default_factory=dict, 
        description="Additional network flow features"
    )
    
    class Config:
        populate_by_name = True
        
    def to_feature_dict(self) -> Dict[str, float]:
        """Convert to feature dictionary for model input."""
        features = {}
        
        # Map all fields to their aliased names
        field_mapping = {
            'dst_port': 'Destination Port',
            'flow_duration': 'Flow Duration',
            'total_fwd_packets': 'Total Fwd Packets',
            'total_bwd_packets': 'Total Backward Packets',
            'total_length_fwd_packets': 'Total Length of Fwd Packets',
            'total_length_bwd_packets': 'Total Length of Bwd Packets',
            'fwd_packet_length_max': 'Fwd Packet Length Max',
            'fwd_packet_length_min': 'Fwd Packet Length Min',
            'fwd_packet_length_mean': 'Fwd Packet Length Mean',
            'fwd_packet_length_std': 'Fwd Packet Length Std',
            'bwd_packet_length_max': 'Bwd Packet Length Max',
            'bwd_packet_length_min': 'Bwd Packet Length Min',
            'bwd_packet_length_mean': 'Bwd Packet Length Mean',
            'bwd_packet_length_std': 'Bwd Packet Length Std',
            'flow_bytes_per_s': 'Flow Bytes/s',
            'flow_packets_per_s': 'Flow Packets/s',
            'flow_iat_mean': 'Flow IAT Mean',
            'flow_iat_std': 'Flow IAT Std',
            'flow_iat_max': 'Flow IAT Max',
            'flow_iat_min': 'Flow IAT Min',
            'syn_flag_count': 'SYN Flag Count',
            'fin_flag_count': 'FIN Flag Count',
            'rst_flag_count': 'RST Flag Count',
            'psh_flag_count': 'PSH Flag Count',
            'ack_flag_count': 'ACK Flag Count',
        }
        
        for field, column_name in field_mapping.items():
            value = getattr(self, field, 0)
            features[column_name] = float(value) if value is not None else 0.0
        
        # Add additional features
        if self.additional_features:
            features.update(self.additional_features)
        
        return features


class PredictionResponse(BaseModel):
    """Response schema for prediction endpoint."""
    
    is_malicious: bool = Field(..., description="Whether the traffic is malicious")
    attack_type: str = Field(..., description="Detected attack type or BENIGN")
    confidence: float = Field(..., description="Prediction confidence score")
    severity: str = Field(..., description="Alert severity level")
    
    # Detection details
    anomaly_detected: bool = Field(False, description="Whether anomaly detection flagged this")
    detection_sources: List[str] = Field(default_factory=list, description="Which models detected the threat")
    
    # Explanation
    explanation: Optional[str] = Field(None, description="Human-readable explanation")
    top_features: Optional[Dict[str, Any]] = Field(None, description="Top contributing features")
    
    # MITRE mapping
    mitre_technique_id: Optional[str] = Field(None, description="Primary MITRE ATT&CK technique ID")
    mitre_technique_name: Optional[str] = Field(None, description="MITRE technique name")
    mitre_tactic: Optional[str] = Field(None, description="MITRE tactic")
    mitre_url: Optional[str] = Field(None, description="MITRE ATT&CK URL")
    
    # Recommendations
    recommended_actions: Optional[List[str]] = Field(None, description="Recommended response actions")


class AlertResponse(BaseModel):
    """Response schema for alert data."""
    
    id: int
    timestamp: datetime
    attack_type: str
    severity: str
    confidence: float
    
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    summary: str
    status: str = "new"
    
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None


class AlertListResponse(BaseModel):
    """Response for listing alerts."""
    
    total: int
    page: int
    page_size: int
    alerts: List[AlertResponse]


class DashboardStats(BaseModel):
    """Dashboard statistics response."""
    
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    alerts_today: int = 0
    alerts_this_week: int = 0
    
    top_attack_types: Dict[str, int] = Field(default_factory=dict)
    top_source_ips: Dict[str, int] = Field(default_factory=dict)
    
    hourly_distribution: Dict[str, int] = Field(default_factory=dict)
    
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0


class ModelInfo(BaseModel):
    """Model information response."""
    
    random_forest: Optional[Dict[str, Any]] = None
    isolation_forest: Optional[Dict[str, Any]] = None
    autoencoder: Optional[Dict[str, Any]] = None
    
    models_loaded: bool = False
    last_trained: Optional[datetime] = None


class TrainRequest(BaseModel):
    """Request to train models."""
    
    use_sample_data: bool = Field(True, description="Use synthetic sample data for training")
    sample_size: int = Field(5000, description="Number of samples for training")
    dataset_path: Optional[str] = Field(None, description="Path to custom dataset")


class TrainResponse(BaseModel):
    """Response from training endpoint."""
    
    success: bool
    message: str
    metrics: Optional[Dict[str, Any]] = None
    training_time_seconds: Optional[float] = None


class MITREMappingResponse(BaseModel):
    """MITRE ATT&CK mapping response."""
    
    attack_type: str
    is_mapped: bool
    techniques: List[Dict[str, Any]]
    primary_technique: Optional[Dict[str, Any]] = None
    tactics: List[str]


class MITREMatrixResponse(BaseModel):
    """MITRE ATT&CK matrix response."""
    
    matrix: Dict[str, Any]
    detected_techniques: List[str]
    detection_count: int


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str
    version: str
    models_loaded: bool
    database_connected: bool
