"""
FastAPI routes for AI-IDS API.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse
from typing import List, Optional
from datetime import datetime, timedelta
import logging
import time
import numpy as np

from .schemas import (
    NetworkFlowInput, PredictionResponse, AlertResponse, AlertListResponse,
    DashboardStats, ModelInfo, TrainRequest, TrainResponse,
    MITREMappingResponse, MITREMatrixResponse, HealthResponse
)
from config import settings
from models import ModelManager
from data import DataPreprocessor, load_sample_data
from explainability import AlertGenerator
from mitre import AttackMapper

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["IDS API"])

# Global instances (initialized on startup)
model_manager: Optional[ModelManager] = None
preprocessor: Optional[DataPreprocessor] = None
alert_generator: Optional[AlertGenerator] = None
attack_mapper: Optional[AttackMapper] = None

# In-memory alert storage (for demo - in production use database)
alerts_store: List[dict] = []
alert_id_counter = 0


def get_model_manager() -> ModelManager:
    """Dependency to get model manager."""
    global model_manager
    if model_manager is None:
        model_manager = ModelManager(settings.MODEL_DIR)
        model_manager.load_all()
    return model_manager


def get_preprocessor() -> DataPreprocessor:
    """Dependency to get preprocessor."""
    global preprocessor
    if preprocessor is None:
        preprocessor = DataPreprocessor(feature_columns=settings.FEATURE_COLUMNS)
    return preprocessor


def get_alert_generator() -> AlertGenerator:
    """Dependency to get alert generator."""
    global alert_generator
    if alert_generator is None:
        alert_generator = AlertGenerator()
    return alert_generator


def get_attack_mapper() -> AttackMapper:
    """Dependency to get attack mapper."""
    global attack_mapper
    if attack_mapper is None:
        attack_mapper = AttackMapper()
    return attack_mapper


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check API health status."""
    mm = get_model_manager()
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        models_loaded=mm.is_loaded,
        database_connected=True  # Simplified for demo
    )


@router.post("/predict", response_model=PredictionResponse)
async def predict(
    flow: NetworkFlowInput,
    mm: ModelManager = Depends(get_model_manager),
    ag: AlertGenerator = Depends(get_alert_generator),
    am: AttackMapper = Depends(get_attack_mapper)
):
    """
    Analyze network flow and detect potential intrusions.
    """
    global alerts_store, alert_id_counter
    
    if not mm.is_loaded:
        raise HTTPException(
            status_code=503, 
            detail="Models not loaded. Please train models first using /api/train"
        )
    
    try:
        # Convert input to features
        features = flow.to_feature_dict()
        
        # Create feature array in correct order
        feature_array = np.zeros((1, len(settings.FEATURE_COLUMNS)))
        for i, col in enumerate(settings.FEATURE_COLUMNS):
            if col in features:
                feature_array[0, i] = features[col]
        
        # Get predictions from all models
        predictions = mm.predict(feature_array)
        ensemble = predictions['ensemble'][0]
        
        # Get MITRE mapping
        mitre_mapping = am.map_attack(ensemble['attack_type'])
        primary_technique = mitre_mapping.get('primary_technique')
        
        # Generate alert
        alert = ag.generate_alert(
            prediction=ensemble,
            features=features,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            mitre_mapping=mitre_mapping
        )
        
        # Store alert if malicious
        if ensemble['is_malicious']:
            alert_id_counter += 1
            alert['id'] = alert_id_counter
            alerts_store.append(alert)
            # Keep only last 1000 alerts
            if len(alerts_store) > 1000:
                alerts_store = alerts_store[-1000:]
        
        return PredictionResponse(
            is_malicious=ensemble['is_malicious'],
            attack_type=ensemble['attack_type'],
            confidence=ensemble['confidence'],
            severity=ensemble['severity'],
            anomaly_detected=ensemble['anomaly_detected'],
            detection_sources=ensemble['detection_sources'],
            explanation=alert.get('explanation'),
            top_features=alert.get('top_features'),
            mitre_technique_id=primary_technique.get('technique_id') if primary_technique else None,
            mitre_technique_name=primary_technique.get('name') if primary_technique else None,
            mitre_tactic=primary_technique.get('tactic') if primary_technique else None,
            mitre_url=primary_technique.get('url') if primary_technique else None,
            recommended_actions=alert.get('recommended_actions')
        )
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/batch", response_model=List[PredictionResponse])
async def predict_batch(
    flows: List[NetworkFlowInput],
    mm: ModelManager = Depends(get_model_manager),
    ag: AlertGenerator = Depends(get_alert_generator),
    am: AttackMapper = Depends(get_attack_mapper)
):
    """
    Batch analysis of multiple network flows.
    """
    if not mm.is_loaded:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    if len(flows) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 flows per batch")
    
    results = []
    for flow in flows:
        result = await predict(flow, mm, ag, am)
        results.append(result)
    
    return results


@router.post("/train", response_model=TrainResponse)
async def train_models(
    request: TrainRequest,
    background_tasks: BackgroundTasks,
    mm: ModelManager = Depends(get_model_manager)
):
    """
    Train all ML models.
    """
    global preprocessor
    
    try:
        start_time = time.time()
        
        # Load training data
        if request.use_sample_data:
            logger.info(f"Generating sample data with {request.sample_size} samples")
            df = load_sample_data(n_samples=request.sample_size)
        else:
            raise HTTPException(
                status_code=400, 
                detail="Custom dataset loading not implemented. Use sample data."
            )
        
        # Preprocess data
        preprocessor = DataPreprocessor(feature_columns=settings.FEATURE_COLUMNS)
        X, y = preprocessor.fit_transform(df, label_column='Label')
        
        # Save preprocessor
        preprocessor.save(f"{settings.MODEL_DIR}/preprocessor.joblib")
        
        # Train models
        metrics = mm.train_all(
            X_train=X,
            y_train=y,
            feature_names=preprocessor.feature_names,
            class_labels=preprocessor.class_labels
        )
        
        # Save models
        mm.save_all()
        
        training_time = time.time() - start_time
        
        return TrainResponse(
            success=True,
            message="All models trained successfully",
            metrics=metrics,
            training_time_seconds=training_time
        )
        
    except Exception as e:
        logger.error(f"Training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts", response_model=AlertListResponse)
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None
):
    """
    Get list of alerts with pagination and filtering.
    """
    filtered = alerts_store.copy()
    
    # Apply filters
    if severity:
        filtered = [a for a in filtered if a.get('severity') == severity]
    if attack_type:
        filtered = [a for a in filtered if a.get('attack_type') == attack_type]
    
    # Sort by timestamp descending
    filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Paginate
    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    page_alerts = filtered[start:end]
    
    # Convert to response format
    alert_responses = []
    for a in page_alerts:
        alert_responses.append(AlertResponse(
            id=a.get('id', 0),
            timestamp=datetime.fromisoformat(a['timestamp']),
            attack_type=a.get('attack_type', 'Unknown'),
            severity=a.get('severity', 'Low'),
            confidence=a.get('confidence', 0),
            src_ip=a.get('src_ip'),
            dst_ip=a.get('dst_ip'),
            src_port=a.get('src_port'),
            dst_port=a.get('dst_port'),
            summary=a.get('summary', ''),
            status=a.get('status', 'new'),
            mitre_technique_id=a.get('mitre', {}).get('primary_technique', {}).get('technique_id') if a.get('mitre') else None,
            mitre_technique_name=a.get('mitre', {}).get('primary_technique', {}).get('name') if a.get('mitre') else None
        ))
    
    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=alert_responses
    )


@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: int):
    """Get detailed information about a specific alert."""
    for alert in alerts_store:
        if alert.get('id') == alert_id:
            return alert
    raise HTTPException(status_code=404, detail="Alert not found")


@router.patch("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: int, status: str):
    """Update alert status."""
    valid_statuses = ['new', 'investigating', 'resolved', 'false_positive']
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    for alert in alerts_store:
        if alert.get('id') == alert_id:
            alert['status'] = status
            if status == 'resolved':
                alert['resolved_at'] = datetime.utcnow().isoformat()
            return {"message": "Status updated", "alert_id": alert_id, "status": status}
    
    raise HTTPException(status_code=404, detail="Alert not found")


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    
    # Calculate stats
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    attack_type_counts = {}
    source_ip_counts = {}
    hourly_counts = {str(h): 0 for h in range(24)}
    
    alerts_today = 0
    alerts_week = 0
    
    for alert in alerts_store:
        try:
            alert_time = datetime.fromisoformat(alert['timestamp'])
        except:
            continue
        
        # Severity
        sev = alert.get('severity', 'Low')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Attack types
        attack = alert.get('attack_type', 'Unknown')
        attack_type_counts[attack] = attack_type_counts.get(attack, 0) + 1
        
        # Source IPs
        src = alert.get('src_ip', 'Unknown')
        if src:
            source_ip_counts[src] = source_ip_counts.get(src, 0) + 1
        
        # Time-based
        if alert_time >= today_start:
            alerts_today += 1
        if alert_time >= week_start:
            alerts_week += 1
        
        # Hourly distribution
        hour = str(alert_time.hour)
        hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
    
    # Get top 5 for each
    top_attacks = dict(sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    top_sources = dict(sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    
    return DashboardStats(
        total_alerts=len(alerts_store),
        critical_count=severity_counts.get('Critical', 0),
        high_count=severity_counts.get('High', 0),
        medium_count=severity_counts.get('Medium', 0),
        low_count=severity_counts.get('Low', 0),
        alerts_today=alerts_today,
        alerts_this_week=alerts_week,
        top_attack_types=top_attacks,
        top_source_ips=top_sources,
        hourly_distribution=hourly_counts
    )


@router.get("/model-info", response_model=ModelInfo)
async def get_model_info(mm: ModelManager = Depends(get_model_manager)):
    """Get information about loaded models."""
    info = mm.get_model_info()
    return ModelInfo(
        random_forest=info.get('random_forest'),
        isolation_forest=info.get('isolation_forest'),
        autoencoder=info.get('autoencoder'),
        models_loaded=mm.is_loaded
    )


@router.get("/mitre/mapping/{attack_type}", response_model=MITREMappingResponse)
async def get_mitre_mapping(
    attack_type: str,
    am: AttackMapper = Depends(get_attack_mapper)
):
    """Get MITRE ATT&CK mapping for an attack type."""
    mapping = am.map_attack(attack_type)
    return MITREMappingResponse(**mapping)


@router.get("/mitre/matrix", response_model=MITREMatrixResponse)
async def get_mitre_matrix(am: AttackMapper = Depends(get_attack_mapper)):
    """Get MITRE ATT&CK matrix with detected techniques highlighted."""
    # Get attack types from recent alerts
    attack_types = [a.get('attack_type', '') for a in alerts_store[-100:]]
    matrix_data = am.get_matrix_for_attacks(attack_types)
    return MITREMatrixResponse(**matrix_data)


@router.get("/mitre/technique/{technique_id}")
async def get_technique_details(
    technique_id: str,
    am: AttackMapper = Depends(get_attack_mapper)
):
    """Get detailed information about a MITRE ATT&CK technique."""
    details = am.get_technique_details(technique_id)
    if not details:
        raise HTTPException(status_code=404, detail="Technique not found")
    return details


@router.post("/demo/generate-alerts")
async def generate_demo_alerts(
    count: int = Query(10, ge=1, le=100),
    mm: ModelManager = Depends(get_model_manager),
    ag: AlertGenerator = Depends(get_alert_generator),
    am: AttackMapper = Depends(get_attack_mapper)
):
    """Generate demo alerts using sample data (for testing)."""
    global alerts_store, alert_id_counter
    
    if not mm.is_loaded:
        raise HTTPException(status_code=503, detail="Models not loaded. Train first.")
    
    # Generate sample data
    df = load_sample_data(n_samples=count * 2)
    
    generated = 0
    for _, row in df.iterrows():
        if generated >= count:
            break
        
        # Skip some benign traffic
        if row['Label'] == 'BENIGN' and np.random.random() > 0.3:
            continue
        
        # Create features dict
        features = {col: row[col] for col in settings.FEATURE_COLUMNS if col in row}
        
        # Create feature array
        X = np.array([[features.get(col, 0) for col in settings.FEATURE_COLUMNS]])
        
        # Get prediction
        predictions = mm.predict(X)
        ensemble = predictions['ensemble'][0]
        
        if ensemble['is_malicious']:
            mitre_mapping = am.map_attack(ensemble['attack_type'])
            alert = ag.generate_alert(
                prediction=ensemble,
                features=features,
                src_ip=f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                dst_ip=f"10.0.0.{np.random.randint(1,255)}",
                src_port=np.random.randint(1024, 65535),
                dst_port=int(features.get('Destination Port', 80)),
                mitre_mapping=mitre_mapping
            )
            alert_id_counter += 1
            alert['id'] = alert_id_counter
            alerts_store.append(alert)
            generated += 1
    
    return {"message": f"Generated {generated} demo alerts", "total_alerts": len(alerts_store)}
