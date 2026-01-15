"""
FastAPI routes for PhalanxAI API.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse, StreamingResponse
from typing import List, Optional
from datetime import datetime, timedelta
from collections import deque
import asyncio
import logging
import time
import json
import numpy as np
import threading
import pandas as pd
import io

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

# Try to import network monitor (requires scapy)
try:
    from capture import NetworkMonitor
    CAPTURE_AVAILABLE = True
except ImportError:
    CAPTURE_AVAILABLE = False
    NetworkMonitor = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["IDS API"])

# Global instances (initialized on startup)
model_manager: Optional[ModelManager] = None
preprocessor: Optional[DataPreprocessor] = None
alert_generator: Optional[AlertGenerator] = None
attack_mapper: Optional[AttackMapper] = None
network_monitor: Optional["NetworkMonitor"] = None

# In-memory alert storage (for demo - in production use database)
alerts_store: List[dict] = []
alert_id_counter = 0

# Real-time traffic metrics (last 60 seconds)
traffic_metrics = deque(maxlen=60)
traffic_lock = asyncio.Lock()

# Real network monitoring state
monitor_traffic_queue = asyncio.Queue(maxsize=100)




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
            # Load CICIDS2017 dataset from Dataset folder
            import pandas as pd
            from pathlib import Path
            
            dataset_dir = Path("Dataset")
            if not dataset_dir.exists():
                raise HTTPException(
                    status_code=400, 
                    detail="Dataset folder not found. Please create a 'Dataset' folder with CICIDS2017 CSV files."
                )
            
            csv_files = list(dataset_dir.glob("*.csv"))
            if not csv_files:
                raise HTTPException(
                    status_code=400,
                    detail="No CSV files found in Dataset folder."
                )
            
            logger.info(f"Loading {len(csv_files)} CSV files from Dataset folder")
            
            dfs = []
            for csv_file in csv_files:
                logger.info(f"Loading {csv_file.name}...")
                try:
                    chunk_df = pd.read_csv(csv_file, encoding='utf-8', low_memory=False)
                    chunk_df.columns = chunk_df.columns.str.strip()
                    dfs.append(chunk_df)
                except Exception as e:
                    logger.warning(f"Error loading {csv_file.name}: {e}")
            
            if not dfs:
                raise HTTPException(status_code=400, detail="Failed to load any CSV files.")
            
            df = pd.concat(dfs, ignore_index=True)
            logger.info(f"Loaded {len(df)} total samples")
            
            # Clean the Label column
            if 'Label' in df.columns:
                df['Label'] = df['Label'].str.strip()
            elif ' Label' in df.columns:
                df['Label'] = df[' Label'].str.strip()
                df = df.drop(columns=[' Label'])
            
            # Sample if dataset is too large (for faster training)
            max_samples = request.sample_size or 100000
            if len(df) > max_samples:
                logger.info(f"Sampling {max_samples} rows for training efficiency")
                # Stratified sampling to maintain class distribution
                df = df.groupby('Label', group_keys=False).apply(
                    lambda x: x.sample(min(len(x), max(1, int(max_samples * len(x) / len(df)))),
                                      random_state=42)
                ).reset_index(drop=True)
            
            # Handle inf and NaN values
            df = df.replace([np.inf, -np.inf], np.nan)
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            for col in numeric_cols:
                df[col] = df[col].fillna(df[col].median() if df[col].notna().any() else 0)
            
            logger.info(f"Final dataset: {len(df)} samples, {df['Label'].nunique()} classes")
            logger.info(f"Class distribution:\n{df['Label'].value_counts()}")
        
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
            message=f"All models trained successfully on {len(df)} samples",
            metrics=metrics,
            training_time_seconds=training_time
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """Get list of generated alerts."""
    filtered_alerts = alerts_store
    
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a['severity'].lower() == severity.lower()]
        
    if status:
        filtered_alerts = [a for a in filtered_alerts if a['status'].lower() == status.lower()]
    
    # Sort by timestamp descending (newest first)
    filtered_alerts = sorted(filtered_alerts, key=lambda x: x['timestamp'], reverse=True)
    
    total = len(filtered_alerts)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "alerts": filtered_alerts[start:end],
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/alerts/export")
async def export_alerts():
    """Download all alerts as CSV."""
    if not alerts_store:
        raise HTTPException(
            status_code=404,
            detail="No alerts to export"
        )
        
    # Convert alerts to DataFrame
    df = pd.DataFrame(alerts_store)
    
    # Select and reorder columns for better readability
    columns = ['id', 'timestamp', 'attack_type', 'severity', 'confidence', 
               'src_ip', 'dst_ip', 'dst_port', 'summary']
    
    # Filter columns that exist
    cls = [c for c in columns if c in df.columns]
    df = df[cls]
    
    # Rename for export
    df.rename(columns={
        'src_ip': 'Source IP',
        'dst_ip': 'Destination IP',
        'dst_port': 'Port',
        'attack_type': 'Attack Type',
        'timestamp': 'Time (UTC)'
    }, inplace=True)
    
    # Generate CSV
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    response = StreamingResponse(iter([stream.getvalue()]), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=phalanx_alerts_export.csv"
    
    return response


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


# ============ Real-Time Traffic Streaming ============

async def generate_traffic_stream():
    """
    SSE generator for real-time traffic data.
    Simulates network traffic with occasional attacks.
    """
    mm = get_model_manager()
    am = get_attack_mapper()
    ag = get_alert_generator()
    
    global alerts_store, alert_id_counter
    
    while True:
        try:
            # Simulate traffic metrics
            timestamp = datetime.utcnow().isoformat()
            
            # Base traffic with some randomness (packets per second)
            base_pps = np.random.normal(1500, 300)
            base_bps = base_pps * np.random.normal(800, 200)  # bytes per second
            
            # Simulate occasional spikes (potential attacks)
            is_spike = np.random.random() < 0.08  # 8% chance of spike
            if is_spike:
                spike_multiplier = np.random.uniform(2, 5)
                base_pps *= spike_multiplier
                base_bps *= spike_multiplier
            
            # Traffic classification
            benign_pct = np.random.uniform(0.85, 0.99) if not is_spike else np.random.uniform(0.4, 0.7)
            malicious_pct = 1 - benign_pct
            
            # Count by type
            total_flows = int(np.random.uniform(50, 150))
            benign_flows = int(total_flows * benign_pct)
            malicious_flows = total_flows - benign_flows
            
            # Detect attack type if malicious traffic
            attack_types = {}
            new_alerts = 0
            
            if malicious_flows > 0 and mm.is_loaded:
                # Simulate detection
                attack_options = ['DDoS', 'PortScan', 'DoS Hulk', 'SSH-Patator', 'Bot']
                for _ in range(malicious_flows):
                    attack = np.random.choice(attack_options)
                    attack_types[attack] = attack_types.get(attack, 0) + 1
                    
                    # Generate alert for some
                    if np.random.random() < 0.3:
                        alert_id_counter += 1
                        alert = {
                            'id': alert_id_counter,
                            'timestamp': timestamp,
                            'attack_type': attack,
                            'severity': np.random.choice(['Critical', 'High', 'Medium']),
                            'confidence': np.random.uniform(0.6, 0.95),
                            'src_ip': f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                            'dst_ip': f"10.0.0.{np.random.randint(1,255)}",
                            'src_port': np.random.randint(1024, 65535),
                            'dst_port': np.random.choice([22, 80, 443, 3306, 8080]),
                            'summary': f"{attack} detected",
                            'status': 'new'
                        }
                        alerts_store.append(alert)
                        new_alerts += 1
                        
                        # Keep only last 1000
                        if len(alerts_store) > 1000:
                            alerts_store = alerts_store[-1000:]
            
            # Traffic data point
            data = {
                'timestamp': timestamp,
                'packets_per_second': max(0, int(base_pps)),
                'bytes_per_second': max(0, int(base_bps)),
                'mbps': round(max(0, base_bps * 8 / 1_000_000), 2),
                'total_flows': total_flows,
                'benign_flows': benign_flows,
                'malicious_flows': malicious_flows,
                'benign_percentage': round(benign_pct * 100, 1),
                'malicious_percentage': round(malicious_pct * 100, 1),
                'is_spike': is_spike,
                'attack_types': attack_types,
                'new_alerts': new_alerts,
                'total_alerts': len(alerts_store)
            }
            
            # Store in metrics
            async with traffic_lock:
                traffic_metrics.append(data)
            
            # Send SSE event
            yield f"data: {json.dumps(data)}\n\n"
            
            # Wait before next update (1 second intervals)
            await asyncio.sleep(1)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Traffic stream error: {e}")
            await asyncio.sleep(1)


@router.get("/traffic/stream")
async def stream_traffic():
    """
    Server-Sent Events endpoint for real-time traffic data.
    Connect to this endpoint to receive live traffic updates every second.
    """
    return StreamingResponse(
        generate_traffic_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
    )


@router.get("/traffic/history")
async def get_traffic_history():
    """Get the last 60 seconds of traffic data."""
    async with traffic_lock:
        return {
            "history": list(traffic_metrics),
            "count": len(traffic_metrics)
        }


@router.get("/traffic/summary")
async def get_traffic_summary():
    """Get current traffic summary."""
    async with traffic_lock:
        if not traffic_metrics:
            return {
                "avg_pps": 0,
                "avg_bps": 0,
                "avg_mbps": 0,
                "total_flows_1min": 0,
                "malicious_flows_1min": 0,
                "threat_percentage": 0
            }
        
        recent = list(traffic_metrics)
        
        return {
            "avg_pps": int(np.mean([m['packets_per_second'] for m in recent])),
            "avg_bps": int(np.mean([m['bytes_per_second'] for m in recent])),
            "avg_mbps": round(np.mean([m['mbps'] for m in recent]), 2),
            "total_flows_1min": sum([m['total_flows'] for m in recent]),
            "malicious_flows_1min": sum([m['malicious_flows'] for m in recent]),
            "threat_percentage": round(
                sum([m['malicious_flows'] for m in recent]) / 
                max(1, sum([m['total_flows'] for m in recent])) * 100, 1
            )
        }


# ============ Real Network Monitoring ============

# Thread-safe lock for alerts
_alerts_lock = threading.Lock()

def _on_monitor_alert(alert: dict):
    """Callback when network monitor detects a threat."""
    global alerts_store, alert_id_counter
    with _alerts_lock:
        alert_id_counter += 1
        alert['id'] = alert_id_counter
        alerts_store.append(alert)
        if len(alerts_store) > 1000:
            alerts_store = alerts_store[-1000:]


def _on_monitor_traffic(traffic_data: dict):
    """Callback for real-time traffic updates."""
    try:
        asyncio.get_event_loop().call_soon_threadsafe(
            lambda: traffic_metrics.append(traffic_data)
        )
    except:
        traffic_metrics.append(traffic_data)


@router.get("/monitor/interfaces")
async def list_network_interfaces():
    """List available network interfaces for monitoring."""
    if not CAPTURE_AVAILABLE:
        return {
            "available": False,
            "message": "Network capture not available. Install scapy: pip install scapy",
            "interfaces": []
        }
    
    try:
        interfaces = NetworkMonitor.list_interfaces()
        return {
            "available": True,
            "interfaces": interfaces,
            "message": "Select an interface to start monitoring"
        }
    except Exception as e:
        return {
            "available": False,
            "message": str(e),
            "interfaces": []
        }


@router.post("/monitor/start")
async def start_network_monitor(
    interface: Optional[str] = Query(None, description="Network interface to monitor"),
    mm: ModelManager = Depends(get_model_manager),
    ag: AlertGenerator = Depends(get_alert_generator),
    am: AttackMapper = Depends(get_attack_mapper)
):
    """
    Start real-time network monitoring.
    Requires root/admin privileges for packet capture.
    """
    global network_monitor
    
    if not CAPTURE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Network capture not available. Install scapy: pip install scapy"
        )
    
    if not mm.is_loaded:
        raise HTTPException(
            status_code=503,
            detail="Models not loaded. Train models first using /api/train"
        )
    
    if network_monitor and network_monitor.is_running:
        return {
            "status": "already_running",
            "message": f"Monitor already running on interface: {network_monitor.capture.interface}",
            "interface": network_monitor.capture.interface
        }
    
    try:
        # Create network monitor
        network_monitor = NetworkMonitor(
            interface=interface,
            model_manager=mm,
            alert_generator=ag,
            attack_mapper=am,
            feature_columns=settings.FEATURE_COLUMNS,
            on_alert=_on_monitor_alert,
            on_traffic_update=_on_monitor_traffic
        )
        
        # Start monitoring
        success = network_monitor.start()
        
        if success:
            return {
                "status": "started",
                "message": f"Network monitoring started on interface: {network_monitor.capture.interface}",
                "interface": network_monitor.capture.interface
            }
        else:
            raise HTTPException(
                status_code=500,
                detail="Failed to start network monitoring"
            )
            
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="Permission denied. Run with sudo/admin privileges for packet capture."
        )
    except Exception as e:
        logger.error(f"Error starting network monitor: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitor/stop")
async def stop_network_monitor():
    """Stop real-time network monitoring."""
    global network_monitor
    
    if not network_monitor or not network_monitor.is_running:
        return {
            "status": "not_running",
            "message": "Network monitor is not running"
        }
    
    try:
        network_monitor.stop()
        return {
            "status": "stopped",
            "message": "Network monitoring stopped",
            "stats": network_monitor.get_stats()
        }
    except Exception as e:
        logger.error(f"Error stopping network monitor: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitor/status")
async def get_monitor_status():
    """Get current network monitor status."""
    global network_monitor
    
    if not CAPTURE_AVAILABLE:
        return {
            "available": False,
            "running": False,
            "message": "Network capture not available. Install scapy: pip install scapy"
        }
    
    if not network_monitor:
        return {
            "available": True,
            "running": False,
            "message": "Monitor not initialized. Start with /api/monitor/start"
        }
    
    return {
        "available": True,
        "running": network_monitor.is_running,
        "interface": network_monitor.capture.interface if network_monitor.capture else None,
        "stats": network_monitor.get_stats() if network_monitor.is_running else None
    }


@router.get("/monitor/stream")
async def stream_real_traffic():
    """
    Server-Sent Events endpoint for REAL network traffic.
    Streams actual captured traffic when monitor is running.
    Falls back to simulation if monitor is not running.
    """
    global network_monitor
    
    async def generate():
        while True:
            try:
                if network_monitor and network_monitor.is_running:
                    # Get real traffic data
                    history = network_monitor.get_recent_traffic()
                    if history:
                        data = history[-1]  # Most recent
                    else:
                        data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'packets_per_second': 0,
                            'bytes_per_second': 0,
                            'mbps': 0,
                            'total_flows': 0,
                            'benign_flows': 0,
                            'malicious_flows': 0,
                            'benign_percentage': 100,
                            'malicious_percentage': 0,
                            'is_spike': False,
                            'new_alerts': 0,
                            'total_alerts': len(alerts_store),
                            'attack_types': {}
                        }
                else:
                    # Monitor not running - send idle state
                    data = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'packets_per_second': 0,
                        'bytes_per_second': 0,
                        'mbps': 0,
                        'total_flows': 0,
                        'benign_flows': 0,
                        'malicious_flows': 0,
                        'benign_percentage': 0,
                        'malicious_percentage': 0,
                        'is_spike': False,
                        'attack_types': {},
                        'new_alerts': 0,
                        'total_alerts': len(alerts_store),
                        'simulation': False,
                        'status': 'idle'
                    }
                
                yield f"data: {json.dumps(data)}\n\n"
                await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stream error: {e}")
                await asyncio.sleep(1)
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


async def _generate_simulated_traffic():
    """Generate simulated traffic data when real monitoring is not active."""
    timestamp = datetime.utcnow().isoformat()
    
    # Simulated traffic with occasional spikes
    base_pps = np.random.normal(1500, 300)
    base_bps = base_pps * np.random.normal(800, 200)
    
    is_spike = np.random.random() < 0.08
    if is_spike:
        base_pps *= np.random.uniform(2, 5)
        base_bps *= np.random.uniform(2, 5)
    
    benign_pct = np.random.uniform(0.85, 0.99) if not is_spike else np.random.uniform(0.4, 0.7)
    total_flows = int(np.random.uniform(50, 150))
    benign_flows = int(total_flows * benign_pct)
    malicious_flows = total_flows - benign_flows
    
    return {
        'timestamp': timestamp,
        'packets_per_second': max(0, int(base_pps)),
        'bytes_per_second': max(0, int(base_bps)),
        'mbps': round(max(0, base_bps * 8 / 1_000_000), 2),
        'total_flows': total_flows,
        'benign_flows': benign_flows,
        'malicious_flows': malicious_flows,
        'benign_percentage': round(benign_pct * 100, 1),
        'malicious_percentage': round((1 - benign_pct) * 100, 1),
        'is_spike': is_spike,
        'attack_types': {},
        'new_alerts': 0,
        'total_alerts': len(alerts_store),
        'simulation': True  # Flag to indicate simulated data
    }


