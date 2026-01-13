"""
Real-time Network Monitor: Integrates packet capture with ML-based intrusion detection.
"""
import asyncio
import threading
import queue
import time
import logging
from datetime import datetime
from typing import Optional, Callable, Dict, List, Any
from collections import deque
import numpy as np

from .packet_capture import PacketCapture, SCAPY_AVAILABLE
from .flow_aggregator import NetworkFlow, PacketInfo

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Real-time network monitoring with ML-based intrusion detection.
    Captures network traffic, analyzes flows using trained models,
    and generates alerts for detected threats.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        model_manager = None,
        alert_generator = None,
        attack_mapper = None,
        feature_columns: List[str] = None,
        on_alert: Optional[Callable[[Dict], None]] = None,
        on_traffic_update: Optional[Callable[[Dict], None]] = None,
    ):
        """
        Initialize the network monitor.
        
        Args:
            interface: Network interface to monitor (auto-detect if None)
            model_manager: Trained ML model manager for predictions
            alert_generator: Alert generator for creating human-readable alerts
            attack_mapper: MITRE ATT&CK mapper
            feature_columns: List of feature columns expected by models
            on_alert: Callback when a threat is detected
            on_traffic_update: Callback for traffic statistics updates
        """
        self.interface = interface
        self.model_manager = model_manager
        self.alert_generator = alert_generator
        self.attack_mapper = attack_mapper
        self.feature_columns = feature_columns or []
        self.on_alert = on_alert
        self.on_traffic_update = on_traffic_update
        
        # Packet capture (will be initialized on start)
        self.capture: Optional[PacketCapture] = None
        
        # Traffic metrics (last 60 seconds)
        self.traffic_history = deque(maxlen=60)
        self.current_second_stats = {
            'timestamp': None,
            'packets': 0,
            'bytes': 0,
            'flows_completed': 0,
            'benign_flows': 0,
            'malicious_flows': 0,
            'alerts': []
        }
        
        # Alerts storage
        self.alerts: List[Dict] = []
        self.alert_id_counter = 0
        self._alerts_lock = threading.Lock()
        
        # Analysis queue
        self._analysis_queue = queue.Queue(maxsize=1000)
        self._analysis_thread = None
        
        # State
        self._running = False
        self._metrics_thread = None
        
        # Stats
        self.stats = {
            'start_time': None,
            'total_packets': 0,
            'total_bytes': 0,
            'total_flows': 0,
            'total_alerts': 0,
            'flows_analyzed': 0
        }
    
    def _on_packet(self, packet: PacketInfo):
        """Called for each captured packet."""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += packet.length
        self.current_second_stats['packets'] += 1
        self.current_second_stats['bytes'] += packet.length
    
    def _on_flow_complete(self, flow: NetworkFlow):
        """Called when a flow is completed - queue for analysis."""
        self.stats['total_flows'] += 1
        self.current_second_stats['flows_completed'] += 1
        
        try:
            self._analysis_queue.put_nowait(flow)
        except queue.Full:
            logger.warning("Analysis queue full, dropping flow")
    
    def _analyze_flow(self, flow: NetworkFlow) -> Optional[Dict]:
        """Analyze a flow using ML models and return detection result."""
        if not self.model_manager or not self.model_manager.is_loaded:
            return None
        
        try:
            # Convert flow to features
            features = flow.to_feature_dict()
            
            # Create feature array in correct order
            X = np.zeros((1, len(self.feature_columns)))
            for i, col in enumerate(self.feature_columns):
                if col in features:
                    val = features[col]
                    if isinstance(val, (int, float)) and not np.isnan(val) and not np.isinf(val):
                        X[0, i] = val
            
            # Get prediction
            predictions = self.model_manager.predict(X)
            ensemble = predictions['ensemble'][0]
            
            self.stats['flows_analyzed'] += 1
            
            return {
                'flow': flow,
                'features': features,
                'prediction': ensemble,
                'is_malicious': ensemble['is_malicious'],
                'attack_type': ensemble['attack_type'],
                'confidence': ensemble['confidence'],
                'severity': ensemble['severity']
            }
            
        except Exception as e:
            logger.error(f"Error analyzing flow: {e}")
            return None
    
    def _analysis_loop(self):
        """Background thread for flow analysis."""
        while self._running:
            try:
                flow = self._analysis_queue.get(timeout=0.5)
                
                result = self._analyze_flow(flow)
                
                if result:
                    if result['is_malicious']:
                        self.current_second_stats['malicious_flows'] += 1
                        self._generate_alert(result)
                    else:
                        self.current_second_stats['benign_flows'] += 1
                        
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Analysis error: {e}")
    
    def _generate_alert(self, result: Dict):
        """Generate an alert for a detected threat."""
        with self._alerts_lock:
            self.alert_id_counter += 1
            
            flow = result['flow']
            prediction = result['prediction']
            features = result['features']
            
            # Get MITRE mapping if available
            mitre_mapping = None
            if self.attack_mapper:
                try:
                    mitre_mapping = self.attack_mapper.map_attack(result['attack_type'])
                except:
                    pass
            
            # Generate human-readable alert
            if self.alert_generator:
                try:
                    alert = self.alert_generator.generate_alert(
                        prediction=prediction,
                        features=features,
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        src_port=flow.src_port,
                        dst_port=flow.dst_port,
                        mitre_mapping=mitre_mapping
                    )
                except Exception as e:
                    logger.error(f"Error generating alert: {e}")
                    alert = {}
            else:
                alert = {}
            
            # Build alert object
            alert_obj = {
                'id': self.alert_id_counter,
                'timestamp': datetime.utcnow().isoformat(),
                'attack_type': result['attack_type'],
                'severity': result['severity'],
                'confidence': result['confidence'],
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'summary': alert.get('summary', f"{result['attack_type']} detected from {flow.src_ip}"),
                'recommended_actions': alert.get('recommended_actions', []),
                'mitre': mitre_mapping,
                'status': 'new',
                'flow_duration': (flow.last_time - flow.start_time),
                'total_packets': flow.total_fwd_packets + flow.total_bwd_packets,
                'total_bytes': flow.total_fwd_length + flow.total_bwd_length
            }
            
            self.alerts.append(alert_obj)
            self.stats['total_alerts'] += 1
            self.current_second_stats['alerts'].append(alert_obj)
            
            # Keep only last 1000 alerts
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
            
            # Call callback
            if self.on_alert:
                try:
                    self.on_alert(alert_obj)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.warning(f"ALERT: {result['attack_type']} detected from {flow.src_ip} (confidence: {result['confidence']:.2%})")
    
    def _metrics_loop(self):
        """Update traffic metrics every second."""
        last_update = time.time()
        
        while self._running:
            time.sleep(0.5)
            
            now = time.time()
            if now - last_update >= 1.0:
                last_update = now
                
                # Finalize current second stats
                stats = self.current_second_stats.copy()
                stats['timestamp'] = datetime.utcnow().isoformat()
                
                # Calculate rates
                capture_stats = self.capture.get_stats() if self.capture else {}
                
                traffic_data = {
                    'timestamp': stats['timestamp'],
                    'packets_per_second': stats['packets'],
                    'bytes_per_second': stats['bytes'],
                    'mbps': (stats['bytes'] * 8) / 1_000_000,
                    'total_flows': stats['flows_completed'],
                    'benign_flows': stats['benign_flows'],
                    'malicious_flows': stats['malicious_flows'],
                    'benign_percentage': (
                        stats['benign_flows'] / max(1, stats['flows_completed']) * 100
                    ) if stats['flows_completed'] > 0 else 100,
                    'malicious_percentage': (
                        stats['malicious_flows'] / max(1, stats['flows_completed']) * 100
                    ) if stats['flows_completed'] > 0 else 0,
                    'is_spike': stats['malicious_flows'] > 5,
                    'new_alerts': len(stats['alerts']),
                    'total_alerts': len(self.alerts),
                    'attack_types': self._count_attack_types(stats['alerts']),
                    'active_flows': capture_stats.get('active_flows', 0)
                }
                
                self.traffic_history.append(traffic_data)
                
                # Call callback
                if self.on_traffic_update:
                    try:
                        self.on_traffic_update(traffic_data)
                    except Exception as e:
                        logger.error(f"Error in traffic callback: {e}")
                
                # Reset current second stats
                self.current_second_stats = {
                    'timestamp': None,
                    'packets': 0,
                    'bytes': 0,
                    'flows_completed': 0,
                    'benign_flows': 0,
                    'malicious_flows': 0,
                    'alerts': []
                }
    
    def _count_attack_types(self, alerts: List[Dict]) -> Dict[str, int]:
        """Count attack types in alerts."""
        counts = {}
        for alert in alerts:
            attack = alert.get('attack_type', 'Unknown')
            counts[attack] = counts.get(attack, 0) + 1
        return counts
    
    def start(self):
        """Start network monitoring."""
        if self._running:
            logger.warning("Monitor already running")
            return False
        
        if not SCAPY_AVAILABLE:
            logger.error("scapy is required for network monitoring")
            return False
        
        self._running = True
        self.stats['start_time'] = time.time()
        
        # Initialize packet capture
        self.capture = PacketCapture(
            interface=self.interface,
            on_packet=self._on_packet,
            on_flow=self._on_flow_complete,
            flow_timeout=5.0  # 5 second timeout for real-time detection
        )
        
        # Start threads
        self._analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._analysis_thread.start()
        
        self._metrics_thread = threading.Thread(target=self._metrics_loop, daemon=True)
        self._metrics_thread.start()
        
        # Start capture
        self.capture.start()
        
        logger.info(f"Network monitor started on interface: {self.capture.interface}")
        return True
    
    def stop(self):
        """Stop network monitoring."""
        self._running = False
        
        # Stop capture
        if self.capture:
            self.capture.stop()
        
        # Stop threads
        if self._analysis_thread:
            self._analysis_thread.join(timeout=2.0)
        
        if self._metrics_thread:
            self._metrics_thread.join(timeout=2.0)
        
        logger.info("Network monitor stopped")
    
    def get_stats(self) -> Dict:
        """Get monitor statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        capture_stats = self.capture.get_stats() if self.capture else {}
        
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'interface': self.capture.interface if self.capture else None,
            'is_running': self._running,
            **capture_stats
        }
    
    def get_recent_traffic(self) -> List[Dict]:
        """Get recent traffic history."""
        return list(self.traffic_history)
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent alerts."""
        with self._alerts_lock:
            return self.alerts[-limit:]
    
    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._running
    
    @staticmethod
    def list_interfaces() -> List[str]:
        """List available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []
        return PacketCapture.list_interfaces()
