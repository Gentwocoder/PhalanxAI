"""
Flow Aggregator: Groups packets into network flows and extracts features.
A flow is identified by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
"""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
import threading
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Information extracted from a single packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # TCP=6, UDP=17, ICMP=1
    length: int
    payload_length: int
    flags: Dict[str, bool] = field(default_factory=dict)
    is_forward: bool = True  # Direction relative to flow


@dataclass
class NetworkFlow:
    """Represents a bidirectional network flow with extracted features."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float
    last_time: float
    
    # Packet counts
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    
    # Length statistics
    total_fwd_length: int = 0
    total_bwd_length: int = 0
    fwd_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)
    
    # Inter-arrival times
    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)
    flow_iats: List[float] = field(default_factory=list)
    
    # Flag counts
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0
    
    # Header lengths
    fwd_header_length: int = 0
    bwd_header_length: int = 0
    
    # Window sizes
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    
    # Active/Idle times
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)
    
    # Timestamps for IAT calculation
    last_fwd_time: float = 0
    last_bwd_time: float = 0
    last_active_time: float = 0
    
    def add_packet(self, packet: PacketInfo):
        """Add a packet to this flow and update statistics."""
        now = packet.timestamp
        
        # Update flow timing
        if self.last_time > 0:
            iat = now - self.last_time
            self.flow_iats.append(iat)
            
            # Track active/idle (idle threshold = 1 second)
            if iat > 1.0:
                self.idle_times.append(iat)
            else:
                self.active_times.append(iat)
        
        self.last_time = now
        
        if packet.is_forward:
            self.total_fwd_packets += 1
            self.total_fwd_length += packet.length
            self.fwd_lengths.append(packet.length)
            
            if self.last_fwd_time > 0:
                self.fwd_iats.append(now - self.last_fwd_time)
            self.last_fwd_time = now
            
            self.fwd_header_length += 20  # Approximate TCP header
        else:
            self.total_bwd_packets += 1
            self.total_bwd_length += packet.length
            self.bwd_lengths.append(packet.length)
            
            if self.last_bwd_time > 0:
                self.bwd_iats.append(now - self.last_bwd_time)
            self.last_bwd_time = now
            
            self.bwd_header_length += 20
        
        # Update flag counts
        flags = packet.flags
        if flags.get('SYN'):
            self.syn_count += 1
        if flags.get('FIN'):
            self.fin_count += 1
        if flags.get('RST'):
            self.rst_count += 1
        if flags.get('PSH'):
            self.psh_count += 1
        if flags.get('ACK'):
            self.ack_count += 1
        if flags.get('URG'):
            self.urg_count += 1
        if flags.get('ECE'):
            self.ece_count += 1
        if flags.get('CWR'):
            self.cwe_count += 1
    
    def to_feature_dict(self) -> Dict:
        """Convert flow to CICIDS2017-compatible feature dictionary."""
        duration = max(1, (self.last_time - self.start_time) * 1_000_000)  # microseconds
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        total_length = self.total_fwd_length + self.total_bwd_length
        
        # Calculate statistics safely
        def safe_mean(lst): return sum(lst) / len(lst) if lst else 0
        def safe_std(lst): 
            if len(lst) < 2: return 0
            mean = safe_mean(lst)
            return (sum((x - mean) ** 2 for x in lst) / len(lst)) ** 0.5
        def safe_max(lst): return max(lst) if lst else 0
        def safe_min(lst): return min(lst) if lst else 0
        
        # Convert IATs from seconds to microseconds
        fwd_iats_us = [x * 1_000_000 for x in self.fwd_iats]
        bwd_iats_us = [x * 1_000_000 for x in self.bwd_iats]
        flow_iats_us = [x * 1_000_000 for x in self.flow_iats]
        active_us = [x * 1_000_000 for x in self.active_times]
        idle_us = [x * 1_000_000 for x in self.idle_times]
        
        features = {
            # Basic flow info
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'Destination Port': self.dst_port,
            
            # Duration and packet counts
            'Flow Duration': duration,
            'Total Fwd Packets': self.total_fwd_packets,
            'Total Backward Packets': self.total_bwd_packets,
            
            # Length statistics
            'Total Length of Fwd Packets': self.total_fwd_length,
            'Total Length of Bwd Packets': self.total_bwd_length,
            'Fwd Packet Length Max': safe_max(self.fwd_lengths),
            'Fwd Packet Length Min': safe_min(self.fwd_lengths) if self.fwd_lengths else 0,
            'Fwd Packet Length Mean': safe_mean(self.fwd_lengths),
            'Fwd Packet Length Std': safe_std(self.fwd_lengths),
            'Bwd Packet Length Max': safe_max(self.bwd_lengths),
            'Bwd Packet Length Min': safe_min(self.bwd_lengths) if self.bwd_lengths else 0,
            'Bwd Packet Length Mean': safe_mean(self.bwd_lengths),
            'Bwd Packet Length Std': safe_std(self.bwd_lengths),
            
            # Flow rates
            'Flow Bytes/s': total_length / (duration / 1_000_000) if duration > 0 else 0,
            'Flow Packets/s': total_packets / (duration / 1_000_000) if duration > 0 else 0,
            
            # IAT statistics
            'Flow IAT Mean': safe_mean(flow_iats_us),
            'Flow IAT Std': safe_std(flow_iats_us),
            'Flow IAT Max': safe_max(flow_iats_us),
            'Flow IAT Min': safe_min(flow_iats_us) if flow_iats_us else 0,
            'Fwd IAT Total': sum(fwd_iats_us),
            'Fwd IAT Mean': safe_mean(fwd_iats_us),
            'Fwd IAT Std': safe_std(fwd_iats_us),
            'Fwd IAT Max': safe_max(fwd_iats_us),
            'Fwd IAT Min': safe_min(fwd_iats_us) if fwd_iats_us else 0,
            'Bwd IAT Total': sum(bwd_iats_us),
            'Bwd IAT Mean': safe_mean(bwd_iats_us),
            'Bwd IAT Std': safe_std(bwd_iats_us),
            'Bwd IAT Max': safe_max(bwd_iats_us),
            'Bwd IAT Min': safe_min(bwd_iats_us) if bwd_iats_us else 0,
            
            # Flags
            'Fwd PSH Flags': self.psh_count if self.total_fwd_packets > 0 else 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': self.urg_count if self.total_fwd_packets > 0 else 0,
            'Bwd URG Flags': 0,
            'FIN Flag Count': self.fin_count,
            'SYN Flag Count': self.syn_count,
            'RST Flag Count': self.rst_count,
            'PSH Flag Count': self.psh_count,
            'ACK Flag Count': self.ack_count,
            'URG Flag Count': self.urg_count,
            'CWE Flag Count': self.cwe_count,
            'ECE Flag Count': self.ece_count,
            
            # Header lengths
            'Fwd Header Length': self.fwd_header_length,
            'Bwd Header Length': self.bwd_header_length,
            
            # Packet rates
            'Fwd Packets/s': self.total_fwd_packets / (duration / 1_000_000) if duration > 0 else 0,
            'Bwd Packets/s': self.total_bwd_packets / (duration / 1_000_000) if duration > 0 else 0,
            
            # Packet length statistics (all packets)
            'Min Packet Length': safe_min(self.fwd_lengths + self.bwd_lengths) if (self.fwd_lengths or self.bwd_lengths) else 0,
            'Max Packet Length': safe_max(self.fwd_lengths + self.bwd_lengths),
            'Packet Length Mean': safe_mean(self.fwd_lengths + self.bwd_lengths),
            'Packet Length Std': safe_std(self.fwd_lengths + self.bwd_lengths),
            'Packet Length Variance': safe_std(self.fwd_lengths + self.bwd_lengths) ** 2,
            
            # Ratios
            'Down/Up Ratio': self.total_bwd_packets / self.total_fwd_packets if self.total_fwd_packets > 0 else 0,
            'Average Packet Size': total_length / total_packets if total_packets > 0 else 0,
            'Avg Fwd Segment Size': self.total_fwd_length / self.total_fwd_packets if self.total_fwd_packets > 0 else 0,
            'Avg Bwd Segment Size': self.total_bwd_length / self.total_bwd_packets if self.total_bwd_packets > 0 else 0,
            
            # Bulk (simplified - would need more complex tracking)
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            
            # Subflow
            'Subflow Fwd Packets': self.total_fwd_packets,
            'Subflow Fwd Bytes': self.total_fwd_length,
            'Subflow Bwd Packets': self.total_bwd_packets,
            'Subflow Bwd Bytes': self.total_bwd_length,
            
            # Window sizes
            'Init_Win_bytes_forward': self.init_win_fwd,
            'Init_Win_bytes_backward': self.init_win_bwd,
            
            # Active data packets
            'act_data_pkt_fwd': self.total_fwd_packets,
            'min_seg_size_forward': 20,  # Minimum segment size
            
            # Active/Idle
            'Active Mean': safe_mean(active_us),
            'Active Std': safe_std(active_us),
            'Active Max': safe_max(active_us),
            'Active Min': safe_min(active_us) if active_us else 0,
            'Idle Mean': safe_mean(idle_us),
            'Idle Std': safe_std(idle_us),
            'Idle Max': safe_max(idle_us),
            'Idle Min': safe_min(idle_us) if idle_us else 0,
        }
        
        return features


class FlowAggregator:
    """
    Aggregates packets into bidirectional flows and tracks flow statistics.
    Flows are identified by the 5-tuple and expire after a timeout.
    """
    
    def __init__(
        self,
        flow_timeout: float = 120.0,  # seconds
        activity_timeout: float = 5.0,  # seconds of inactivity before flow is "complete"
        on_flow_complete: Optional[Callable[[NetworkFlow], None]] = None
    ):
        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self.on_flow_complete = on_flow_complete
        
        self.flows: Dict[str, NetworkFlow] = {}
        self.completed_flows: List[NetworkFlow] = []
        self.lock = threading.Lock()
        
        # Stats
        self.total_packets = 0
        self.total_bytes = 0
        self.total_flows = 0
        
        # Cleanup thread
        self._running = False
        self._cleanup_thread = None
    
    def _get_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> tuple:
        """Generate bidirectional flow ID (sorted to ensure same flow for both directions)."""
        forward = (src_ip, src_port, dst_ip, dst_port, protocol)
        backward = (dst_ip, dst_port, src_ip, src_port, protocol)
        
        # Always use the "smaller" tuple as the canonical form
        if forward < backward:
            return forward, True  # is_forward = True
        else:
            return backward, False  # is_forward = False
    
    def add_packet(self, packet: PacketInfo) -> Optional[NetworkFlow]:
        """
        Add a packet to the appropriate flow.
        Returns the flow if it was just completed.
        """
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            
            # Get bidirectional flow ID
            flow_key, is_forward = self._get_flow_id(
                packet.src_ip, packet.dst_ip,
                packet.src_port, packet.dst_port,
                packet.protocol
            )
            flow_id = f"{flow_key[0]}:{flow_key[1]}-{flow_key[2]}:{flow_key[3]}-{flow_key[4]}"
            packet.is_forward = is_forward
            
            # Get or create flow
            if flow_id not in self.flows:
                self.flows[flow_id] = NetworkFlow(
                    flow_id=flow_id,
                    src_ip=flow_key[0],
                    dst_ip=flow_key[2],
                    src_port=flow_key[1],
                    dst_port=flow_key[3],
                    protocol=flow_key[4],
                    start_time=packet.timestamp,
                    last_time=packet.timestamp
                )
                self.total_flows += 1
            
            flow = self.flows[flow_id]
            flow.add_packet(packet)
            
            return None
    
    def _cleanup_expired_flows(self):
        """Remove and process flows that have timed out."""
        while self._running:
            time.sleep(1.0)
            
            now = time.time()
            expired = []
            
            with self.lock:
                for flow_id, flow in list(self.flows.items()):
                    # Check for timeout
                    if now - flow.last_time > self.activity_timeout:
                        expired.append(flow_id)
                        
                        # Call callback
                        if self.on_flow_complete:
                            try:
                                self.on_flow_complete(flow)
                            except Exception as e:
                                logger.error(f"Error in flow callback: {e}")
                        
                        self.completed_flows.append(flow)
                
                # Remove expired flows
                for flow_id in expired:
                    del self.flows[flow_id]
                
                # Trim completed flows list
                if len(self.completed_flows) > 1000:
                    self.completed_flows = self.completed_flows[-500:]
    
    def start(self):
        """Start the cleanup thread."""
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_flows, daemon=True)
        self._cleanup_thread.start()
        logger.info("Flow aggregator started")
    
    def stop(self):
        """Stop the cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2.0)
        logger.info("Flow aggregator stopped")
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get list of currently active flows."""
        with self.lock:
            return list(self.flows.values())
    
    def get_stats(self) -> Dict:
        """Get aggregator statistics."""
        with self.lock:
            return {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_flows': self.total_flows,
                'active_flows': len(self.flows),
                'completed_flows': len(self.completed_flows)
            }
