"""
Packet Capture Module: Real-time network packet capture using scapy.
Requires root/admin privileges to capture packets.
"""
import threading
import queue
import time
import logging
from typing import Optional, Callable, List
from dataclasses import dataclass

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")

from .flow_aggregator import PacketInfo, FlowAggregator, NetworkFlow

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Real-time packet capture and analysis.
    Captures packets from a network interface, aggregates them into flows,
    and calls a callback for each completed flow.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
        on_flow: Optional[Callable[[NetworkFlow], None]] = None,
        bpf_filter: str = "ip",  # Berkeley Packet Filter
        flow_timeout: float = 5.0,  # Faster timeout for real-time detection
    ):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface to capture from (e.g., 'eth0', 'wlan0')
                      If None, will try to auto-detect
            on_packet: Callback for each captured packet
            on_flow: Callback for each completed flow (for ML analysis)
            bpf_filter: BPF filter expression (default: all IP packets)
            flow_timeout: Seconds of inactivity before a flow is considered complete
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for packet capture. Install with: pip install scapy")
        
        self.interface = interface or self._get_default_interface()
        self.on_packet = on_packet
        self.on_flow = on_flow
        self.bpf_filter = bpf_filter
        
        # Flow aggregation
        self.flow_aggregator = FlowAggregator(
            flow_timeout=flow_timeout,
            activity_timeout=flow_timeout,
            on_flow_complete=self._handle_flow_complete
        )
        
        # Capture thread
        self._running = False
        self._capture_thread = None
        self._packet_queue = queue.Queue(maxsize=10000)
        self._process_thread = None
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None,
            'last_packet_time': None
        }
    
    def _get_default_interface(self) -> str:
        """Get default network interface."""
        try:
            interfaces = get_if_list()
            # Prefer common names
            preferred = ['eth0', 'en0', 'ens33', 'enp0s3', 'wlan0', 'wlp2s0']
            for pref in preferred:
                if pref in interfaces:
                    return pref
            
            # Filter out loopback and virtual
            real_interfaces = [i for i in interfaces if not i.startswith(('lo', 'docker', 'veth', 'br-'))]
            if real_interfaces:
                return real_interfaces[0]
            
            return conf.iface  # Scapy default
        except Exception as e:
            logger.warning(f"Could not detect interface: {e}")
            return 'eth0'
    
    def _handle_flow_complete(self, flow: NetworkFlow):
        """Called when a flow is completed (timed out)."""
        if self.on_flow:
            try:
                self.on_flow(flow)
            except Exception as e:
                logger.error(f"Error in flow callback: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from a scapy packet."""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip = packet[IP]
            
            # Determine protocol and ports
            src_port = 0
            dst_port = 0
            protocol = ip.proto
            flags = {}
            payload_len = 0
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = 6
                # Extract TCP flags
                flags = {
                    'SYN': bool(tcp.flags & 0x02),
                    'FIN': bool(tcp.flags & 0x01),
                    'RST': bool(tcp.flags & 0x04),
                    'PSH': bool(tcp.flags & 0x08),
                    'ACK': bool(tcp.flags & 0x10),
                    'URG': bool(tcp.flags & 0x20),
                    'ECE': bool(tcp.flags & 0x40),
                    'CWR': bool(tcp.flags & 0x80)
                }
                if packet.haslayer(Raw):
                    payload_len = len(packet[Raw].load)
                    
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = 17
                if packet.haslayer(Raw):
                    payload_len = len(packet[Raw].load)
                    
            elif packet.haslayer(ICMP):
                protocol = 1
            
            return PacketInfo(
                timestamp=float(packet.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(packet),
                payload_length=payload_len,
                flags=flags
            )
            
        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None
    
    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        try:
            self._packet_queue.put_nowait(packet)
            self.stats['packets_captured'] += 1
        except queue.Full:
            self.stats['packets_dropped'] += 1
    
    def _process_packets(self):
        """Process packets from the queue."""
        while self._running:
            try:
                packet = self._packet_queue.get(timeout=0.5)
                
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    self.stats['packets_processed'] += 1
                    self.stats['bytes_captured'] += packet_info.length
                    self.stats['last_packet_time'] = time.time()
                    
                    # Add to flow aggregator
                    self.flow_aggregator.add_packet(packet_info)
                    
                    # Call packet callback
                    if self.on_packet:
                        self.on_packet(packet_info)
                        
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def _capture_loop(self):
        """Main capture loop running in a thread."""
        logger.info(f"Starting packet capture on interface: {self.interface}")
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda x: not self._running
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            if "permission" in str(e).lower() or "permitted" in str(e).lower():
                logger.error("Root/admin privileges required for packet capture!")
    
    def start(self):
        """Start packet capture."""
        if self._running:
            logger.warning("Capture already running")
            return
        
        self._running = True
        self.stats['start_time'] = time.time()
        
        # Start flow aggregator
        self.flow_aggregator.start()
        
        # Start packet processing thread
        self._process_thread = threading.Thread(target=self._process_packets, daemon=True)
        self._process_thread.start()
        
        # Start capture thread
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        
        logger.info(f"Packet capture started on {self.interface}")
    
    def stop(self):
        """Stop packet capture."""
        self._running = False
        
        # Stop capture thread
        if self._capture_thread:
            self._capture_thread.join(timeout=2.0)
        
        # Stop processing thread
        if self._process_thread:
            self._process_thread.join(timeout=2.0)
        
        # Stop flow aggregator
        self.flow_aggregator.stop()
        
        logger.info("Packet capture stopped")
    
    def get_stats(self) -> dict:
        """Get capture statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        flow_stats = self.flow_aggregator.get_stats()
        
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'packets_per_second': self.stats['packets_captured'] / uptime if uptime > 0 else 0,
            'bytes_per_second': self.stats['bytes_captured'] / uptime if uptime > 0 else 0,
            'queue_size': self._packet_queue.qsize(),
            **flow_stats
        }
    
    @staticmethod
    def list_interfaces() -> List[str]:
        """List available network interfaces."""
        if not SCAPY_AVAILABLE:
            return []
        return get_if_list()
    
    @property
    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running


# Convenience function for quick testing
def capture_and_print(interface: str = None, count: int = 100):
    """Quick test function to capture and print packets."""
    captured = []
    
    def on_packet(pkt):
        print(f"[{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}] {pkt.length} bytes")
        captured.append(pkt)
    
    def on_flow(flow):
        features = flow.to_feature_dict()
        print(f"\n=== Flow Complete ===")
        print(f"  {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port}")
        print(f"  Packets: {flow.total_fwd_packets + flow.total_bwd_packets}")
        print(f"  Duration: {features['Flow Duration']/1000000:.2f}s")
    
    cap = PacketCapture(interface=interface, on_packet=on_packet, on_flow=on_flow)
    
    print(f"Available interfaces: {cap.list_interfaces()}")
    print(f"Capturing on: {cap.interface}")
    print(f"Capturing {count} packets... (Ctrl+C to stop)\n")
    
    cap.start()
    
    try:
        while len(captured) < count:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    
    cap.stop()
    print(f"\nCaptured {len(captured)} packets")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    capture_and_print()
