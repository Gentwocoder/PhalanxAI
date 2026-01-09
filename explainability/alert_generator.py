"""
Human-readable alert generation from ML predictions.
"""
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class AlertGenerator:
    """Generate human-readable security alerts from ML predictions."""
    
    # Attack type descriptions
    ATTACK_DESCRIPTIONS = {
        'BENIGN': 'Normal network traffic with no malicious indicators detected.',
        'DDoS': 'Distributed Denial of Service attack detected. Multiple sources are flooding the network with traffic to overwhelm services.',
        'DoS Hulk': 'DoS Hulk attack detected. This attack generates unique, obfuscated traffic to bypass caching engines.',
        'DoS GoldenEye': 'DoS GoldenEye attack detected. HTTP-based DoS using Keep-Alive connections with incomplete HTTP requests.',
        'DoS Slowhttptest': 'Slow HTTP attack detected. Attacker is sending partial HTTP requests slowly to exhaust server connections.',
        'DoS slowloris': 'Slowloris attack detected. Attacker is maintaining many connections to the server with partial requests.',
        'PortScan': 'Port scanning activity detected. An attacker is probing for open ports and vulnerable services.',
        'FTP-Patator': 'FTP brute force attack detected. Multiple login attempts against FTP service.',
        'SSH-Patator': 'SSH brute force attack detected. Multiple login attempts against SSH service.',
        'Bot': 'Bot activity detected. Traffic patterns indicate automated malicious behavior.',
        'Infiltration': 'Network infiltration attempt detected. Attacker may have gained initial access.',
        'Heartbleed': 'Heartbleed exploit attempt detected. Attacker trying to extract sensitive data from memory.',
        'Web Attack - Brute Force': 'Web application brute force attack detected. Multiple authentication attempts.',
        'Web Attack - SQL Injection': 'SQL Injection attack detected. Attacker attempting to inject malicious SQL commands.',
        'Web Attack - XSS': 'Cross-Site Scripting (XSS) attack detected. Attacker injecting malicious scripts.',
        'Unknown (Anomaly)': 'Anomalous traffic detected that does not match known patterns. May indicate zero-day attack.'
    }
    
    # Severity thresholds
    SEVERITY_CONFIG = {
        'Critical': {'min_confidence': 0.9, 'color': '#dc2626'},
        'High': {'min_confidence': 0.7, 'color': '#ea580c'},
        'Medium': {'min_confidence': 0.5, 'color': '#ca8a04'},
        'Low': {'min_confidence': 0.0, 'color': '#16a34a'}
    }
    
    # Recommended actions by attack type
    RECOMMENDED_ACTIONS = {
        'DDoS': [
            'Enable rate limiting on affected services',
            'Contact upstream provider for DDoS mitigation',
            'Block source IP ranges at firewall level',
            'Consider enabling CDN or DDoS protection service'
        ],
        'DoS Hulk': [
            'Implement rate limiting',
            'Enable connection limits per IP',
            'Add the attacking IPs to blocklist'
        ],
        'DoS GoldenEye': [
            'Set timeouts for incomplete HTTP requests',
            'Limit concurrent connections per IP',
            'Enable mod_reqtimeout if using Apache'
        ],
        'DoS Slowhttptest': [
            'Configure minimum data rate for requests',
            'Set aggressive timeouts for slow connections',
            'Use a reverse proxy with proper timeout settings'
        ],
        'DoS slowloris': [
            'Increase the maximum number of clients',
            'Limit connections per IP address',
            'Set request timeouts',
            'Use a reverse proxy like Nginx'
        ],
        'PortScan': [
            'Review firewall rules and close unnecessary ports',
            'Enable port scan detection and automatic blocking',
            'Monitor for follow-up exploitation attempts',
            'Consider implementing port knocking'
        ],
        'FTP-Patator': [
            'Enable account lockout after failed attempts',
            'Implement CAPTCHA for FTP login',
            'Consider disabling FTP in favor of SFTP',
            'Block source IP after threshold exceeded'
        ],
        'SSH-Patator': [
            'Enable fail2ban or similar intrusion prevention',
            'Use SSH key authentication only',
            'Change SSH port from default 22',
            'Implement IP whitelisting for SSH access'
        ],
        'Bot': [
            'Analyze traffic patterns for C&C communication',
            'Isolate affected systems for investigation',
            'Run malware scans on internal hosts',
            'Block known bot C&C domains'
        ],
        'Infiltration': [
            'Isolate affected systems immediately',
            'Initiate incident response procedures',
            'Preserve logs for forensic analysis',
            'Scan for lateral movement indicators'
        ],
        'Heartbleed': [
            'Patch OpenSSL immediately',
            'Revoke and reissue SSL certificates',
            'Reset all potentially affected passwords',
            'Review logs for data exfiltration'
        ],
        'Web Attack - Brute Force': [
            'Enable account lockout policies',
            'Implement CAPTCHA after failed attempts',
            'Use multi-factor authentication',
            'Rate limit login endpoints'
        ],
        'Web Attack - SQL Injection': [
            'Use parameterized queries immediately',
            'Enable Web Application Firewall (WAF)',
            'Review and sanitize all user inputs',
            'Audit database for unauthorized access'
        ],
        'Web Attack - XSS': [
            'Implement Content Security Policy (CSP)',
            'Sanitize and encode all user outputs',
            'Enable HTTPOnly and Secure flags on cookies',
            'Review templates for unsafe rendering'
        ],
        'Unknown (Anomaly)': [
            'Capture traffic for detailed analysis',
            'Compare with baseline normal behavior',
            'Investigate affected systems',
            'Consider engaging threat intelligence services'
        ]
    }
    
    def __init__(self):
        """Initialize alert generator."""
        pass
    
    def generate_alert(
        self,
        prediction: Dict[str, Any],
        features: Optional[Dict[str, float]] = None,
        explanation: Optional[Dict[str, Any]] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        mitre_mapping: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security alert.
        
        Args:
            prediction: Model prediction dictionary
            features: Raw feature values
            explanation: SHAP/LIME explanation
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            mitre_mapping: MITRE ATT&CK mapping
        
        Returns:
            Complete alert dictionary
        """
        attack_type = prediction.get('attack_type', 'Unknown')
        confidence = prediction.get('confidence', 0.0)
        is_malicious = prediction.get('is_malicious', False)
        severity = prediction.get('severity', 'Low')
        
        # Generate description
        description = self.ATTACK_DESCRIPTIONS.get(
            attack_type,
            f'Suspicious activity detected: {attack_type}'
        )
        
        # Generate human-readable summary
        summary = self._generate_summary(
            attack_type, confidence, severity, src_ip, dst_ip, dst_port
        )
        
        # Get recommended actions
        actions = self.RECOMMENDED_ACTIONS.get(
            attack_type,
            ['Investigate the traffic pattern', 'Monitor for similar activity']
        )
        
        # Build explanation text
        explanation_text = ""
        if explanation:
            explanation_text = self._format_explanation(explanation)
        
        alert = {
            'id': None,  # Will be set by database
            'timestamp': datetime.utcnow().isoformat(),
            'attack_type': attack_type,
            'severity': severity,
            'severity_color': self.SEVERITY_CONFIG.get(severity, {}).get('color', '#gray'),
            'confidence': confidence,
            'is_malicious': is_malicious,
            
            # Network info
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            
            # Human-readable content
            'summary': summary,
            'description': description,
            'explanation': explanation_text,
            'recommended_actions': actions,
            
            # Technical details
            'top_features': explanation.get('top_features', {}) if explanation else {},
            'detection_sources': prediction.get('detection_sources', []),
            'anomaly_detected': prediction.get('anomaly_detected', False),
            
            # MITRE ATT&CK
            'mitre': mitre_mapping,
            
            # Status
            'status': 'new',
            'raw_features': features
        }
        
        return alert
    
    def _generate_summary(
        self,
        attack_type: str,
        confidence: float,
        severity: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        dst_port: Optional[int]
    ) -> str:
        """Generate a brief summary of the alert."""
        source = src_ip or "Unknown source"
        target = dst_ip or "internal system"
        port_info = f" on port {dst_port}" if dst_port else ""
        
        if attack_type == 'BENIGN':
            return f"Normal traffic from {source} to {target}{port_info}."
        
        return (
            f"{severity} severity {attack_type} detected from {source} "
            f"targeting {target}{port_info}. "
            f"Detection confidence: {confidence:.1%}."
        )
    
    def _format_explanation(self, explanation: Dict[str, Any]) -> str:
        """Format ML explanation into readable text."""
        text = "Detection Analysis:\n"
        
        if 'top_features' in explanation:
            text += "\nKey indicators that triggered this alert:\n"
            for i, (feature, info) in enumerate(explanation['top_features'].items()):
                if i >= 5:
                    break
                
                if isinstance(info, dict):
                    value = info.get('feature_value', info.get('shap_value', 'N/A'))
                    contribution = info.get('contribution', 'unknown')
                    text += f"  • {feature}: {value} ({contribution} contribution)\n"
                else:
                    text += f"  • {feature}: {info}\n"
        
        return text
    
    def generate_batch_alerts(
        self,
        predictions: List[Dict[str, Any]],
        features_list: Optional[List[Dict[str, float]]] = None,
        explanations: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """Generate multiple alerts efficiently."""
        alerts = []
        
        for i, prediction in enumerate(predictions):
            features = features_list[i] if features_list else None
            explanation = explanations[i] if explanations else None
            
            alert = self.generate_alert(
                prediction=prediction,
                features=features,
                explanation=explanation
            )
            alerts.append(alert)
        
        return alerts
    
    def format_alert_for_dashboard(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert for dashboard display."""
        return {
            'id': alert.get('id'),
            'time': alert.get('timestamp'),
            'type': alert.get('attack_type'),
            'severity': alert.get('severity'),
            'color': alert.get('severity_color'),
            'source': alert.get('src_ip', 'N/A'),
            'destination': f"{alert.get('dst_ip', 'N/A')}:{alert.get('dst_port', '')}",
            'confidence': f"{alert.get('confidence', 0) * 100:.0f}%",
            'status': alert.get('status'),
            'summary': alert.get('summary'),
            'mitre_id': alert.get('mitre', {}).get('technique_id', '') if alert.get('mitre') else ''
        }
