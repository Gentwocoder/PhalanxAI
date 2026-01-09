"""
MITRE ATT&CK techniques database.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique representation."""
    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    detection: str
    mitigations: List[str]
    url: str
    platforms: List[str]
    data_sources: List[str]


class MITREAttackDB:
    """Database of MITRE ATT&CK techniques relevant to network intrusion detection."""
    
    # Main tactics in ATT&CK framework
    TACTICS = {
        'TA0001': {'name': 'Initial Access', 'description': 'Techniques for gaining initial foothold'},
        'TA0002': {'name': 'Execution', 'description': 'Techniques for running malicious code'},
        'TA0003': {'name': 'Persistence', 'description': 'Techniques for maintaining access'},
        'TA0004': {'name': 'Privilege Escalation', 'description': 'Techniques for gaining higher permissions'},
        'TA0005': {'name': 'Defense Evasion', 'description': 'Techniques for avoiding detection'},
        'TA0006': {'name': 'Credential Access', 'description': 'Techniques for stealing credentials'},
        'TA0007': {'name': 'Discovery', 'description': 'Techniques for learning about the environment'},
        'TA0008': {'name': 'Lateral Movement', 'description': 'Techniques for moving through the network'},
        'TA0009': {'name': 'Collection', 'description': 'Techniques for gathering target data'},
        'TA0010': {'name': 'Exfiltration', 'description': 'Techniques for stealing data'},
        'TA0011': {'name': 'Command and Control', 'description': 'Techniques for communicating with compromised systems'},
        'TA0040': {'name': 'Impact', 'description': 'Techniques for disrupting availability or integrity'},
        'TA0043': {'name': 'Reconnaissance', 'description': 'Techniques for gathering information to plan attacks'}
    }
    
    # Network-relevant techniques
    TECHNIQUES: Dict[str, MITRETechnique] = {}
    
    def __init__(self):
        """Initialize the MITRE ATT&CK database."""
        self._populate_techniques()
    
    def _populate_techniques(self):
        """Populate the techniques database."""
        techniques_data = [
            # Initial Access
            {
                'technique_id': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'tactic_id': 'TA0001',
                'description': 'Adversaries may exploit vulnerabilities in internet-facing applications to gain initial access.',
                'detection': 'Monitor application logs for abnormal behavior, unexpected commands, or SQL/command injection attempts.',
                'mitigations': [
                    'Application Isolation and Sandboxing',
                    'Exploit Protection',
                    'Network Segmentation',
                    'Privileged Account Management',
                    'Update Software',
                    'Vulnerability Scanning'
                ],
                'url': 'https://attack.mitre.org/techniques/T1190',
                'platforms': ['Windows', 'Linux', 'macOS', 'Containers'],
                'data_sources': ['Application Log', 'Network Traffic']
            },
            {
                'technique_id': 'T1133',
                'name': 'External Remote Services',
                'tactic': 'Initial Access',
                'tactic_id': 'TA0001',
                'description': 'Adversaries may leverage external-facing remote services to gain access to a network.',
                'detection': 'Monitor for unusual external connections to remote services like RDP, VPN, SSH.',
                'mitigations': [
                    'Disable or Remove Feature or Program',
                    'Limit Access to Resource Over Network',
                    'Multi-factor Authentication',
                    'Network Segmentation'
                ],
                'url': 'https://attack.mitre.org/techniques/T1133',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Authentication Logs', 'Network Traffic']
            },
            # Credential Access
            {
                'technique_id': 'T1110',
                'name': 'Brute Force',
                'tactic': 'Credential Access',
                'tactic_id': 'TA0006',
                'description': 'Adversaries may use brute force techniques to guess credentials and gain access.',
                'detection': 'Monitor authentication logs for many failed login attempts followed by success.',
                'mitigations': [
                    'Account Lockout Policies',
                    'Multi-factor Authentication',
                    'Password Policies'
                ],
                'url': 'https://attack.mitre.org/techniques/T1110',
                'platforms': ['Windows', 'Linux', 'macOS', 'Containers', 'SaaS'],
                'data_sources': ['Authentication Logs', 'User Account']
            },
            {
                'technique_id': 'T1110.001',
                'name': 'Password Guessing',
                'tactic': 'Credential Access',
                'tactic_id': 'TA0006',
                'description': 'Adversaries may guess passwords to attempt access when password hashes are not available.',
                'detection': 'Monitor for many failed authentication attempts across various accounts.',
                'mitigations': [
                    'Account Lockout Policies',
                    'Multi-factor Authentication',
                    'Password Policies'
                ],
                'url': 'https://attack.mitre.org/techniques/T1110/001',
                'platforms': ['Windows', 'Linux', 'macOS', 'SaaS'],
                'data_sources': ['Authentication Logs']
            },
            # Discovery
            {
                'technique_id': 'T1046',
                'name': 'Network Service Discovery',
                'tactic': 'Discovery',
                'tactic_id': 'TA0007',
                'description': 'Adversaries may scan for services running on remote hosts to identify potential targets.',
                'detection': 'Monitor network traffic for port scans and service enumeration activities.',
                'mitigations': [
                    'Disable or Remove Feature or Program',
                    'Network Intrusion Prevention',
                    'Network Segmentation'
                ],
                'url': 'https://attack.mitre.org/techniques/T1046',
                'platforms': ['Windows', 'Linux', 'macOS', 'Containers'],
                'data_sources': ['Network Traffic', 'Process']
            },
            {
                'technique_id': 'T1018',
                'name': 'Remote System Discovery',
                'tactic': 'Discovery',
                'tactic_id': 'TA0007',
                'description': 'Adversaries may attempt to gather information about remote systems on the network.',
                'detection': 'Monitor for commands and network traffic associated with remote system discovery.',
                'mitigations': [
                    'Network Segmentation',
                    'Operating System Configuration'
                ],
                'url': 'https://attack.mitre.org/techniques/T1018',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Command', 'Network Traffic', 'Process']
            },
            # Command and Control
            {
                'technique_id': 'T1071',
                'name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Adversaries may use application layer protocols for C2 communication to avoid detection.',
                'detection': 'Analyze network data for uncommon data flows or unusual protocol usage.',
                'mitigations': [
                    'Network Intrusion Prevention',
                    'Filter Network Traffic'
                ],
                'url': 'https://attack.mitre.org/techniques/T1071',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Network Traffic']
            },
            {
                'technique_id': 'T1071.001',
                'name': 'Web Protocols',
                'tactic': 'Command and Control',
                'tactic_id': 'TA0011',
                'description': 'Adversaries may use HTTP/HTTPS for C2 communication to blend with normal traffic.',
                'detection': 'Monitor for HTTP/HTTPS traffic to suspicious domains or with unusual patterns.',
                'mitigations': [
                    'Network Intrusion Prevention',
                    'SSL/TLS Inspection'
                ],
                'url': 'https://attack.mitre.org/techniques/T1071/001',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Network Traffic']
            },
            # Impact
            {
                'technique_id': 'T1498',
                'name': 'Network Denial of Service',
                'tactic': 'Impact',
                'tactic_id': 'TA0040',
                'description': 'Adversaries may perform DoS attacks to degrade or block availability of targeted resources.',
                'detection': 'Monitor network traffic for unusual volumes from single sources or to single destinations.',
                'mitigations': [
                    'Filter Network Traffic',
                    'Network Intrusion Prevention'
                ],
                'url': 'https://attack.mitre.org/techniques/T1498',
                'platforms': ['Windows', 'Linux', 'macOS', 'Containers', 'IaaS'],
                'data_sources': ['Network Traffic', 'Sensor Health']
            },
            {
                'technique_id': 'T1498.001',
                'name': 'Direct Network Flood',
                'tactic': 'Impact',
                'tactic_id': 'TA0040',
                'description': 'Adversaries may send high volume of network traffic directly to a target.',
                'detection': 'Monitor for sudden spikes in network traffic volume.',
                'mitigations': [
                    'Filter Network Traffic',
                    'Network Intrusion Prevention'
                ],
                'url': 'https://attack.mitre.org/techniques/T1498/001',
                'platforms': ['Windows', 'Linux', 'macOS', 'IaaS'],
                'data_sources': ['Network Traffic', 'Sensor Health']
            },
            {
                'technique_id': 'T1499',
                'name': 'Endpoint Denial of Service',
                'tactic': 'Impact',
                'tactic_id': 'TA0040',
                'description': 'Adversaries may perform endpoint DoS attacks to degrade or block service availability.',
                'detection': 'Monitor for unusual patterns of service requests or resource exhaustion.',
                'mitigations': [
                    'Filter Network Traffic',
                    'Network Intrusion Prevention'
                ],
                'url': 'https://attack.mitre.org/techniques/T1499',
                'platforms': ['Windows', 'Linux', 'macOS', 'Containers', 'IaaS'],
                'data_sources': ['Application Log', 'Network Traffic', 'Sensor Health']
            },
            {
                'technique_id': 'T1499.002',
                'name': 'Service Exhaustion Flood',
                'tactic': 'Impact',
                'tactic_id': 'TA0040',
                'description': 'Adversaries may flood services with requests to exhaust resources.',
                'detection': 'Monitor for high volumes of requests to specific services.',
                'mitigations': [
                    'Filter Network Traffic',
                    'Network Intrusion Prevention'
                ],
                'url': 'https://attack.mitre.org/techniques/T1499/002',
                'platforms': ['Windows', 'Linux', 'macOS', 'IaaS'],
                'data_sources': ['Application Log', 'Network Traffic']
            },
            # Exfiltration
            {
                'technique_id': 'T1041',
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'tactic_id': 'TA0010',
                'description': 'Adversaries may steal data by exfiltrating it over an existing C2 channel.',
                'detection': 'Monitor for large amounts of data leaving the network over C2 channels.',
                'mitigations': [
                    'Data Loss Prevention',
                    'Network Intrusion Prevention'
                ],
                'url': 'https://attack.mitre.org/techniques/T1041',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Command', 'File', 'Network Traffic']
            },
            # Lateral Movement
            {
                'technique_id': 'T1021',
                'name': 'Remote Services',
                'tactic': 'Lateral Movement',
                'tactic_id': 'TA0008',
                'description': 'Adversaries may use remote services to move laterally within a network.',
                'detection': 'Monitor for remote service connections, especially from unusual sources.',
                'mitigations': [
                    'Disable or Remove Feature or Program',
                    'Limit Access to Resource Over Network',
                    'Multi-factor Authentication',
                    'Network Segmentation',
                    'Privileged Account Management'
                ],
                'url': 'https://attack.mitre.org/techniques/T1021',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'data_sources': ['Authentication Logs', 'Network Traffic', 'Process']
            },
            {
                'technique_id': 'T1021.001',
                'name': 'Remote Desktop Protocol',
                'tactic': 'Lateral Movement',
                'tactic_id': 'TA0008',
                'description': 'Adversaries may use RDP to move laterally to other systems.',
                'detection': 'Monitor for RDP connections from unusual sources or at unusual times.',
                'mitigations': [
                    'Disable or Remove Feature or Program',
                    'Limit Access to Resource Over Network',
                    'Multi-factor Authentication',
                    'Network Segmentation',
                    'Privileged Account Management'
                ],
                'url': 'https://attack.mitre.org/techniques/T1021/001',
                'platforms': ['Windows'],
                'data_sources': ['Authentication Logs', 'Network Traffic', 'Process']
            },
            {
                'technique_id': 'T1021.004',
                'name': 'SSH',
                'tactic': 'Lateral Movement',
                'tactic_id': 'TA0008',
                'description': 'Adversaries may use SSH to move laterally to other systems.',
                'detection': 'Monitor for SSH connections from unusual sources or failed authentication attempts.',
                'mitigations': [
                    'Disable or Remove Feature or Program',
                    'Limit Access to Resource Over Network',
                    'Multi-factor Authentication',
                    'Network Segmentation'
                ],
                'url': 'https://attack.mitre.org/techniques/T1021/004',
                'platforms': ['Linux', 'macOS'],
                'data_sources': ['Authentication Logs', 'Network Traffic', 'Process']
            }
        ]
        
        for data in techniques_data:
            technique = MITRETechnique(**data)
            self.TECHNIQUES[technique.technique_id] = technique
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get a specific technique by ID."""
        return self.TECHNIQUES.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic_id: str) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic."""
        return [t for t in self.TECHNIQUES.values() if t.tactic_id == tactic_id]
    
    def get_all_techniques(self) -> Dict[str, MITRETechnique]:
        """Get all techniques."""
        return self.TECHNIQUES
    
    def get_all_tactics(self) -> Dict[str, Dict]:
        """Get all tactics."""
        return self.TACTICS
    
    def search_techniques(self, query: str) -> List[MITRETechnique]:
        """Search techniques by name or description."""
        query = query.lower()
        results = []
        for technique in self.TECHNIQUES.values():
            if (query in technique.name.lower() or 
                query in technique.description.lower()):
                results.append(technique)
        return results
    
    def get_matrix_data(self) -> Dict[str, Any]:
        """Get data formatted for ATT&CK matrix visualization."""
        matrix = {}
        for tactic_id, tactic_info in self.TACTICS.items():
            techniques = self.get_techniques_by_tactic(tactic_id)
            matrix[tactic_id] = {
                'name': tactic_info['name'],
                'description': tactic_info['description'],
                'techniques': [
                    {
                        'id': t.technique_id,
                        'name': t.name,
                        'url': t.url
                    }
                    for t in techniques
                ]
            }
        return matrix
