"""
Map detected attacks to MITRE ATT&CK techniques.
"""
from typing import Dict, List, Optional, Any, Tuple
from .attack_db import MITREAttackDB, MITRETechnique
import logging

logger = logging.getLogger(__name__)


class AttackMapper:
    """Map detected attack types to MITRE ATT&CK framework."""
    
    # Mapping from IDS attack labels to MITRE techniques
    ATTACK_TO_MITRE: Dict[str, List[str]] = {
        # DDoS/DoS attacks
        'DDoS': ['T1498', 'T1498.001'],
        'DoS Hulk': ['T1499', 'T1499.002'],
        'DoS GoldenEye': ['T1499', 'T1499.002'],
        'DoS Slowhttptest': ['T1499', 'T1499.002'],
        'DoS slowloris': ['T1499', 'T1499.002'],
        
        # Brute force attacks
        'FTP-Patator': ['T1110', 'T1110.001'],
        'SSH-Patator': ['T1110', 'T1110.001', 'T1021.004'],
        'Web Attack - Brute Force': ['T1110', 'T1110.001'],
        
        # Web attacks
        'Web Attack - SQL Injection': ['T1190'],
        'Web Attack - XSS': ['T1190'],
        
        # Network reconnaissance
        'PortScan': ['T1046', 'T1018'],
        
        # Bot/C2
        'Bot': ['T1071', 'T1071.001'],
        
        # Infiltration
        'Infiltration': ['T1133', 'T1021'],
        
        # Heartbleed (CVE-based)
        'Heartbleed': ['T1190'],
        
        # Unknown anomalies (potential zero-day)
        'Unknown (Anomaly)': ['T1190', 'T1071']
    }
    
    def __init__(self):
        """Initialize the attack mapper."""
        self.db = MITREAttackDB()
    
    def map_attack(self, attack_type: str) -> Dict[str, Any]:
        """
        Map an attack type to MITRE ATT&CK techniques.
        
        Args:
            attack_type: Detected attack label
        
        Returns:
            Dictionary with MITRE mapping information
        """
        if attack_type == 'BENIGN':
            return {
                'attack_type': attack_type,
                'is_mapped': False,
                'techniques': [],
                'primary_technique': None,
                'tactics': []
            }
        
        technique_ids = self.ATTACK_TO_MITRE.get(attack_type, [])
        
        if not technique_ids:
            logger.warning(f"No MITRE mapping found for attack type: {attack_type}")
            return {
                'attack_type': attack_type,
                'is_mapped': False,
                'techniques': [],
                'primary_technique': None,
                'tactics': []
            }
        
        techniques = []
        tactics = set()
        
        for tid in technique_ids:
            technique = self.db.get_technique(tid)
            if technique:
                techniques.append({
                    'technique_id': technique.technique_id,
                    'name': technique.name,
                    'tactic': technique.tactic,
                    'tactic_id': technique.tactic_id,
                    'description': technique.description,
                    'detection': technique.detection,
                    'mitigations': technique.mitigations,
                    'url': technique.url
                })
                tactics.add(technique.tactic)
        
        primary = techniques[0] if techniques else None
        
        return {
            'attack_type': attack_type,
            'is_mapped': len(techniques) > 0,
            'techniques': techniques,
            'primary_technique': primary,
            'tactics': list(tactics),
            'technique_ids': technique_ids
        }
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., 'T1190')
        
        Returns:
            Technique details dictionary
        """
        technique = self.db.get_technique(technique_id)
        if not technique:
            return None
        
        return {
            'technique_id': technique.technique_id,
            'name': technique.name,
            'tactic': technique.tactic,
            'tactic_id': technique.tactic_id,
            'description': technique.description,
            'detection': technique.detection,
            'mitigations': technique.mitigations,
            'url': technique.url,
            'platforms': technique.platforms,
            'data_sources': technique.data_sources
        }
    
    def get_all_mappings(self) -> Dict[str, List[str]]:
        """Get all attack type to MITRE technique mappings."""
        return self.ATTACK_TO_MITRE.copy()
    
    def get_attack_chain(self, attack_types: List[str]) -> Dict[str, Any]:
        """
        Analyze a sequence of attacks to identify potential attack chain.
        
        Args:
            attack_types: List of detected attack types in order
        
        Returns:
            Attack chain analysis
        """
        if not attack_types:
            return {'chain_detected': False, 'stages': []}
        
        # Map tactics to kill chain stages
        KILL_CHAIN_ORDER = [
            'TA0043',  # Reconnaissance
            'TA0001',  # Initial Access
            'TA0002',  # Execution
            'TA0003',  # Persistence
            'TA0004',  # Privilege Escalation
            'TA0005',  # Defense Evasion
            'TA0006',  # Credential Access
            'TA0007',  # Discovery
            'TA0008',  # Lateral Movement
            'TA0009',  # Collection
            'TA0010',  # Exfiltration
            'TA0011',  # Command and Control
            'TA0040'   # Impact
        ]
        
        stages = []
        tactics_seen = set()
        
        for attack_type in attack_types:
            if attack_type == 'BENIGN':
                continue
            
            mapping = self.map_attack(attack_type)
            if mapping['is_mapped']:
                for technique in mapping['techniques']:
                    tactic_id = technique['tactic_id']
                    if tactic_id not in tactics_seen:
                        tactics_seen.add(tactic_id)
                        stages.append({
                            'tactic_id': tactic_id,
                            'tactic': technique['tactic'],
                            'attack_type': attack_type,
                            'technique': technique['name'],
                            'technique_id': technique['technique_id']
                        })
        
        # Sort by kill chain order
        stages.sort(key=lambda x: KILL_CHAIN_ORDER.index(x['tactic_id']) 
                    if x['tactic_id'] in KILL_CHAIN_ORDER else 99)
        
        # Determine if this looks like a coordinated attack chain
        is_chain = len(stages) > 1 and len(tactics_seen) > 1
        
        return {
            'chain_detected': is_chain,
            'stages': stages,
            'tactics_covered': len(tactics_seen),
            'risk_assessment': self._assess_chain_risk(stages, tactics_seen)
        }
    
    def _assess_chain_risk(
        self, 
        stages: List[Dict], 
        tactics_seen: set
    ) -> Dict[str, Any]:
        """Assess the risk level of an attack chain."""
        HIGH_RISK_TACTICS = {'TA0010', 'TA0040', 'TA0008'}  # Exfiltration, Impact, Lateral Movement
        CRITICAL_TACTICS = {'TA0010', 'TA0040'}
        
        risk_level = 'Low'
        factors = []
        
        if len(stages) >= 3:
            risk_level = 'Medium'
            factors.append('Multiple attack stages detected')
        
        if tactics_seen & HIGH_RISK_TACTICS:
            risk_level = 'High'
            factors.append('High-risk tactics observed')
        
        if tactics_seen & CRITICAL_TACTICS:
            risk_level = 'Critical'
            factors.append('Critical impact tactics detected')
        
        # Check for complete kill chain progression
        if 'TA0001' in tactics_seen and 'TA0007' in tactics_seen:
            factors.append('Initial access followed by discovery - possible active intrusion')
        
        if 'TA0006' in tactics_seen and 'TA0008' in tactics_seen:
            factors.append('Credential theft and lateral movement - high compromise risk')
        
        return {
            'level': risk_level,
            'factors': factors,
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            'Low': 'Continue monitoring. Review alerts for false positives.',
            'Medium': 'Investigate affected systems. Increase logging and monitoring.',
            'High': 'Initiate incident response. Isolate affected systems if possible.',
            'Critical': 'IMMEDIATE ACTION REQUIRED. Execute incident response plan. Consider network isolation.'
        }
        return recommendations.get(risk_level, 'Monitor and investigate.')
    
    def get_matrix_for_attacks(self, attack_types: List[str]) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK matrix data highlighting techniques from detected attacks.
        
        Args:
            attack_types: List of detected attack types
        
        Returns:
            Matrix data with highlighted techniques
        """
        # Get base matrix
        matrix = self.db.get_matrix_data()
        
        # Get all technique IDs from detected attacks
        detected_technique_ids = set()
        for attack_type in attack_types:
            if attack_type != 'BENIGN':
                technique_ids = self.ATTACK_TO_MITRE.get(attack_type, [])
                detected_technique_ids.update(technique_ids)
        
        # Mark detected techniques
        for tactic_id, tactic_data in matrix.items():
            for technique in tactic_data['techniques']:
                technique['detected'] = technique['id'] in detected_technique_ids
        
        return {
            'matrix': matrix,
            'detected_techniques': list(detected_technique_ids),
            'detection_count': len(detected_technique_ids)
        }
