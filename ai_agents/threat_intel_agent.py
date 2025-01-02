"""Threat intelligence agent for security monitoring."""

from .base_agent import BaseAgent
from typing import Dict, Any, List
import requests
import json
from datetime import datetime, timedelta

class ThreatIntelAgent(BaseAgent):
    def __init__(self, api_keys: Dict[str, str]):
        super().__init__(
            name="ThreatIntel",
            role="Threat Intelligence Analyst",
            goal="Monitor and analyze threat intelligence feeds for relevant security threats"
        )
        self.api_keys = api_keys
        self.intel_sources = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/blacklist',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
            # Add more threat intel sources as needed
        }
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address against threat intelligence sources."""
        results = {}
        
        # Check AbuseIPDB
        if 'abuseipdb' in self.api_keys:
            try:
                headers = {
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json',
                }
                response = requests.get(
                    f"{self.intel_sources['abuseipdb']}/check",
                    headers=headers,
                    params={'ipAddress': ip_address}
                )
                if response.status_code == 200:
                    data = response.json()
                    if data['data']['abuseConfidenceScore'] > 80:
                        self.store_finding(
                            category="malicious_ip",
                            finding=f"High-risk IP detected: {ip_address}",
                            severity="HIGH",
                            metadata={
                                "ip": ip_address,
                                "confidence_score": data['data']['abuseConfidenceScore'],
                                "source": "AbuseIPDB"
                            }
                        )
                    results['abuseipdb'] = data
            except Exception as e:
                self.logger.error(f"Error checking AbuseIPDB: {str(e)}")
        
        return results
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a domain against threat intelligence sources."""
        results = {}
        
        # Implement domain analysis using available threat intel sources
        # Similar to analyze_ip but for domains
        
        return results
    
    def get_recent_threats(self, time_window: timedelta = timedelta(days=1)) -> List[Dict[str, Any]]:
        """Get recent threats from our findings database."""
        cutoff_time = datetime.utcnow() - time_window
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, category, severity, finding, metadata
            FROM agent_findings
            WHERE agent_name = ? AND timestamp > ? AND severity IN ('HIGH', 'CRITICAL')
            ORDER BY timestamp DESC
        """, (self.name, cutoff_time.isoformat()))
        
        threats = cursor.fetchall()
        conn.close()
        
        return [
            {
                "timestamp": t[0],
                "category": t[1],
                "severity": t[2],
                "finding": t[3],
                "metadata": json.loads(t[4]) if t[4] else None
            }
            for t in threats
        ]
