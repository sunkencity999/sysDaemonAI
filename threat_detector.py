#!/usr/bin/env python3
import collections
from datetime import datetime, timedelta
import ipaddress
import json
import logging
from scapy.all import DNS, DNSQR, IP
from typing import Dict, List, Set, Tuple
import re
import requests
import os
import time
from config import ABUSEIPDB_CONFIG
from api_cache import APICache
from ip_blacklist_manager import IPBlacklistManager
from llm_analyzer import LLMAnalyzer

class ThreatDetector:
    def __init__(self, logger=None, ip_blacklist_manager=None):
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize IP blacklist manager if not provided
        self.ip_blacklist_manager = ip_blacklist_manager or IPBlacklistManager()
        
        # Initialize LLM analyzer
        self.llm_analyzer = LLMAnalyzer(logger)
        
        # Port scan detection
        self.port_scan_threshold = 10  # Number of ports per minute to trigger alert
        self.port_scan_window = 60  # Time window in seconds
        self.port_access_history = collections.defaultdict(list)  # {ip: [(timestamp, port)]}
        
        # Known safe addresses and services
        self.safe_addresses = {
            '127.0.0.1': 'Localhost',
            '::1': 'Localhost IPv6',
            'localhost': 'Localhost hostname'
        }
        
        self.safe_services = {
            11434: 'Ollama API',  # Ollama default port
            8000: 'Local development server',
            3000: 'Local development server',
            5000: 'Local development server',
        }
        
        # Attack vector patterns
        self.suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            3389: "RDP",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
            8080: "HTTP Alternate",
            8443: "HTTPS Alternate",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            161: "SNMP",
            389: "LDAP",
            636: "LDAPS",
            1521: "Oracle",
            5601: "Kibana",
            9000: "Portainer",
            6443: "Kubernetes API",
            2379: "etcd",
            5000: "Docker Registry",
            9090: "Prometheus",
            9093: "Alertmanager",
            9100: "Node Exporter"
        }
        
        # Initialize threat intelligence feeds
        self.threat_feeds = [
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://www.spamhaus.org/drop/drop.txt",
            "https://check.torproject.org/exit-addresses",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
        ]
        
        # Load threat intelligence data
        self.known_threats = self._load_threat_intel()
        
        # Initialize behavioral analysis
        self.connection_history = collections.defaultdict(list)
        self.behavioral_patterns = {
            'data_exfiltration': {
                'threshold': 50000000,  # 50MB
                'window': 300  # 5 minutes
            },
            'brute_force': {
                'threshold': 10,  # attempts
                'window': 60  # 1 minute
            },
            'lateral_movement': {
                'threshold': 5,  # internal hosts
                'window': 300  # 5 minutes
            }
        }
        
        # Failed authentication detection
        self.failed_auth_threshold = 5
        self.auth_attempts = collections.defaultdict(int)
        
        # DNS monitoring
        self.dns_query_history = collections.defaultdict(list)  # {domain: [timestamp]}
        self.suspicious_dns_patterns = [
            r".*\d+\.\d+\.\d+\.\d+\..*",  # IP address in domain
            r".*[a-f0-9]{32}.*",          # MD5-like hash
            r".*base64.*",                 # Base64-like strings
        ]
        
        # Known malicious patterns
        self.malicious_patterns = {
            "commands": [
                "cmd.exe", "powershell.exe", "bash", "nc ", "netcat",
                "wget ", "curl ", "chmod +x", "./", "eval("
            ],
            "paths": [
                "/etc/passwd", "/etc/shadow", "/proc/self/environ",
                "wp-config.php", ".env", "id_rsa", ".git/"
            ],
            "payloads": [
                "<script>", "union select", "' or '1'='1", "../../",
                "$(", "${", "&&", "||", ";", "|"
            ]
        }
        
        # Current threats tracking
        self.current_threats = []
        self.threat_retention_period = timedelta(hours=24)  # Keep threats for 24 hours

    def is_malicious_ip(self, ip: str) -> bool:
        """Check if an IP is known to be malicious."""
        # First check if it's a safe address
        if ip in self.safe_addresses:
            return False
            
        # Check the blacklist cache
        return self.ip_blacklist_manager.is_malicious(ip)
        
    def analyze_connection(self, conn_data: Dict) -> List[Dict]:
        """
        Analyze a single connection for potential threats with enhanced LLM analysis.
        Returns a list of detected threats.
        """
        threats = []
        timestamp = datetime.fromisoformat(conn_data['timestamp'])
        remote_ip = conn_data['remote_ip']
        remote_port = conn_data['remote_port']

        # Skip analysis for known safe addresses
        if remote_ip in self.safe_addresses:
            return []

        # Skip analysis for known safe services on localhost
        if (remote_ip == '127.0.0.1' or remote_ip == '::1') and remote_port in self.safe_services:
            return []

        # Check for port scanning
        if self.check_port_scan(remote_ip, remote_port, timestamp):
            threats.append({
                'type': 'port_scan',
                'severity': 'high',
                'details': f'Port scanning detected from {remote_ip}',
                'timestamp': timestamp.isoformat(),
                'context': {
                    'scan_window': self.port_scan_window,
                    'unique_ports': len(set(p for _, p in self.port_access_history[remote_ip])),
                    'total_attempts': len(self.port_access_history[remote_ip])
                }
            })

        # Check suspicious ports (but not for localhost)
        if remote_ip not in ['127.0.0.1', '::1'] and remote_port in self.suspicious_ports:
            threats.append({
                'type': 'suspicious_port',
                'severity': 'medium',
                'details': f'Connection to {self.suspicious_ports[remote_port]} port ({remote_port})',
                'timestamp': timestamp.isoformat(),
                'context': {
                    'service': self.suspicious_ports[remote_port],
                    'known_vulnerabilities': True,
                    'recommended_action': 'block' if remote_port in [23, 445] else 'monitor'
                }
            })

        # Enhanced IP analysis with context
        try:
            ip_obj = ipaddress.ip_address(remote_ip)
            ip_context = {
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_multicast': ip_obj.is_multicast,
                'version': ip_obj.version,
                'reverse_pointer': None  # Could be populated with reverse DNS lookup
            }
            
            if (ip_obj.is_private and 
                remote_ip not in ['127.0.0.1', '::1'] and 
                remote_port in self.suspicious_ports):
                threats.append({
                    'type': 'internal_scan',
                    'severity': 'high',
                    'details': f'Internal network scan detected from {remote_ip}',
                    'timestamp': timestamp.isoformat(),
                    'context': ip_context
                })
        except ValueError:
            pass
        
        # Check if IP is known to be malicious with enhanced context
        if self.is_malicious_ip(remote_ip):
            threats.append({
                'type': 'malicious_ip',
                'severity': 'high',
                'details': f'Connection to known malicious IP: {remote_ip}',
                'timestamp': timestamp.isoformat(),
                'context': {
                    'blacklist_source': 'AbuseIPDB',
                    'previous_incidents': self.ip_blacklist_manager.get_ip_history(remote_ip),
                    'ip_metadata': ip_context if 'ip_context' in locals() else None
                }
            })

        # If threats were detected, get enhanced analysis
        if threats:
            llm_analysis = self.llm_analyzer.analyze_security_event({
                'connection': conn_data,
                'threats': threats,
                'timestamp': timestamp.isoformat()
            })
            
            # Add LLM insights to each threat
            for threat in threats:
                threat['llm_analysis'] = {
                    'risk_assessment': llm_analysis.get('summary', ''),
                    'recommendations': llm_analysis.get('recommendations', ''),
                    'confidence_score': llm_analysis.get('confidence_score', 0.0)
                }
            
            # Update current threats
            self._update_current_threats(threats)

        return threats

    def _update_current_threats(self, new_threats: List[Dict]) -> None:
        """
        Update the current threats list, removing expired threats and adding new ones.
        """
        current_time = datetime.fromisoformat('2024-12-11T16:34:27-08:00')  # Using provided time
        
        # Remove expired threats
        self.current_threats = [
            threat for threat in self.current_threats
            if current_time - datetime.fromisoformat(threat['timestamp']) <= self.threat_retention_period
        ]
        
        # Add new threats
        self.current_threats.extend(new_threats)

    def get_current_threats(self) -> List[Dict]:
        """
        Returns the list of current active threats within the retention period.
        
        Returns:
            List[Dict]: List of current threats with their details, severity, and timestamps
        """
        current_time = datetime.fromisoformat('2024-12-11T16:34:27-08:00')  # Using provided time
        
        # Filter out expired threats before returning
        self.current_threats = [
            threat for threat in self.current_threats
            if current_time - datetime.fromisoformat(threat['timestamp']) <= self.threat_retention_period
        ]
        
        return self.current_threats

    def analyze_dns_packet(self, packet) -> Dict:
        """
        Analyze DNS packets for suspicious patterns.
        Returns detected threat if found, None otherwise.
        """
        if DNS in packet and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8')
            timestamp = datetime.now()
            
            # Store query history
            self.dns_query_history[query].append(timestamp)
            
            # Check for suspicious patterns
            for pattern in self.suspicious_dns_patterns:
                if re.match(pattern, query):
                    return {
                        'type': 'suspicious_dns',
                        'severity': 'medium',
                        'details': f'Suspicious DNS query pattern: {query}',
                        'timestamp': timestamp.isoformat()
                    }
            
            # Check for DNS tunneling (high frequency of unique subdomains)
            if len(self.dns_query_history[query]) > 10:  # More than 10 queries per domain
                return {
                    'type': 'dns_tunneling',
                    'severity': 'high',
                    'details': f'Potential DNS tunneling detected: {query}',
                    'timestamp': timestamp.isoformat()
                }
        
        return None

    def analyze_payload(self, data: str) -> List[Dict]:
        """
        Analyze network payload for known malicious patterns.
        Returns a list of detected threats.
        """
        threats = []
        timestamp = datetime.now()

        for category, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                if pattern in data:
                    threats.append({
                        'type': 'malicious_pattern',
                        'severity': 'high',
                        'details': f'Detected {category} pattern: {pattern}',
                        'timestamp': timestamp.isoformat()
                    })

        return threats

    def generate_threat_report(self, threats: List[Dict]) -> str:
        """
        Generate a detailed threat report with LLM-enhanced analysis.
        """
        if not threats:
            return "No immediate threats detected."

        # First, generate the basic report
        basic_report = "Threat Analysis Report:\n\n"
        
        # Group threats by severity
        severity_groups = collections.defaultdict(list)
        for threat in threats:
            severity_groups[threat['severity']].append(threat)

        # Generate report sections by severity
        for severity in ['high', 'medium', 'low']:
            if severity in severity_groups:
                basic_report += f"{severity.upper()} Severity Threats:\n"
                for threat in severity_groups[severity]:
                    basic_report += f"- Type: {threat['type']}\n"
                    basic_report += f"  Details: {threat['details']}\n"
                    basic_report += f"  Timestamp: {threat['timestamp']}\n"
                basic_report += "\n"

        # Get enhanced analysis from LLM
        llm_analysis = self.llm_analyzer.analyze_security_event({
            'threats': threats,
            'severity_distribution': {
                severity: len(threats_list)
                for severity, threats_list in severity_groups.items()
            },
            'timestamp': datetime.now().isoformat(),
            'threat_types': [threat['type'] for threat in threats],
            'threat_details': [threat['details'] for threat in threats]
        })

        # Combine basic report with LLM analysis
        enhanced_report = (
            f"{basic_report}\n"
            f"AI-Enhanced Analysis:\n"
            f"{'=' * 50}\n"
            f"Summary: {llm_analysis.get('summary', 'No summary available')}\n\n"
            f"Detailed Analysis:\n{llm_analysis.get('details', 'No detailed analysis available')}\n\n"
            f"Recommendations:\n{llm_analysis.get('recommendations', 'No recommendations available')}\n\n"
            f"Confidence Score: {llm_analysis.get('confidence_score', 0.0)}\n"
            f"Analysis Timestamp: {llm_analysis.get('timestamp', datetime.now().isoformat())}\n"
        )

        return enhanced_report

    def check_port_scan(self, ip: str, port: int, timestamp: datetime) -> bool:
        """
        Detect potential port scanning activity.
        Returns True if port scanning is detected.
        """
        # Add new port access to history
        self.port_access_history[ip].append((timestamp, port))
        
        # Remove old entries outside the window
        window_start = timestamp - timedelta(seconds=self.port_scan_window)
        self.port_access_history[ip] = [
            (ts, p) for ts, p in self.port_access_history[ip]
            if ts > window_start
        ]
        
        # Count unique ports in window
        unique_ports = len(set(p for _, p in self.port_access_history[ip]))
        
        if unique_ports >= self.port_scan_threshold:
            self.logger.warning(f"Potential port scan detected from {ip}: {unique_ports} ports in {self.port_scan_window}s")
            return True
        return False

    def _load_threat_intel(self) -> Set[str]:
        """
        Load threat intelligence data from configured feeds.
        Returns a set of known malicious IPs.
        """
        known_threats = set()
        
        for feed in self.threat_feeds:
            try:
                response = requests.get(feed)
                response.raise_for_status()
                known_threats.update(response.text.splitlines())
            except requests.RequestException as e:
                self.logger.error(f"Failed to load threat intel from {feed}: {e}")
        
        return known_threats
