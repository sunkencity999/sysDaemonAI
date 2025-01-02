"""Log monitoring agent for system security."""

from .base_agent import BaseAgent
import re
from typing import List, Dict, Any, Optional
import os
from datetime import datetime, timedelta
import logging
from PyQt6.QtCore import QObject, pyqtSignal
import json
import platform

class LogMonitorAgent(BaseAgent, QObject):
    """Agent for monitoring system logs for security events."""
    
    # Signals for UI updates
    finding_signal = pyqtSignal(str, dict)  # (finding_html, metadata)
    status_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self):
        BaseAgent.__init__(
            self,
            name="LogMonitor",
            role="System Log Analyst",
            goal="Monitor system logs for security-relevant events and anomalies"
        )
        QObject.__init__(self)
        
        # Initialize log paths based on OS
        self.log_paths = self._get_system_logs()
        self.last_check = {}  # Track last check position for each file
        self.logger = logging.getLogger(__name__)
        
        # Configure log rotation
        for handler in self.logger.handlers:
            if isinstance(handler, logging.FileHandler):
                # Create a rotating file handler
                max_bytes = 10 * 1024 * 1024  # 10MB
                backup_count = 5
                rotating_handler = logging.handlers.RotatingFileHandler(
                    handler.baseFilename,
                    maxBytes=max_bytes,
                    backupCount=backup_count
                )
                rotating_handler.setFormatter(handler.formatter)
                self.logger.removeHandler(handler)
                self.logger.addHandler(rotating_handler)
        
        # Add memory-efficient set for duplicate detection
        self.seen_lines = set()
        self.max_seen_lines = 10000  # Limit memory usage
        
        # Security patterns to look for
        self.patterns = {
            'authentication': {
                'pattern': r'authentication\s+failure|failed\s+login|invalid\s+password',
                'severity': 'HIGH',
                'description': 'Authentication failure detected',
                'recommendations': [
                    'Review authentication logs for source IP',
                    'Check for brute force attempts',
                    'Consider implementing account lockout policies'
                ]
            },
            'privilege_escalation': {
                'pattern': r'sudo|su\s+command|privilege\s+escalation',
                'severity': 'HIGH',
                'description': 'Potential privilege escalation attempt',
                'recommendations': [
                    'Review sudo/su command usage',
                    'Verify user permissions',
                    'Check for unauthorized privilege changes'
                ]
            },
            'network': {
                'pattern': r'connection\s+refused|port\s+scan|firewall\s+block',
                'severity': 'MEDIUM',
                'description': 'Suspicious network activity detected',
                'recommendations': [
                    'Review source IP addresses',
                    'Check firewall rules',
                    'Monitor for continued scanning activity'
                ]
            },
            'malware': {
                'pattern': r'malware|virus|trojan|ransomware',
                'severity': 'HIGH',
                'description': 'Potential malware activity detected',
                'recommendations': [
                    'Isolate affected systems',
                    'Run full system scan',
                    'Update antivirus signatures'
                ]
            },
            'system': {
                'pattern': r'system\s+error|crash|kernel\s+panic|out\s+of\s+memory',
                'severity': 'MEDIUM',
                'description': 'System stability issue detected',
                'recommendations': [
                    'Check system resources',
                    'Review error logs',
                    'Monitor system performance'
                ]
            }
        }
        
        # Initialize last check positions
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                self.last_check[log_path] = os.path.getsize(log_path)
                
    def _get_system_logs(self) -> List[str]:
        """Get system log paths based on OS."""
        system = platform.system()
        
        if system == "Darwin":  # macOS
            logs = []
            # System logs
            if os.path.exists("/var/log/system.log"):
                logs.append("/var/log/system.log")
            
            # Application logs
            app_logs = os.path.expanduser("~/Library/Logs")
            if os.path.exists(app_logs):
                logs.append(app_logs)
            
            # System diagnostic reports
            diag_reports = os.path.expanduser("~/Library/Logs/DiagnosticReports")
            if os.path.exists(diag_reports):
                logs.append(diag_reports)
                
            # Console logs
            console_logs = "/var/log/com.apple.xpc.launchd"
            if os.path.exists(console_logs):
                logs.append(console_logs)
                
            # Add our application logs
            app_log = os.path.join(os.getcwd(), "logs/monitoring.log")
            if os.path.exists(app_log):
                logs.append(app_log)
                
            return logs
            
        elif system == "Linux":
            return [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/kern.log",
            ]
        else:  # Windows or other
            return []
    
    def analyze_logs(self, time_window: timedelta = timedelta(hours=1)) -> List[Dict[str, Any]]:
        """Analyze logs within the specified time window."""
        findings = []
        cutoff_time = datetime.now() - time_window
        accessible_logs = False
        
        for log_path in self.log_paths:
            if not os.path.exists(log_path):
                self.logger.warning(f"Log file not found: {log_path}")
                continue
                
            if not os.access(log_path, os.R_OK):
                self.logger.warning(f"No read permission for log file: {log_path}")
                continue
                
            accessible_logs = True
            
            try:
                # Handle directory of logs
                if os.path.isdir(log_path):
                    for root, _, files in os.walk(log_path):
                        for file in files:
                            if file.endswith('.log') or file.endswith('.txt'):
                                full_path = os.path.join(root, file)
                                self._analyze_single_log(full_path, cutoff_time, findings)
                else:
                    # Handle single log file
                    self._analyze_single_log(log_path, cutoff_time, findings)
                
            except PermissionError:
                self.logger.error(f"Permission denied reading log {log_path}")
                self.error_signal.emit(f"Permission denied reading log {log_path}")
            except Exception as e:
                self.logger.error(f"Error analyzing log {log_path}: {str(e)}")
                self.error_signal.emit(f"Error analyzing log {log_path}: {str(e)}")
        
        if not accessible_logs:
            self.error_signal.emit("No accessible system logs found. Try running with elevated privileges.")
            return []
            
        if not findings:
            self.status_signal.emit("No new findings in logs")
        else:
            self.status_signal.emit(f"Found {len(findings)} new log entries")
            
        return findings
    
    def _analyze_single_log(self, log_path: str, cutoff_time: datetime, findings: List[Dict[str, Any]]):
        """Analyze a single log file."""
        try:
            current_size = os.path.getsize(log_path)
            last_size = self.last_check.get(log_path, 0)
            
            # Skip if file hasn't changed
            if current_size == last_size:
                return
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # If file has grown, only read new content
                if current_size > last_size:
                    f.seek(last_size)
                else:
                    # File was rotated or truncated, read from start
                    f.seek(0)
                    # Clear seen lines since file was rotated
                    self.seen_lines.clear()
                
                batch_size = 1000  # Process lines in batches
                batch = []
                
                for line in f:
                    # Skip if we've seen this line before
                    line_hash = hash(line.strip())
                    if line_hash in self.seen_lines:
                        continue
                        
                    # Add to seen lines with size limit
                    self.seen_lines.add(line_hash)
                    if len(self.seen_lines) > self.max_seen_lines:
                        self.seen_lines.clear()  # Clear if too large
                        self.seen_lines.add(line_hash)  # Keep current line
                    
                    # Skip our own logs
                    if "Stored finding:" in line or "LogMonitorAgent" in line:
                        continue
                    
                    # Parse timestamp from log line
                    timestamp = self._parse_timestamp(line)
                    if timestamp and timestamp < cutoff_time:
                        continue
                    
                    # Add to batch
                    batch.append(line)
                    
                    # Process batch when it reaches batch_size
                    if len(batch) >= batch_size:
                        self._process_batch(batch, findings, log_path)
                        batch = []
                
                # Process remaining lines
                if batch:
                    self._process_batch(batch, findings, log_path)
            
            # Update last check position
            self.last_check[log_path] = current_size
            
        except UnicodeDecodeError:
            # Skip binary files
            self.logger.debug(f"Skipping binary file: {log_path}")
        except Exception as e:
            self.logger.error(f"Error analyzing log {log_path}: {str(e)}")
            raise
    
    def _process_batch(self, batch: List[str], findings: List[Dict[str, Any]], log_path: str):
        """Process a batch of log lines."""
        for line in batch:
            # Analyze line for patterns
            line_findings = self._analyze_line(line)
            for category, matches in line_findings.items():
                if matches:
                    timestamp = self._parse_timestamp(line)
                    finding = {
                        'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'category': category,
                        'source': os.path.basename(log_path),
                        'matches': matches,
                        'severity': self.patterns[category]['severity'],
                        'description': self.patterns[category]['description'],
                        'recommendations': self.patterns[category]['recommendations'],
                        'raw_log': line.strip()
                    }
                    findings.append(finding)
                    
                    # Store finding in database
                    self.store_finding(
                        category=category,
                        finding=json.dumps(finding),
                        severity=finding['severity'],
                        metadata={'source': finding['source']}
                    )
                    
                    # Emit signal for UI update
                    self._format_and_emit_finding(finding)
    
    def _analyze_line(self, line: str) -> Dict[str, List[str]]:
        """Analyze a single log line for patterns."""
        # Skip our own finding logs to prevent recursion
        if "Stored finding:" in line or "LogMonitorAgent" in line:
            return {}
            
        findings = {}
        for category, pattern_info in self.patterns.items():
            matches = re.findall(pattern_info['pattern'], line, re.IGNORECASE)
            if matches:
                findings[category] = matches
        return findings
    
    def _parse_timestamp(self, line: str) -> Optional[datetime]:
        """Parse timestamp from log line."""
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # 2024-12-20 15:05:21
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',    # Dec 20 15:05:21
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})'   # 12/20/2024 15:05:21
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    try:
                        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                    except ValueError:
                        try:
                            return datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S")
                        except ValueError:
                            continue
        return None
    
    def _format_and_emit_finding(self, finding: Dict[str, Any]):
        """Format finding for UI display and emit signal."""
        severity_colors = {
            'HIGH': '#ff4444',
            'MEDIUM': '#ffaa00',
            'LOW': '#44aa44'
        }
        
        html = f"""
        <div style='margin-bottom: 10px; padding: 5px; border-left: 3px solid {severity_colors.get(finding['severity'], '#888888')};'>
            <p><strong>Time:</strong> {finding['timestamp']}</p>
            <p><strong>Category:</strong> {finding['category']} ({finding['severity']})</p>
            <p><strong>Source:</strong> {finding['source']}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Log Entry:</strong> <pre>{finding['raw_log']}</pre></p>
            <p><strong>Recommendations:</strong></p>
            <ul>
                {''.join(f'<li>{rec}</li>' for rec in finding['recommendations'])}
            </ul>
        </div>
        """
        
        self.finding_signal.emit(html, finding)
