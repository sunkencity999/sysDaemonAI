#!/usr/bin/env python3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from plyer import notification
import os

class AlertManager:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.alert_history = {}
        self.alert_cooldowns = {
            'critical': 900,    # 15 minutes for critical alerts
            'high': 1800,      # 30 minutes for high priority
            'medium': 3600,    # 1 hour for medium priority
            'low': 7200       # 2 hours for low priority
        }
        
        # Enhanced thresholds with severity levels
        self.thresholds = {
            'cpu_usage': {
                'critical': 90.0,
                'high': 80.0,
                'medium': 70.0,
                'low': 60.0
            },
            'memory_usage': {
                'critical': 90.0,
                'high': 80.0,
                'medium': 70.0,
                'low': 60.0
            },
            'disk_usage': {
                'critical': 95.0,
                'high': 85.0,
                'medium': 75.0,
                'low': 65.0
            },
            'bandwidth_spike_factor': {
                'critical': 5.0,
                'high': 3.0,
                'medium': 2.0,
                'low': 1.5
            },
            'latency_threshold': {
                'critical': 500.0,
                'high': 300.0,
                'medium': 200.0,
                'low': 100.0
            },
            'process_cpu_usage': {
                'critical': 95.0,
                'high': 85.0,
                'medium': 75.0,
                'low': 65.0
            },
            'process_memory_usage': {
                'critical': 95.0,
                'high': 85.0,
                'medium': 75.0,
                'low': 65.0
            }
        }
        
        # Initialize notification channels
        self.notification_channels = {
            'system': True,     # System notifications
            'log': True,        # Log file
            'database': True    # Database storage
        }
        
    def can_alert(self, alert_type: str, severity: str, identifier: str = "default") -> bool:
        """Check if enough time has passed since the last alert based on severity"""
        key = f"{alert_type}:{identifier}"
        if key not in self.alert_history:
            return True
            
        last_alert_time = self.alert_history[key]
        cooldown = self.alert_cooldowns.get(severity, self.alert_cooldowns['medium'])
        return (datetime.now() - last_alert_time).total_seconds() >= cooldown
        
    def get_severity(self, metric_type: str, value: float) -> str:
        """Determine severity level based on thresholds"""
        thresholds = self.thresholds.get(metric_type, {})
        
        if value >= thresholds.get('critical', float('inf')):
            return 'critical'
        elif value >= thresholds.get('high', float('inf')):
            return 'high'
        elif value >= thresholds.get('medium', float('inf')):
            return 'medium'
        elif value >= thresholds.get('low', float('inf')):
            return 'low'
        return 'info'
        
    def record_alert(self, alert_type: str, identifier: str = "default"):
        """Record that an alert was sent"""
        key = f"{alert_type}:{identifier}"
        self.alert_history[key] = datetime.now()
        
    def show_notification(self, title: str, message: str, alert_type: str, 
                         severity: str = 'medium', identifier: str = "default"):
        """Show notifications through configured channels"""
        if not self.can_alert(alert_type, severity, identifier):
            return
            
        timestamp = datetime.now()
        
        # Format message with severity and timestamp
        formatted_message = f"[{severity.upper()}] {message}"
        
        try:
            # System notification
            if self.notification_channels['system']:
                try:
                    notification.notify(
                        title=f"{title} ({severity.upper()})",
                        message=formatted_message,
                        app_icon=None,
                        timeout=10,
                    )
                except Exception as e:
                    self.logger.error(f"Failed to send system notification: {str(e)}")
            
            # Log notification
            if self.notification_channels['log']:
                log_level = {
                    'critical': logging.CRITICAL,
                    'high': logging.ERROR,
                    'medium': logging.WARNING,
                    'low': logging.INFO,
                    'info': logging.INFO
                }.get(severity, logging.INFO)
                
                self.logger.log(log_level, formatted_message)
            
            # Database notification
            if self.notification_channels['database']:
                from database import DatabaseManager
                db = DatabaseManager()
                db.add_alert(
                    alert_type=alert_type,
                    severity=severity,
                    description=message,
                    metrics={'title': title, 'timestamp': timestamp.isoformat()}
                )
            
            self.record_alert(alert_type, identifier)
            
        except Exception as e:
            self.logger.error(f"Error in alert notification system: {str(e)}")
            
    def check_system_metrics(self, metrics: Dict) -> List[Dict]:
        """Check system metrics against thresholds and generate alerts"""
        alerts = []
        
        # CPU Usage Alert
        cpu_usage = metrics['cpu']['total_usage']
        severity = self.get_severity('cpu_usage', cpu_usage)
        if severity != 'info':
            alert = {
                'type': 'cpu_usage',
                'title': 'High CPU Usage Alert',
                'message': f'System CPU usage is at {cpu_usage:.1f}% (threshold: {self.thresholds["cpu_usage"][severity]}%)',
                'severity': severity
            }
            alerts.append(alert)
            
        # Memory Usage Alert
        memory_percent = metrics['memory']['percent']
        severity = self.get_severity('memory_usage', memory_percent)
        if severity != 'info':
            alert = {
                'type': 'memory_usage',
                'title': 'High Memory Usage Alert',
                'message': f'System memory usage is at {memory_percent:.1f}% (threshold: {self.thresholds["memory_usage"][severity]}%)',
                'severity': severity
            }
            alerts.append(alert)
            
        # Disk Usage Alert
        disk_percent = metrics['disk']['percent']
        severity = self.get_severity('disk_usage', disk_percent)
        if severity != 'info':
            alert = {
                'type': 'disk_usage',
                'title': 'High Disk Usage Alert',
                'message': f'Disk usage is at {disk_percent:.1f}% (threshold: {self.thresholds["disk_usage"][severity]}%)',
                'severity': severity
            }
            alerts.append(alert)
            
        return alerts
        
    def check_bandwidth(self, current: Dict, previous: Optional[Dict]) -> List[Dict]:
        """Check bandwidth metrics and generate alerts"""
        alerts = []
        
        if not previous:
            return alerts
            
        # Check for bandwidth spikes
        for direction in ['upload', 'download']:
            current_value = current[direction]
            previous_value = previous[direction]
            
            if previous_value > 0 and current_value > (previous_value * self.thresholds['bandwidth_spike_factor']['high']):
                severity = 'high'
                if current_value > (previous_value * self.thresholds['bandwidth_spike_factor']['critical']):
                    severity = 'critical'
                alert = {
                    'type': f'bandwidth_spike_{direction}',
                    'title': f'Bandwidth Spike Alert ({direction.title()})',
                    'message': f'Sudden increase in {direction} bandwidth: {current[f"{direction}_human"]}',
                    'severity': severity
                }
                alerts.append(alert)
                
        return alerts
        
    def check_latency(self, latency_data: Dict) -> List[Dict]:
        """Check latency measurements and generate alerts"""
        alerts = []
        
        for host, data in latency_data.items():
            if data['current'] and data['current'] > self.thresholds['latency_threshold']['high']:
                severity = 'high'
                if data['current'] > self.thresholds['latency_threshold']['critical']:
                    severity = 'critical'
                alert = {
                    'type': 'high_latency',
                    'title': 'High Latency Alert',
                    'message': f'High latency detected to {host}: {data["current"]:.1f}ms (threshold: {self.thresholds["latency_threshold"][severity]}ms)',
                    'severity': severity,
                    'identifier': host
                }
                alerts.append(alert)
                
        return alerts
        
    def check_process_metrics(self, process_stats: List[Dict]) -> List[Dict]:
        """Check process-specific metrics and generate alerts"""
        alerts = []
        
        for proc in process_stats:
            # Check CPU usage per process
            severity = self.get_severity('process_cpu_usage', proc['cpu_percent'])
            if severity != 'info':
                alert = {
                    'type': 'process_cpu_usage',
                    'title': 'High Process CPU Usage',
                    'message': f'Process {proc["name"]} (PID: {proc["pid"]}) CPU usage: {proc["cpu_percent"]:.1f}%',
                    'severity': severity,
                    'identifier': str(proc['pid'])
                }
                alerts.append(alert)
                
            # Check memory usage per process
            severity = self.get_severity('process_memory_usage', proc['memory_percent'])
            if severity != 'info':
                alert = {
                    'type': 'process_memory_usage',
                    'title': 'High Process Memory Usage',
                    'message': f'Process {proc["name"]} (PID: {proc["pid"]}) memory usage: {proc["memory_percent"]:.1f}%',
                    'severity': severity,
                    'identifier': str(proc['pid'])
                }
                alerts.append(alert)
                
        return alerts
        
    def process_performance_data(self, current_data: Dict, previous_data: Optional[Dict] = None):
        """Process all performance data and generate appropriate alerts"""
        all_alerts = []
        
        # Check system metrics
        all_alerts.extend(self.check_system_metrics(current_data['system_metrics']))
        
        # Check bandwidth
        if previous_data:
            all_alerts.extend(self.check_bandwidth(
                current_data['current_bandwidth'],
                previous_data['current_bandwidth']
            ))
            
        # Check latency
        all_alerts.extend(self.check_latency(current_data.get('latency_stats', {})))
        
        # Check process metrics
        all_alerts.extend(self.check_process_metrics(current_data['process_stats']))
        
        # Show notifications for all alerts
        for alert in all_alerts:
            self.show_notification(
                title=alert['title'],
                message=alert['message'],
                alert_type=alert['type'],
                severity=alert.get('severity', 'medium'),
                identifier=alert.get('identifier', 'default')
            )
