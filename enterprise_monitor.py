#!/usr/bin/env python3
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from logging_config import setup_logging
from database import DatabaseManager
from alert_manager import AlertManager
from async_utils import AsyncTaskManager, TaskPriority

@dataclass
class ComplianceEvent:
    timestamp: datetime
    event_type: str
    user: str
    action: str
    resource: str
    status: str
    details: Dict

class EnterpriseMonitor:
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        setup_logging(app_name='enterprise_monitor')
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager or DatabaseManager()
        self.alert_manager = AlertManager()
        self.task_manager = AsyncTaskManager()
        
        # Initialize compliance tracking
        self._init_compliance_tracking()
        
    def _init_compliance_tracking(self):
        """Initialize compliance tracking tables and settings"""
        self.db_manager.execute("""
            CREATE TABLE IF NOT EXISTS compliance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                event_type TEXT,
                user TEXT,
                action TEXT,
                resource TEXT,
                status TEXT,
                details JSON,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.db_manager.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                severity TEXT,
                category TEXT,
                message TEXT,
                metadata JSON,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def log_compliance_event(self, event: ComplianceEvent):
        """Log a compliance-related event"""
        try:
            self.db_manager.execute(
                """INSERT INTO compliance_events 
                   (timestamp, event_type, user, action, resource, status, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (event.timestamp, event.event_type, event.user, event.action,
                 event.resource, event.status, json.dumps(event.details))
            )
            
            # Alert on critical compliance events
            if event.status == 'violation':
                self.alert_manager.create_alert(
                    severity='high',
                    category='compliance',
                    message=f'Compliance violation: {event.action} on {event.resource}',
                    metadata=event.details
                )
                
        except Exception as e:
            self.logger.error(f"Failed to log compliance event: {str(e)}")
    
    def audit_log(self, severity: str, category: str, message: str, metadata: Dict = None):
        """Log an audit event"""
        try:
            self.db_manager.execute(
                """INSERT INTO audit_logs 
                   (timestamp, severity, category, message, metadata)
                   VALUES (?, ?, ?, ?, ?)""",
                (datetime.now(), severity, category, message, 
                 json.dumps(metadata) if metadata else None)
            )
        except Exception as e:
            self.logger.error(f"Failed to create audit log: {str(e)}")
    
    def get_compliance_report(self, start_time: datetime, end_time: datetime) -> Dict:
        """Generate a compliance report for the specified time period"""
        try:
            events = self.db_manager.fetch_all(
                """SELECT event_type, status, COUNT(*) as count
                   FROM compliance_events 
                   WHERE timestamp BETWEEN ? AND ?
                   GROUP BY event_type, status""",
                (start_time, end_time)
            )
            
            violations = self.db_manager.fetch_all(
                """SELECT * FROM compliance_events
                   WHERE status = 'violation'
                   AND timestamp BETWEEN ? AND ?
                   ORDER BY timestamp DESC""",
                (start_time, end_time)
            )
            
            return {
                'summary': {
                    'total_events': sum(e[2] for e in events),
                    'violations': len(violations),
                    'compliant': sum(e[2] for e in events if e[1] == 'compliant'),
                    'period_start': start_time,
                    'period_end': end_time
                },
                'events_by_type': {
                    e[0]: {'total': e[2], 'status': e[1]} 
                    for e in events
                },
                'recent_violations': [
                    {
                        'timestamp': v[1],
                        'type': v[2],
                        'user': v[3],
                        'action': v[4],
                        'resource': v[5],
                        'details': json.loads(v[7])
                    }
                    for v in violations[:10]  # Last 10 violations
                ]
            }
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {str(e)}")
            return {}
    
    def get_audit_trail(self, 
                       start_time: datetime, 
                       end_time: datetime,
                       severity: Optional[str] = None,
                       category: Optional[str] = None) -> List[Dict]:
        """Retrieve audit trail for the specified filters"""
        try:
            query = """SELECT * FROM audit_logs WHERE timestamp BETWEEN ? AND ?"""
            params = [start_time, end_time]
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if category:
                query += " AND category = ?"
                params.append(category)
                
            query += " ORDER BY timestamp DESC"
            
            logs = self.db_manager.fetch_all(query, tuple(params))
            
            return [{
                'timestamp': log[1],
                'severity': log[2],
                'category': log[3],
                'message': log[4],
                'metadata': json.loads(log[5]) if log[5] else None
            } for log in logs]
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve audit trail: {str(e)}")
            return []
    
    def monitor_privileged_access(self, user: str, action: str, resource: str):
        """Monitor and log privileged access attempts"""
        event = ComplianceEvent(
            timestamp=datetime.now(),
            event_type='privileged_access',
            user=user,
            action=action,
            resource=resource,
            status='pending',
            details={'timestamp': time.time()}
        )
        
        # Log the access attempt
        self.log_compliance_event(event)
        
        # Schedule async validation
        self.task_manager.schedule_task(
            self._validate_privileged_access,
            args=(event,),
            priority=TaskPriority.HIGH
        )
    
    async def _validate_privileged_access(self, event: ComplianceEvent):
        """Validate privileged access attempt"""
        try:
            # Implement your validation logic here
            is_valid = True  # Replace with actual validation
            
            # Update the event status
            self.db_manager.execute(
                """UPDATE compliance_events 
                   SET status = ?, 
                       details = ?
                   WHERE timestamp = ? 
                   AND user = ? 
                   AND action = ?""",
                ('compliant' if is_valid else 'violation',
                 json.dumps({
                     **event.details,
                     'validated_at': time.time(),
                     'validation_result': is_valid
                 }),
                 event.timestamp,
                 event.user,
                 event.action)
            )
            
            if not is_valid:
                self.alert_manager.create_alert(
                    severity='critical',
                    category='security',
                    message=f'Invalid privileged access attempt by {event.user}',
                    metadata={'event': event.__dict__}
                )
                
        except Exception as e:
            self.logger.error(f"Failed to validate privileged access: {str(e)}")
            # Log the error and potentially create an alert
