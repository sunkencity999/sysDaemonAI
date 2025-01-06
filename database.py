#!/usr/bin/env python3
import os
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, ForeignKey, Index, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session
from sqlalchemy.pool import QueuePool
from cachetools import TTLCache, LRUCache
import schedule
import threading
import time
from typing import List, Optional, Dict, Any

# Create the base class for declarative models
Base = declarative_base()

class SystemMetrics(Base):
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    network_throughput = Column(Float)
    process_count = Column(Integer)
    
    # Add index for timestamp since it's frequently queried
    __table_args__ = (
        Index('idx_system_metrics_timestamp', timestamp),
    )

class NetworkConnection(Base):
    __tablename__ = 'network_connections'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String)
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    connection_status = Column(String)
    threat_level = Column(Float, nullable=True)
    
    # Add composite index for IP pairs
    __table_args__ = (
        Index('idx_network_conn_ips', source_ip, destination_ip),
        Index('idx_network_conn_timestamp', timestamp),
    )

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    alert_type = Column(String, index=True)
    severity = Column(String, index=True)
    description = Column(String)
    metrics = Column(JSON)
    resolved = Column(Integer, default=0, index=True)
    resolution_time = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_alerts_type_severity', alert_type, severity),
    )

class Threat(Base):
    __tablename__ = 'threats'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    process_name = Column(String, index=True)
    remote_ip = Column(String, index=True)
    remote_port = Column(Integer)
    connection_status = Column(String)
    threat_type = Column(String, index=True)
    resolved = Column(Integer, default=0, index=True)
    resolution_time = Column(DateTime, nullable=True)
    resolution_action = Column(String, nullable=True)
    
    __table_args__ = (
        Index('idx_threats_ip_type', remote_ip, threat_type),
    )

class DatabaseManager:
    def __init__(self):
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Use home directory for database
        home_dir = os.path.expanduser("~")
        data_dir = os.path.join(home_dir, '.sysdaemonai', 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Database path
        self.db_path = os.path.join(data_dir, 'sysdaemon.db')
        
        # Configure database settings
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        self.batch_size = 100
        self.flush_interval = 60  # seconds
        self.BATCH_SIZE = 250  # Increased batch size for better throughput
        self.retention_periods = {
            'system_metrics': 90,  # 90 days
            'network_connections': 180,  # 180 days
            'alerts': 365,  # 1 year
            'threats': 365  # 1 year
        }
        
        # Configure the engine with optimized pooling
        self.engine = create_engine(
            f'sqlite:///{self.db_path}',
            connect_args={'check_same_thread': False},
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            pool_recycle=3600
        )
        
        # Initialize session factory
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        
        # Initialize metrics batching
        self._metrics_batch: List[SystemMetrics] = []
        self._network_batch: List[NetworkConnection] = []
        self._alerts_batch: List[Alert] = []
        self._last_flush = datetime.now()
        
        # Initialize caches with optimized sizes and TTLs
        self.metrics_cache = TTLCache(maxsize=5000, ttl=300)  # Increased cache size, 5 minute TTL
        self.network_cache = TTLCache(maxsize=5000, ttl=300)
        self.alerts_cache = LRUCache(maxsize=2000)  # Doubled LRU cache size
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Schedule automatic cleanup
        self._schedule_cleanup()

    @contextmanager
    def get_session(self):
        """Get a database session with retry logic"""
        session = self.Session()
        retry_count = 0
        
        try:
            while True:
                try:
                    yield session
                    session.commit()
                    break
                except Exception as e:
                    session.rollback()
                    retry_count += 1
                    
                    if retry_count >= self.max_retries:
                        self.logger.error(f"Max retries ({self.max_retries}) exceeded: {str(e)}")
                        raise
                    
                    self.logger.warning(f"Database operation failed, attempt {retry_count} of {self.max_retries}: {str(e)}")
                    time.sleep(self.retry_delay)
        finally:
            session.close()
            
    def execute_with_retry(self, operation, *args, **kwargs):
        """Execute a database operation with retry logic"""
        retry_count = 0
        while True:
            try:
                with self.get_session() as session:
                    return operation(session, *args, **kwargs)
            except Exception as e:
                retry_count += 1
                if retry_count >= self.max_retries:
                    self.logger.error(f"Operation failed after {self.max_retries} retries: {str(e)}")
                    raise
                self.logger.warning(f"Operation failed, attempt {retry_count} of {self.max_retries}: {str(e)}")
                time.sleep(self.retry_delay * retry_count)  # Exponential backoff
                
    def _flush_metrics_batch(self):
        """Flush the metrics batch to the database."""
        if self._metrics_batch:
            self.execute_with_retry(self._flush_metrics_batch_operation)
            self._metrics_batch = []
    
    def _flush_metrics_batch_operation(self, session):
        session.bulk_save_objects(self._metrics_batch)
    
    def _flush_network_batch(self):
        """Flush the network connections batch to the database."""
        if self._network_batch:
            self.execute_with_retry(self._flush_network_batch_operation)
            self._network_batch = []
    
    def _flush_network_batch_operation(self, session):
        session.bulk_save_objects(self._network_batch)
    
    def _flush_alerts_batch(self):
        """Flush the alerts batch to the database."""
        if self._alerts_batch:
            self.execute_with_retry(self._flush_alerts_batch_operation)
            self._alerts_batch = []
    
    def _flush_alerts_batch_operation(self, session):
        session.bulk_save_objects(self._alerts_batch)
    
    def add_system_metrics(self, cpu: float, memory: float, disk: float, 
                          network: float, process_count: int):
        metrics = SystemMetrics(
            timestamp=datetime.now(),
            cpu_usage=cpu,
            memory_usage=memory,
            disk_usage=disk,
            network_throughput=network,
            process_count=process_count
        )
        self._metrics_batch.append(metrics)
        
        if len(self._metrics_batch) >= self.batch_size:
            self._flush_metrics_batch()
    
    def add_network_connection(self, src_ip: str, dst_ip: str, src_port: int, 
                             dst_port: int, protocol: str, bytes_sent: int, 
                             bytes_received: int, status: str, 
                             threat_level: Optional[float] = None):
        conn = NetworkConnection(
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            connection_status=status,
            threat_level=threat_level
        )
        self._network_batch.append(conn)
        
        if len(self._network_batch) >= self.batch_size:
            self._flush_network_batch()
    
    def add_alert(self, alert_type: str, severity: str, description: str, 
                  metrics: Dict[str, Any]):
        alert = Alert(
            timestamp=datetime.now(),
            alert_type=alert_type,
            severity=severity,
            description=description,
            metrics=metrics
        )
        self._alerts_batch.append(alert)
        
        if len(self._alerts_batch) >= self.batch_size:
            self._flush_alerts_batch()
    
    def get_metrics_range(self, start_time: datetime, end_time: datetime) -> List[SystemMetrics]:
        cache_key = f"metrics_{start_time}_{end_time}"
        if cache_key in self.metrics_cache:
            return self.metrics_cache[cache_key]
        
        def get_metrics_range_operation(session):
            return session.query(SystemMetrics).filter(
                SystemMetrics.timestamp.between(start_time, end_time)
            ).all()
        
        result = self.execute_with_retry(get_metrics_range_operation)
        self.metrics_cache[cache_key] = result
        return result
    
    def get_network_connections(self, start_time: datetime, end_time: datetime) -> List[NetworkConnection]:
        cache_key = f"network_{start_time}_{end_time}"
        if cache_key in self.network_cache:
            return self.network_cache[cache_key]
        
        def get_network_connections_operation(session):
            return session.query(NetworkConnection).filter(
                NetworkConnection.timestamp.between(start_time, end_time)
            ).all()
        
        result = self.execute_with_retry(get_network_connections_operation)
        self.network_cache[cache_key] = result
        return result
    
    def get_alerts(self, start_time: datetime, end_time: datetime, 
                   resolved: Optional[bool] = None) -> List[Alert]:
        cache_key = f"alerts_{start_time}_{end_time}_{resolved}"
        if cache_key in self.alerts_cache:
            return self.alerts_cache[cache_key]
        
        def get_alerts_operation(session):
            query = session.query(Alert).filter(
                Alert.timestamp.between(start_time, end_time)
            )
            if resolved is not None:
                query = query.filter(Alert.resolved == int(resolved))
            return query.all()
        
        result = self.execute_with_retry(get_alerts_operation)
        self.alerts_cache[cache_key] = result
        return result
    
    def resolve_alert(self, alert_id: int):
        def resolve_alert_operation(session):
            alert = session.query(Alert).get(alert_id)
            if alert:
                alert.resolved = 1
                alert.resolution_time = datetime.now()
        
        self.execute_with_retry(resolve_alert_operation)
    
    def cleanup_old_data(self, table_name: str, days_to_keep: int):
        """Clean up old data from specified table"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            def cleanup_old_data_operation(session):
                if table_name == 'system_metrics':
                    session.query(SystemMetrics).filter(SystemMetrics.timestamp < cutoff_date).delete()
                elif table_name == 'network_connections':
                    session.query(NetworkConnection).filter(NetworkConnection.timestamp < cutoff_date).delete()
                elif table_name == 'alerts':
                    session.query(Alert).filter(Alert.timestamp < cutoff_date).delete()
                elif table_name == 'threats':
                    session.query(Threat).filter(Threat.timestamp < cutoff_date).delete()
            
            self.execute_with_retry(cleanup_old_data_operation)
            self.logger.info(f"Cleaned up old data from {table_name} older than {days_to_keep} days")
        except Exception as e:
            self.logger.error(f"Error cleaning up old data from {table_name}: {str(e)}")
    
    def record_threat(self, threat_data: dict):
        """Record a detected threat in the database."""
        try:
            def record_threat_operation(session):
                threat = Threat(
                    timestamp=datetime.fromisoformat(threat_data['timestamp']),
                    process_name=threat_data['process_name'],
                    remote_ip=threat_data['remote_ip'],
                    remote_port=threat_data['remote_port'],
                    connection_status=threat_data['connection_status'],
                    threat_type=threat_data['threat_type']
                )
                session.add(threat)
            
            self.execute_with_retry(record_threat_operation)
        except Exception as e:
            self.logger.error(f"Failed to record threat: {str(e)}")
            raise
    
    def execute(self, query: str, params: dict = None) -> bool:
        """Execute a query with parameters"""
        try:
            with self.engine.connect() as conn:
                if params:
                    result = conn.execute(text(query), [params])
                else:
                    result = conn.execute(text(query))
                conn.commit()
                return True  # Return True to indicate success
        except Exception as e:
            self.logger.error(f"Database error in execute: {str(e)}")
            return False  # Return False to indicate failure
            
    def fetch_one(self, query: str, params: dict = None) -> Optional[tuple]:
        """Execute a SELECT query and return a single row"""
        try:
            with self.engine.connect() as conn:
                if params:
                    result = conn.execute(text(query), [params])
                else:
                    result = conn.execute(text(query))
                return result.fetchone()
        except Exception as e:
            self.logger.error(f"Database error in fetch_one: {str(e)}")
            return None
            
    def fetch_all(self, query: str, params: dict = None) -> List[tuple]:
        """Execute a SELECT query and return all rows"""
        try:
            with self.engine.connect() as conn:
                if params:
                    result = conn.execute(text(query), [params])
                else:
                    result = conn.execute(text(query))
                return result.fetchall()
        except Exception as e:
            self.logger.error(f"Database error in fetch_all: {str(e)}")
            return []
    
    def __del__(self):
        """Ensure all batches are flushed before destroying the object."""
        try:
            self._flush_metrics_batch()
            self._flush_network_batch()
            self._flush_alerts_batch()
        except:
            pass

    def _schedule_cleanup(self):
        """Schedule automatic data cleanup based on retention periods"""
        import schedule
        import threading
        
        def cleanup_job():
            for table, days in self.retention_periods.items():
                self.cleanup_old_data(table, days)
        
        schedule.every().day.at("02:00").do(cleanup_job)  # Run at 2 AM
        
        def run_schedule():
            while True:
                schedule.run_pending()
                time.sleep(3600)  # Check every hour
        
        cleanup_thread = threading.Thread(target=run_schedule, daemon=True)
        cleanup_thread.start()
