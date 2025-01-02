#!/usr/bin/env python3
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import asyncio
from prometheus_client import Counter, Gauge, Histogram
import logging
from database import SystemMetrics, NetworkConnection, Alert, Threat

# Prometheus metrics
DB_OPERATIONS = Counter(
    'database_operations_total',
    'Number of database operations',
    ['operation_type', 'table']
)
DB_OPERATION_DURATION = Histogram(
    'database_operation_duration_seconds',
    'Time spent in database operations',
    ['operation_type', 'table'],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0)
)
DB_CONNECTION_POOL = Gauge(
    'database_connection_pool',
    'Database connection pool statistics',
    ['state']
)
DB_ROWS = Gauge(
    'database_rows',
    'Number of rows in database tables',
    ['table']
)

class AsyncDatabaseManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine = create_async_engine(
            'sqlite+aiosqlite:///data/sysdaemon.db',
            pool_size=20,
            max_overflow=30,
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True
        )
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Initialize metrics collection
        asyncio.create_task(self._collect_metrics())
    
    async def _collect_metrics(self):
        """Collect and update database metrics periodically"""
        while True:
            try:
                async with self.async_session() as session:
                    # Update connection pool metrics
                    pool = self.engine.pool
                    DB_CONNECTION_POOL.labels('in_use').set(pool.checkedin())
                    DB_CONNECTION_POOL.labels('available').set(pool.checkedout())
                    
                    # Update table row counts
                    for table in [SystemMetrics, NetworkConnection, Alert, Threat]:
                        count = await session.scalar(
                            text(f"SELECT COUNT(*) FROM {table.__tablename__}")
                        )
                        DB_ROWS.labels(table.__tablename__).set(count)
                
                await asyncio.sleep(60)  # Update every minute
            except Exception as e:
                self.logger.error(f"Error collecting metrics: {str(e)}")
                await asyncio.sleep(5)  # Retry after 5 seconds on error
    
    async def add_system_metrics_batch(self, metrics_list: List[Dict[str, Any]]):
        """Add system metrics in batch"""
        async with DB_OPERATION_DURATION.labels('insert', 'system_metrics').time():
            async with self.async_session() as session:
                session.add_all([
                    SystemMetrics(**metrics)
                    for metrics in metrics_list
                ])
                await session.commit()
                DB_OPERATIONS.labels('insert', 'system_metrics').inc(len(metrics_list))
    
    async def add_network_connections_batch(self, connections_list: List[Dict[str, Any]]):
        """Add network connections in batch"""
        async with DB_OPERATION_DURATION.labels('insert', 'network_connections').time():
            async with self.async_session() as session:
                session.add_all([
                    NetworkConnection(**conn)
                    for conn in connections_list
                ])
                await session.commit()
                DB_OPERATIONS.labels('insert', 'network_connections').inc(len(connections_list))
    
    async def get_metrics_range(self, start_time: datetime, end_time: datetime,
                              partition: str = 'current') -> List[SystemMetrics]:
        """Get metrics with partitioning support"""
        async with DB_OPERATION_DURATION.labels('select', 'system_metrics').time():
            async with self.async_session() as session:
                table_name = f"system_metrics_{partition}" if partition != 'current' else "system_metrics"
                result = await session.execute(
                    text(f"""
                        SELECT * FROM {table_name}
                        WHERE timestamp BETWEEN :start AND :end
                        ORDER BY timestamp DESC
                    """),
                    {"start": start_time, "end": end_time}
                )
                DB_OPERATIONS.labels('select', 'system_metrics').inc()
                return result.mappings().all()
    
    async def partition_historical_data(self, table: str, partition_date: datetime):
        """Create a new partition for historical data"""
        async with self.async_session() as session:
            # Create partition table
            partition_name = f"{table}_{partition_date.strftime('%Y%m')}"
            await session.execute(text(f"""
                CREATE TABLE IF NOT EXISTS {partition_name} AS 
                SELECT * FROM {table}
                WHERE timestamp >= :start_date 
                AND timestamp < :end_date
            """), {
                "start_date": partition_date,
                "end_date": partition_date + timedelta(days=30)
            })
            
            # Move data to partition and delete from main table
            await session.execute(text(f"""
                DELETE FROM {table}
                WHERE timestamp >= :start_date 
                AND timestamp < :end_date
            """), {
                "start_date": partition_date,
                "end_date": partition_date + timedelta(days=30)
            })
            
            await session.commit()
    
    async def cleanup_old_partitions(self, months_to_keep: int):
        """Remove old partitions beyond retention period"""
        async with self.async_session() as session:
            # Get list of all tables
            result = await session.execute(text("""
                SELECT name FROM sqlite_master 
                WHERE type='table' 
                AND name LIKE 'system_metrics_%'
                OR name LIKE 'network_connections_%'
            """))
            tables = result.scalars().all()
            
            cutoff_date = datetime.now() - timedelta(days=30 * months_to_keep)
            
            for table in tables:
                try:
                    table_date = datetime.strptime(table.split('_')[-1], '%Y%m')
                    if table_date < cutoff_date:
                        await session.execute(text(f"DROP TABLE {table}"))
                except ValueError:
                    continue  # Skip if table name doesn't match expected format
            
            await session.commit()
    
    async def get_partition_stats(self) -> Dict[str, Any]:
        """Get statistics about current partitions"""
        async with self.async_session() as session:
            result = await session.execute(text("""
                SELECT name, 
                       (SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name=name) as index_count,
                       (SELECT COUNT(*) FROM name) as row_count
                FROM sqlite_master 
                WHERE type='table' 
                AND (name LIKE 'system_metrics_%'
                     OR name LIKE 'network_connections_%'
                     OR name = 'system_metrics'
                     OR name = 'network_connections')
            """))
            
            stats = {}
            for row in result.mappings():
                stats[row['name']] = {
                    'index_count': row['index_count'],
                    'row_count': row['row_count']
                }
            return stats
