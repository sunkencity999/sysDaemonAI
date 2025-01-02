#!/usr/bin/env python3
from datetime import datetime, timedelta
import asyncio
import logging
from typing import Optional, List
from async_database import AsyncDatabaseManager

class PartitionManager:
    def __init__(self, db_manager: AsyncDatabaseManager):
        self.logger = logging.getLogger(__name__)
        self.db = db_manager
        self.partition_interval = timedelta(days=30)  # Monthly partitions
        self.retention_months = 12  # Keep 1 year of data
        
    async def create_partition(self, table_name: str, start_date: datetime) -> bool:
        """Create a new partition for the specified table and date range"""
        try:
            await self.db.partition_historical_data(table_name, start_date)
            self.logger.info(f"Created partition for {table_name} starting {start_date}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create partition: {str(e)}")
            return False
    
    async def manage_partitions(self):
        """Main partition management routine"""
        while True:
            try:
                # Get current partition statistics
                stats = await self.db.get_partition_stats()
                
                # Check if we need to create new partitions
                current_month_start = datetime.now().replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )
                
                # Create partitions for tables if needed
                for table in ['system_metrics', 'network_connections']:
                    if f"{table}_{current_month_start.strftime('%Y%m')}" not in stats:
                        await self.create_partition(table, current_month_start)
                
                # Cleanup old partitions
                await self.db.cleanup_old_partitions(self.retention_months)
                
                # Log partition statistics
                self.logger.info(f"Current partition stats: {stats}")
                
                # Wait for next check (daily)
                await asyncio.sleep(24 * 60 * 60)
            
            except Exception as e:
                self.logger.error(f"Error in partition management: {str(e)}")
                await asyncio.sleep(300)  # Retry after 5 minutes on error
    
    async def get_data_from_partitions(self, table_name: str, 
                                     start_date: datetime,
                                     end_date: datetime) -> List[dict]:
        """Retrieve data across partitions"""
        results = []
        current_date = start_date
        
        while current_date <= end_date:
            partition_name = f"{table_name}_{current_date.strftime('%Y%m')}"
            
            # Get data from this partition
            partition_data = await self.db.get_metrics_range(
                start_date,
                end_date,
                partition=current_date.strftime('%Y%m')
            )
            results.extend(partition_data)
            
            # Move to next month
            current_date = (current_date.replace(day=1) + timedelta(days=32)).replace(day=1)
        
        return results
    
    def start(self):
        """Start the partition manager"""
        asyncio.create_task(self.manage_partitions())
