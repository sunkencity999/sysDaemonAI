#!/usr/bin/env python3
import asyncio
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
from prometheus_client import start_http_server
import signal
import sys
from typing import Optional
from async_database import AsyncDatabaseManager
from partition_manager import PartitionManager
from network_monitor import NetworkMonitor
import threading

class MonitoringSystem:
    def __init__(self):
        self.logger = self._setup_logging()
        self.db_manager: Optional[AsyncDatabaseManager] = None
        self.partition_manager: Optional[PartitionManager] = None
        self.network_monitor: Optional[NetworkMonitor] = None
        self.running = True
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logger = logging.getLogger("MonitoringSystem")
        logger.setLevel(logging.INFO)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_dir / "monitoring.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}. Initiating shutdown...")
        self.running = False
        
        # Stop the network monitor
        if self.network_monitor:
            self.network_monitor.stop()
        
        # Stop the event loop
        loop = asyncio.get_event_loop()
        loop.stop()
    
    async def _start_prometheus(self):
        """Start Prometheus metrics server"""
        try:
            start_http_server(9090)
            self.logger.info("Started Prometheus metrics server on port 9090")
        except Exception as e:
            self.logger.error(f"Failed to start Prometheus server: {str(e)}")
            raise
    
    async def _initialize_database(self):
        """Initialize database components"""
        try:
            self.logger.info("Initializing database manager...")
            self.db_manager = AsyncDatabaseManager()
            
            self.logger.info("Initializing partition manager...")
            self.partition_manager = PartitionManager(self.db_manager)
            self.partition_manager.start()
            
            self.logger.info("Database components initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database components: {str(e)}")
            raise
    
    def _start_network_monitor(self):
        """Start the network monitoring component"""
        try:
            self.logger.info("Starting network monitor...")
            self.network_monitor = NetworkMonitor(
                async_db_manager=self.db_manager
            )
            self.network_monitor.start()
            self.logger.info("Network monitor started successfully")
        except Exception as e:
            self.logger.error(f"Failed to start network monitor: {str(e)}")
            raise
    
    async def startup(self):
        """Main startup sequence"""
        try:
            self.logger.info("Starting monitoring system...")
            
            # Start Prometheus metrics server
            await self._start_prometheus()
            
            # Initialize database components
            await self._initialize_database()
            
            # Start network monitor in a separate thread
            monitor_thread = threading.Thread(
                target=self._start_network_monitor
            )
            monitor_thread.start()
            
            self.logger.info("Monitoring system startup complete")
            
            # Keep the async event loop running
            while self.running:
                await asyncio.sleep(1)
            
        except Exception as e:
            self.logger.error(f"Error during startup: {str(e)}")
            raise
        finally:
            self.logger.info("Monitoring system shutdown complete")
    
    @classmethod
    def run(cls):
        """Class method to run the monitoring system"""
        monitor = cls()
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(monitor.startup())
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()

if __name__ == "__main__":
    MonitoringSystem.run()
