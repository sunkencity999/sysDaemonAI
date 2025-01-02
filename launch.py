#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import subprocess
import logging
from monitor_startup import MonitoringSystem

def setup_logging():
    """Set up basic logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger("Launcher")

def check_environment():
    """Check if the environment is properly set up"""
    logger = logging.getLogger("Launcher")
    
    # Check Python version
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 or higher is required")
        sys.exit(1)
    
    # Check if virtual environment is activated
    if not hasattr(sys, 'real_prefix') and not sys.base_prefix != sys.prefix:
        logger.warning("Virtual environment is not activated. It's recommended to run in a virtual environment")
    
    # Check for required directories
    required_dirs = ['logs', 'data']
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            logger.info(f"Creating {dir_name} directory")
            dir_path.mkdir(parents=True)

def main():
    """Main entry point for the application"""
    logger = setup_logging()
    
    try:
        # Check environment
        check_environment()
        
        # Start the monitoring system
        logger.info("Starting monitoring system...")
        MonitoringSystem.run()
        
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
