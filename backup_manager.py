#!/usr/bin/env python3
import os
import shutil
import logging
import tarfile
from datetime import datetime
import schedule
import time
import threading
from typing import List, Optional
from advanced_config import AdvancedConfig

class BackupManager:
    def __init__(self):
        self.config = AdvancedConfig()
        self.logger = logging.getLogger('BackupManager')
        self.backup_thread = None
        self.stop_flag = threading.Event()
        
        # Create backup directory if it doesn't exist
        self.backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        os.makedirs(self.backup_dir, exist_ok=True)

    def start(self):
        """Start the backup manager in a separate thread"""
        if not self.config.get('backup', 'enabled'):
            self.logger.info("Backup manager is disabled in configuration")
            return

        if self.backup_thread and self.backup_thread.is_alive():
            self.logger.warning("Backup manager is already running")
            return

        self.stop_flag.clear()
        self.backup_thread = threading.Thread(target=self._run_scheduler)
        self.backup_thread.daemon = True
        self.backup_thread.start()
        self.logger.info("Backup manager started")

    def stop(self):
        """Stop the backup manager"""
        if self.backup_thread and self.backup_thread.is_alive():
            self.stop_flag.set()
            self.backup_thread.join()
            self.logger.info("Backup manager stopped")

    def _run_scheduler(self):
        """Run the backup scheduler"""
        interval_hours = self.config.get('backup', 'interval_hours')
        schedule.every(interval_hours).hours.do(self.create_backup)
        
        # Run initial backup
        self.create_backup()
        
        while not self.stop_flag.is_set():
            schedule.run_pending()
            time.sleep(60)

    def create_backup(self) -> Optional[str]:
        """Create a new backup of specified directories"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'sysdaemon_backup_{timestamp}.tar.gz'
            backup_path = os.path.join(self.backup_dir, backup_filename)
            
            # Get paths to backup from config
            backup_paths = self.config.get('backup', 'backup_paths')
            
            # Create compressed tar archive
            with tarfile.open(backup_path, 'w:gz') as tar:
                for path in backup_paths:
                    abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
                    if os.path.exists(abs_path):
                        tar.add(abs_path, arcname=os.path.basename(path))
                    else:
                        self.logger.warning(f"Backup path does not exist: {abs_path}")
            
            self.cleanup_old_backups()
            self.logger.info(f"Backup created successfully: {backup_filename}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {str(e)}")
            return None

    def cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        try:
            retention_count = self.config.get('backup', 'retention_count')
            backups = self._get_existing_backups()
            
            if len(backups) > retention_count:
                backups_to_delete = backups[:-retention_count]
                for backup in backups_to_delete:
                    os.remove(backup)
                    self.logger.info(f"Removed old backup: {os.path.basename(backup)}")
                    
        except Exception as e:
            self.logger.error(f"Failed to cleanup old backups: {str(e)}")

    def restore_backup(self, backup_path: str) -> bool:
        """Restore from a specific backup file"""
        try:
            if not os.path.exists(backup_path):
                self.logger.error(f"Backup file does not exist: {backup_path}")
                return False
                
            # Create temporary extraction directory
            temp_dir = os.path.join(self.backup_dir, 'temp_restore')
            os.makedirs(temp_dir, exist_ok=True)
            
            # Extract backup
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            # Restore each backed up directory
            base_dir = os.path.dirname(os.path.abspath(__file__))
            for item in os.listdir(temp_dir):
                source = os.path.join(temp_dir, item)
                destination = os.path.join(base_dir, item)
                
                if os.path.exists(destination):
                    shutil.rmtree(destination)
                shutil.move(source, destination)
            
            # Cleanup temporary directory
            shutil.rmtree(temp_dir)
            
            self.logger.info(f"Successfully restored from backup: {os.path.basename(backup_path)}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore backup: {str(e)}")
            return False

    def _get_existing_backups(self) -> List[str]:
        """Get list of existing backup files sorted by creation time"""
        backups = []
        for filename in os.listdir(self.backup_dir):
            if filename.startswith('sysdaemon_backup_') and filename.endswith('.tar.gz'):
                backup_path = os.path.join(self.backup_dir, filename)
                backups.append(backup_path)
        
        return sorted(backups, key=os.path.getctime)
