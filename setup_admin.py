#!/usr/bin/env python3
import os
import sys
import logging
from auth_manager import AuthManager
from database import DatabaseManager
from logging_config import setup_logging

def setup_admin_user():
    # Setup logging
    setup_logging(app_name='setup_admin')
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize managers
        db_manager = DatabaseManager()
        auth_manager = AuthManager(db_manager)
        
        # Check if admin user already exists
        admin_exists = db_manager.fetch_one(
            "SELECT id FROM users WHERE username = :username",
            {"username": "Admin"}
        )
        
        if admin_exists:
            logger.info("Admin user already exists")
            return True
            
        # Create admin user
        success = auth_manager.create_user(
            username="Admin",
            password="sysdaemonAI",
            role="admin"
        )
        
        if success:
            logger.info("Successfully created admin user")
            return True
        else:
            logger.error("Failed to create admin user")
            return False
            
    except Exception as e:
        logger.error(f"Error setting up admin user: {str(e)}")
        return False

if __name__ == "__main__":
    if setup_admin_user():
        print("Successfully set up admin user")
        sys.exit(0)
    else:
        print("Failed to set up admin user")
        sys.exit(1)
