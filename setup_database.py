#!/usr/bin/env python3
import os
import sys
import sqlite3
import logging
from logging_config import setup_logging
from database import DatabaseManager

def init_database():
    # Setup logging
    setup_logging(app_name='setup_database')
    logger = logging.getLogger(__name__)
    
    try:
        # Use home directory for database
        home_dir = os.path.expanduser("~")
        data_dir = os.path.join(home_dir, '.sysdaemonai', 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Database path
        db_path = os.path.join(data_dir, 'sysdaemon.db')
        
        # Create database and set permissions
        conn = sqlite3.connect(db_path)
        
        # Create users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                role TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Create sessions table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create access_logs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create roles table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                permissions JSON NOT NULL,
                created_at DATETIME NOT NULL
            )
        """)
        
        # Create user_roles table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
        """)
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        # Set file permissions
        os.chmod(db_path, 0o644)
        
        logger.info(f"Successfully initialized database at {db_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

if __name__ == "__main__":
    if init_database():
        print("Successfully initialized database")
        # Now create the admin user
        os.system(f"{sys.executable} setup_admin.py")
    else:
        print("Failed to initialize database")
        sys.exit(1)
