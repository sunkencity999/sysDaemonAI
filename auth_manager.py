#!/usr/bin/env python3
import jwt
import bcrypt
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict
from database import DatabaseManager
from logging_config import setup_logging

class AuthManager:
    def __init__(self, db_manager: DatabaseManager = None):
        setup_logging(app_name='auth_manager')
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager or DatabaseManager()
        self.secret_key = self._load_or_generate_secret()
        
    def _load_or_generate_secret(self) -> str:
        """Load existing secret key or generate a new one"""
        try:
            with open('.secret_key', 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            import secrets
            secret = secrets.token_hex(32)
            with open('.secret_key', 'w') as f:
                f.write(secret)
            return secret
    
    def create_user(self, username: str, password: str, role: str = 'analyst') -> bool:
        """Create a new user with hashed password"""
        try:
            # Hash password with bcrypt
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode(), salt)
            
            # Check if user exists
            existing_user = self.db_manager.fetch_one(
                "SELECT username FROM users WHERE username = :username",
                {"username": username}
            )
            
            if existing_user:
                self.logger.warning(f"User {username} already exists")
                return False
            
            # Store in database
            self.db_manager.execute(
                """INSERT INTO users (username, password_hash, role, created_at) 
                   VALUES (:username, :password_hash, :role, :created_at)""",
                {
                    "username": username,
                    "password_hash": hashed,
                    "role": role,
                    "created_at": datetime.now()
                }
            )
            self.logger.info(f"Created new user: {username}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create user: {str(e)}")
            return False

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token if successful"""
        try:
            result = self.db_manager.fetch_one(
                "SELECT password_hash, role FROM users WHERE username = :username",
                {"username": username}
            )
            
            if not result:
                return None
                
            stored_hash, role = result
            
            if bcrypt.checkpw(password.encode(), stored_hash):
                # Generate JWT token
                token = jwt.encode({
                    'username': username,
                    'role': role,
                    'exp': datetime.utcnow() + timedelta(hours=8)
                }, self.secret_key, algorithm='HS256')
                
                self.logger.info(f"Successful authentication for user: {username}")
                return token
            
            self.logger.warning(f"Failed authentication attempt for user: {username}")
            return None
            
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return None
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload if valid"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("Expired token")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid token: {str(e)}")
            return None
    
    def check_permission(self, token: str, required_role: str) -> bool:
        """Check if user has required role"""
        payload = self.verify_token(token)
        if not payload:
            return False
            
        user_role = payload.get('role')
        role_hierarchy = {
            'admin': 3,
            'analyst': 2,
            'viewer': 1
        }
        
        return role_hierarchy.get(user_role, 0) >= role_hierarchy.get(required_role, 0)

    def register(self, username: str, password: str) -> bool:
        """Register a new user with default role 'viewer'"""
        return self.create_user(username, password, role='viewer')
