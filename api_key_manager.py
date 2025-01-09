"""Secure API key management module."""

import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class APIKeyManager:
    def __init__(self, keys_dir=None):
        if keys_dir is None:
            keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.keys')
        self.keys_dir = Path(keys_dir)
        self.keys_file = self.keys_dir / 'api_keys.enc'
        self.salt_file = self.keys_dir / 'salt'
        
        # Ensure keys directory exists
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load salt
        if not self.salt_file.exists():
            self.salt = os.urandom(16)
            self.salt_file.write_bytes(self.salt)
        else:
            self.salt = self.salt_file.read_bytes()
        
        # Initialize encryption key
        self._init_encryption_key()

    def _init_encryption_key(self):
        """Initialize the encryption key using system-specific data."""
        # Use machine-specific data as key material
        machine_id = self._get_machine_id()
        
        # Generate key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
        self.cipher_suite = Fernet(key)

    def _get_machine_id(self):
        """Get a unique machine identifier."""
        # Try to get system UUID on macOS
        try:
            import subprocess
            result = subprocess.run(['system_profiler', 'SPHardwareDataType'], 
                                 capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Hardware UUID' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        
        # Fallback to using hostname
        return os.uname().nodename

    def store_key(self, key_name: str, key_value: str):
        """Securely store an API key."""
        # Load existing keys
        keys = self.load_keys()
        
        # Update or add new key
        keys[key_name] = key_value
        
        # Encrypt and save
        encrypted_data = self.cipher_suite.encrypt(json.dumps(keys).encode())
        self.keys_file.write_bytes(encrypted_data)

    def load_keys(self) -> dict:
        """Load all stored API keys."""
        if not self.keys_file.exists():
            return {}
        
        try:
            encrypted_data = self.keys_file.read_bytes()
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            print(f"Error loading API keys: {e}")
            return {}

    def get_key(self, key_name: str, default=None) -> str:
        """Get an API key by name."""
        # First check environment variable
        env_key = os.environ.get(f"SYSDAEMON_{key_name.upper()}")
        if env_key:
            return env_key
        
        # Then check stored keys
        keys = self.load_keys()
        return keys.get(key_name, default)

    def delete_key(self, key_name: str):
        """Delete an API key."""
        keys = self.load_keys()
        if key_name in keys:
            del keys[key_name]
            encrypted_data = self.cipher_suite.encrypt(json.dumps(keys).encode())
            self.keys_file.write_bytes(encrypted_data)
