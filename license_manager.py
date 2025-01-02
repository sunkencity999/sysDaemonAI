import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from pathlib import Path
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

class KeyManager:
    def __init__(self):
        self.private_key_file = Path.home() / '.sysdaemonai' / 'private_key.pem'
        self.public_key_file = Path.home() / '.sysdaemonai' / 'public_key.pem'
        self.private_key_file.parent.mkdir(exist_ok=True)

    def generate_keys(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.private_key_file, 'wb') as f:
            f.write(private_pem)
        with open(self.public_key_file, 'wb') as f:
            f.write(public_pem)

    def load_private_key(self):
        if not self.private_key_file.exists():
            self.generate_keys()
        with open(self.private_key_file, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    def load_public_key(self):
        if not self.public_key_file.exists():
            self.generate_keys()
        with open(self.public_key_file, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key


class LicenseManager:
    def __init__(self):
        self.key_manager = KeyManager()
        self.license_file = Path.home() / '.sysdaemonai' / 'license.dat'
        self.license_file.parent.mkdir(exist_ok=True)
        self.public_key = self.key_manager.load_public_key()
        self.private_key = self.key_manager.load_private_key()

    def _get_system_info(self) -> str:
        """Get unique system identifier."""
        if os.path.exists('/etc/machine-id'):
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()
        elif os.path.exists('/var/lib/dbus/machine-id'):
            with open('/var/lib/dbus/machine-id', 'r') as f:
                return f.read().strip()
        else:
            # Fallback to MAC address
            import uuid
            return str(uuid.getnode())

    def generate_license_key(self, tier: str, duration_days: int) -> str:
        """Generate a new license key."""
        if tier not in ['individual', 'professional', 'enterprise', 'administrator']:
            raise ValueError("Invalid tier specified.")
        license_data = {
            'id': str(uuid.uuid4()),
            'tier': tier,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'duration_days': duration_days,
            'hardware_id': self._get_system_info()
        }
        
        # Convert to string and sign
        license_str = json.dumps(license_data).encode()
        signature = self.private_key.sign(
            license_str,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Combine the license data and signature
        license_package = {
            'license_data': license_data,
            'signature': base64.urlsafe_b64encode(signature).decode()
        }
        return json.dumps(license_package)

    def validate_license(self) -> Dict:
        """Validate the current license."""
        if not self.license_file.exists():
            raise ValueError("No license file found")

        try:
            with open(self.license_file, 'r') as f:
                license_package = json.loads(f.read())
                license_data = license_package['license_data']
                signature = base64.urlsafe_b64decode(license_package['signature'])

            # Verify the signature
            self.public_key.verify(
                signature,
                json.dumps(license_data).encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            # Check hardware ID
            if license_data['hardware_id'] != self._get_system_info():
                raise ValueError("Invalid hardware ID")

            # Check expiration
            created_at = datetime.fromisoformat(license_data['created_at'])
            expiration = created_at.replace(tzinfo=timezone.utc) + \
                        timedelta(days=license_data['duration_days'])
            
            if datetime.now(timezone.utc) > expiration:
                raise ValueError("License expired")

            return {
                'valid': True,
                'tier': license_data['tier'],
                'expires_at': expiration.isoformat()
            }

        except InvalidSignature:
            return {
                'valid': False,
                'error': 'Invalid signature'
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }

    def install_license(self, license_key: str) -> Dict:
        """Install a new license key."""
        try:
            # Save the license key
            with open(self.license_file, 'w') as f:
                f.write(license_key)

            return {
                'status': 'success',
                'message': 'License installed successfully'
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_license_info(self) -> Optional[Dict]:
        """Get current license information."""
        try:
            return self.validate_license()
        except:
            return None
