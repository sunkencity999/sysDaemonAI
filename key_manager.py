from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

class KeyManager:
    def __init__(self, key_dir='keys'):
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)
        self.private_key_path = os.path.join(self.key_dir, 'private_key.pem')
        self.public_key_path = os.path.join(self.key_dir, 'public_key.pem')

    def generate_keys(self):
        """Generate a new RSA public/private key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Save private key
        with open(self.private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL
            ))

        # Save public key
        with open(self.public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print(f"Keys generated and saved to {self.key_dir}")

    def load_private_key(self):
        """Load the private key from a file."""
        if not os.path.exists(self.private_key_path):
            self.generate_keys()  # Generate keys if they do not exist
        with open(self.private_key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

    def load_public_key(self):
        """Load the public key from a file."""
        if not os.path.exists(self.public_key_path):
            self.generate_keys()  # Generate keys if they do not exist
        with open(self.public_key_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
