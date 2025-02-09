from abc import ABC, abstractmethod
from typing import Optional
import hashlib
import os
from pathlib import Path
import base64
import click

class AuthenticationService(ABC):
    """Abstract base class for authentication services."""
    
    @abstractmethod
    def authenticate(self, password: str) -> bool:
        """Authenticate using the given password."""
        pass
    
    @abstractmethod
    def set_master_password(self, password: str) -> None:
        """Set or update the master password."""
        pass

class HashBasedAuth(AuthenticationService):
    """Simple hash-based authentication implementation."""
    
    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._hash_path = self.storage_path / 'master.hash'
    
    def authenticate(self, password: str) -> bool:
        """Verify the provided password against stored hash."""
        if not self._hash_path.exists():
            return False
        
        stored_data = self._hash_path.read_text()
        stored_salt, stored_hash = stored_data.split(':')
        return self._hash_password(password, base64.b64decode(stored_salt)) == stored_hash
    
    def set_master_password(self, password: str) -> None:
        """Set a new master password."""
        if self._hash_path.exists():
            current_password = click.prompt("Enter current master password", hide_input=True)
            if not self.authenticate(current_password):
                click.echo("Authentication failed. Cannot reset master password.")
                return
        
        salt = os.urandom(16)
        password_hash = self._hash_password(password, salt)
        self._hash_path.write_text(f"{base64.b64encode(salt).decode()}:{password_hash}")
        click.echo("Master password set successfully.")
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """Create a secure hash of the password."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000  # Number of iterations
        ).hex()

# ... rest of the auth.py content ... 