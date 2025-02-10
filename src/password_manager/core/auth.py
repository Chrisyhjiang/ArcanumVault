# password_manager/core/auth.py

from abc import ABC, abstractmethod
from pathlib import Path
import hashlib
import os
import base64
import logging

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
    
    def __init__(self, master_password_file: Path):
        self.master_password_file = master_password_file
        self.salt_file = master_password_file.parent / 'salt'
        self._master_key = None
        self._salt = self._load_or_create_salt()
    
    def get_master_key(self) -> bytes:
        if self._master_key is None:
            raise ValueError("No master key available. Please authenticate first.")
        return self._master_key
    
    def _load_or_create_salt(self) -> bytes:
        """Load the stored salt from file (stripping whitespace) or create a new one."""
        if self.salt_file.exists():
            return base64.b64decode(self.salt_file.read_text().strip())
        salt = os.urandom(16)
        self.salt_file.parent.mkdir(parents=True, exist_ok=True)
        self.salt_file.write_text(base64.b64encode(salt).decode())
        # Set file permission to read/write for owner only
        os.chmod(self.salt_file, 0o600)
        return salt

    @property
    def salt(self) -> bytes:
        """Expose the persisted salt."""
        return self._salt

    def _hash_password(self, password: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self._salt,
            100000,
            dklen=32
        )
    
    def authenticate(self, password: str) -> bool:
        if not self.master_password_file.exists():
            return False
        stored_hash = self.master_password_file.read_text().strip()
        password_hash = self._hash_password(password)
        logging.debug(f"Stored hash: {stored_hash}, Computed hash: {base64.b64encode(password_hash).decode()}")
        logging.debug(f"Using salt: {base64.b64encode(self._salt).decode()}")
        if base64.b64encode(password_hash).decode() == stored_hash:
            self._master_key = password_hash
            logging.debug(f"Authentication successful, master key: {self._master_key.hex()}")
            return True
        return False
    
    def set_master_password(self, password: str) -> None:
        password_hash = self._hash_password(password)
        self._master_key = password_hash
        self.master_password_file.parent.mkdir(parents=True, exist_ok=True)
        self.master_password_file.write_text(base64.b64encode(password_hash).decode())
        # Set file permission to read/write for owner only
        os.chmod(self.master_password_file, 0o600)
