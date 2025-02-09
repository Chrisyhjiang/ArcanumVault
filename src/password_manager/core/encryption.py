from abc import ABC, abstractmethod
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class EncryptionService(ABC):
    """Abstract base class for encryption services."""
    
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt the given data."""
        pass
    
    @abstractmethod
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt the given data."""
        pass

class AES256Encryption(EncryptionService):
    """AES-256 encryption implementation with proper key derivation."""
    
    def __init__(self, master_key: Optional[bytes] = None, salt: Optional[bytes] = None):
        """Initialize with an optional master key and salt."""
        self._master_key = master_key or os.urandom(32)  # 256-bit key
        self._salt = salt or os.urandom(16)
        self._key = self._derive_key()
    
    def _derive_key(self) -> bytes:
        """Derive an encryption key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=self._salt,
            iterations=100000,
        )
        return kdf.derive(self._master_key)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256 in GCM mode."""
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv),
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Combine IV, ciphertext, and tag
        return base64.b64encode(iv + encryptor.tag + ciphertext)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-256 in GCM mode."""
        # Decode and split the components
        raw_data = base64.b64decode(encrypted_data)
        iv = raw_data[:12]
        tag = raw_data[12:28]
        ciphertext = raw_data[28:]
        
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
        )
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    @property
    def key(self) -> bytes:
        return self._master_key
    
    @property
    def salt(self) -> bytes:
        return self._salt

