# password_manager/core/encryption.py

import os
import base64
import logging
from typing import Optional
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

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
    
    def __init__(self, master_key: bytes, salt: Optional[bytes] = None):
        """
        Initialize with the master key and a provided salt.
        If no salt is given, a new one is generated.
        """
        self._master_key = master_key
        self._salt = salt if salt is not None else os.urandom(16)
        self._key = self._derive_key()
        logging.debug(f"Initialized AES256Encryption with key: {self._key.hex()} and salt: {self._salt.hex()}")
    
    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
        )
        return kdf.derive(self._master_key)
    
    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        logging.debug(f"Encrypted data with IV: {iv.hex()}, Tag: {encryptor.tag.hex()}, Ciphertext: {ciphertext.hex()}")
        # Combine IV, tag, and ciphertext; then base64-encode
        return base64.b64encode(iv + encryptor.tag + ciphertext)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        raw_data = base64.b64decode(encrypted_data)
        iv = raw_data[:12]
        tag = raw_data[12:28]
        ciphertext = raw_data[28:]
        logging.debug(f"Decrypting data with IV: {iv.hex()}, Tag: {tag.hex()}, Ciphertext length: {len(ciphertext)}")
        logging.debug(f"Using key: {self._key.hex()}")
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
        )
        decryptor = cipher.decryptor()
        try:
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            logging.debug(f"Decryption successful, plaintext: {decrypted_data.decode(errors='ignore')}")
            return decrypted_data
        except InvalidTag as e:
            logging.error("Decryption failed due to invalid tag", exc_info=e)
            raise

    @property
    def key(self) -> bytes:
        return self._master_key
    
    @property
    def salt(self) -> bytes:
        return self._salt
