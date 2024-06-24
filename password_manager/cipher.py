import threading
from cryptography.fernet import Fernet
from .utils import derive_key, reencrypt_passwords, decrypt_master_password
class CipherSingleton:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(CipherSingleton, cls).__new__(cls)
                    cls._instance._cipher_initialized = False
                    try:
                        cls._instance._initialize_cipher()
                    except FileNotFoundError:
                        cls._instance.cipher = None
        return cls._instance

    def _initialize_cipher(self):
        self.cipher = self._create_cipher()
        self._cipher_initialized = True

    def _create_cipher(self):
        password = decrypt_master_password()
        key = derive_key(password)
        return Fernet(key)

    def get_cipher(self):
        if not self._cipher_initialized:
            raise ValueError("Cipher not initialized. Run 'vault set-master-password' to set it.")
        return self.cipher

    def refresh_cipher(self):
        with self._lock:
            old_cipher = self.cipher
            self.cipher = self._create_cipher()
            self._cipher_initialized = True
            reencrypt_passwords(old_cipher, self.cipher)
