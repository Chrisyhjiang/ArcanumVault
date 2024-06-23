import os
import base64
import logging
import threading
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .constants import SECURE_KEY_FILE, SALT_FILE, CURRENT_DIRECTORY_FILE, DATA_DIR, MASTER_PASSWORD_FILE
from .password_operations import reencrypt_passwords

# Setup logging to redirect to a file
logging.basicConfig(filename='vault.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Logging initialized")  # Initial log message to verify logging setup

# Global lock for synchronizing key operations
key_lock = threading.Lock()

def decrypt_master_password():
    """Decrypt and return the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_password = f.read()
    password = fernet.decrypt(encrypted_password).decode()
    return password

def load_secure_key():
    """Load the secure key from the file."""
    if SECURE_KEY_FILE.exists():
        with open(SECURE_KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        return generate_secure_key()

def generate_secure_key():
    """Generate and store a secure key for encryption."""
    key = Fernet.generate_key()
    with open(SECURE_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    set_permissions(SECURE_KEY_FILE)
    return key

def set_permissions(path):
    """Set secure permissions for the file."""
    os.chmod(path, 0o600)  # Owner can read and write

def generate_salt():
    """Generate a random salt and save it to a file."""
    salt = os.urandom(16)  # Generate a 16-byte salt
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    set_permissions(SALT_FILE)
    return salt

def load_salt():
    """Load the salt from the file, generating it if it doesn't exist."""
    if not SALT_FILE.exists():
        return generate_salt()
    with open(SALT_FILE, 'rb') as f:
        return f.read()

# Load the salt (generate it if it doesn't exist)
fixed_salt = load_salt()

def derive_key(password: str):
    global fixed_salt  # Access the global variable
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=fixed_salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    derived_key_b64 = base64.urlsafe_b64encode(derived_key)
    logging.debug(f"Derived key: {derived_key_b64}")
    return derived_key_b64

def load_current_directory():
    if CURRENT_DIRECTORY_FILE.exists():
        with open(CURRENT_DIRECTORY_FILE, 'r') as f:
            return Path(f.read().strip())
    return DATA_DIR

def save_current_directory(current_directory):
    with open(CURRENT_DIRECTORY_FILE, 'w') as f:
        f.write(str(current_directory))

def get_password_file_path(domain, folder=None):
    current_dir = load_current_directory()
    if folder:
        target_dir = (current_dir / folder).resolve()
    else:
        target_dir = current_dir
    return target_dir / f"{domain}.pass"

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

# Instantiate the cipher singleton
cipher_singleton = CipherSingleton()
