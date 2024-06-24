import os
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from ctypes import CDLL, c_void_p, c_long
import threading
import logging
import base64

# Setup logging to redirect to a file
logging.basicConfig(filename='vault.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Logging initialized")  # Initial log message to verify logging setup

# Setup directories and files
DATA_DIR = Path.home() / ".password_manager" / "data"
SECURE_KEY_FILE = Path.home() / ".password_manager" / "secure_key.key"
MASTER_PASSWORD_FILE = Path.home() / ".password_manager" / "master_password.enc"
SESSION_FILE = Path.home() / ".password_manager" / ".session"
CURRENT_DIRECTORY_FILE = Path.home() / ".password_manager" / ".current_directory"
SALT_FILE = Path.home() / ".password_manager" / "salt"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SESSION_TIMEOUT = 3600  # Set session timeout to 3600 seconds (1 hour)

if os.uname().sysname == "Darwin":
    import objc
    from Foundation import NSObject
    from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthenticationWithBiometrics

libdispatch = CDLL('/usr/lib/system/libdispatch.dylib')
libdispatch.dispatch_semaphore_create.argtypes = [c_long]
libdispatch.dispatch_semaphore_create.restype = c_void_p
libdispatch.dispatch_semaphore_wait.argtypes = [c_void_p, c_long]
libdispatch.dispatch_semaphore_wait.restype = c_long
libdispatch.dispatch_semaphore_signal.argtypes = [c_void_p]
libdispatch.dispatch_semaphore_signal.restype = c_long

# Global lock for synchronizing key operations
key_lock = threading.Lock()

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

def reencrypt_passwords(old_cipher, new_cipher):
    for root, _, files in os.walk(DATA_DIR):
        for file in files:
            if file.endswith('.pass'):
                file_path = Path(root) / file
                with open(file_path, 'r') as f:
                    lines = f.read().splitlines()
                    if len(lines) < 4:
                        click.echo(f"Invalid password file format for {file_path.stem}. Skipping.")
                        continue
                    description = lines[1]
                    user_id = lines[2]
                    encrypted_password = lines[3].encode()
                    try:
                        decrypted_password = old_cipher.decrypt(encrypted_password)
                    except InvalidToken:
                        click.echo(f"Failed to decrypt {file_path.stem}. Skipping.")
                        continue
                    new_encrypted_password = new_cipher.encrypt(decrypted_password)
                    password_entry = f"{lines[0]}\n{description}\n{user_id}\n{new_encrypted_password.decode()}"
                    with open(file_path, 'w') as f:
                        f.write(password_entry)
    logging.info("Re-encryption with new master password completed.")

def decrypt_master_password():
    """Decrypt and return the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_password = f.read()
    password = fernet.decrypt(encrypted_password).decode()
    return password

