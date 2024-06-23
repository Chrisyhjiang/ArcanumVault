import click
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import time
import uuid
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

def decrypt_master_password():
    """Decrypt and return the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_password = f.read()
    password = fernet.decrypt(encrypted_password).decode()
    return password

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

# Define the CipherSingleton class
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

def encrypt_master_password(password: str):
    """Encrypt and store the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    encrypted_password = fernet.encrypt(password.encode())
    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_password)
    set_permissions(MASTER_PASSWORD_FILE)
    logging.info("Master password stored in encrypted form on disk.")

def load_current_directory():
    if CURRENT_DIRECTORY_FILE.exists():
        with open(CURRENT_DIRECTORY_FILE, 'r') as f:
            return Path(f.read().strip())
    return DATA_DIR

def save_current_directory(current_directory):
    with open(CURRENT_DIRECTORY_FILE, 'w') as f:
        f.write(str(current_directory))

def authenticate_fingerprint_mac():
    """Authenticate the user using fingerprint on macOS."""
    context = LAContext.alloc().init()
    success, error = context.canEvaluatePolicy_error_(LAPolicyDeviceOwnerAuthenticationWithBiometrics, None)
    
    if success:
        click.echo("Please authenticate using your fingerprint...")
        semaphore = libdispatch.dispatch_semaphore_create(0)
        
        def callback(_success, _error):
            nonlocal authenticated
            if _success:
                authenticated = True
            else:
                click.echo(f"Fingerprint authentication error: {_error}")
                authenticated = False
            libdispatch.dispatch_semaphore_signal(semaphore)

        authenticated = False
        context.evaluatePolicy_localizedReason_reply_(
            LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            "Authenticate to access password manager",
            callback
        )
        libdispatch.dispatch_semaphore_wait(semaphore, c_long(-1))
        return authenticated
    else:
        click.echo(f"Fingerprint authentication not available: {error}")
        return False

def authenticate_user():
    try:
        username = os.getlogin()
        if username == 'root':
            username = getpass.getuser()
    except Exception:
        username = getpass.getuser()

    choice = click.prompt('Choose authentication method: [P]assword/[F]ingerprint', type=str).lower()

    if choice == 'p':
        stored_master_password = decrypt_master_password()
        password = click.prompt('Master Password', hide_input=True)
        if password != stored_master_password:
            click.echo("Authentication failed.")
            exit(1)
        else:
            click.echo("Authentication succeeded.")
            with open(SESSION_FILE, 'w') as f:
                f.write(str(int(time.time())))
    elif choice == 'f':
        if os.uname().sysname == "Darwin":
            if not authenticate_fingerprint_mac():
                click.echo("Fingerprint authentication failed.")
                exit(1)
            else:
                click.echo("Fingerprint authentication succeeded.")
                with open(SESSION_FILE, 'w') as f:
                    f.write(str(int(time.time())))
        else:
            click.echo("Fingerprint authentication is not supported on this system.")
            exit(1)
    else:
        click.echo("Invalid choice.")
        exit(1)

def ensure_authenticated():
    """Ensure the user is authenticated before proceeding."""
    if not is_authenticated():
        click.echo("You need to authenticate first.")
        authenticate_user()
    else:
        with open(SESSION_FILE, 'w') as f:
            f.write(str(int(time.time())))

def is_authenticated():
    if not SESSION_FILE.exists() or os.stat(SESSION_FILE).st_size == 0:
        return False
    with open(SESSION_FILE, 'r') as f:
        timestamp = int(f.read().strip())
    if time.time() - timestamp > SESSION_TIMEOUT:
        os.remove(SESSION_FILE)
        return False
    return True

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

def store_master_password(password: str):
    """Store the master password and refresh the cipher."""
    encrypt_master_password(password)
    cipher_singleton.refresh_cipher()

def get_password_file_path(domain, folder=None):
    current_dir = load_current_directory()
    if folder:
        target_dir = (current_dir / folder).resolve()
    else:
        target_dir = current_dir
    return target_dir / f"{domain}.pass"

@click.group(invoke_without_command=True)
@click.pass_context
def vault(ctx):
    ctx.ensure_object(dict)
    
    if not MASTER_PASSWORD_FILE.exists():
        click.echo("Master password is not set. Run 'vault set-master-password' to set it.")
        ctx.invoke(set_master_password)
    ensure_authenticated()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@vault.command()
def authenticate():
    """Authenticate the user."""
    authenticate_user()

@vault.command()
def set_master_password():
    master_password = click.prompt('Master Password', hide_input=True)
    encrypt_master_password(master_password)
    cipher_singleton.refresh_cipher()  # Refresh the cipher when the master password is set
    click.echo("Master password set successfully.")

@vault.command()
@click.argument('folder', required=False)
def insert(folder):
    ensure_authenticated()
    domain = click.prompt('Domain Name')
    description = click.prompt('Description')
    user_id = click.prompt('User ID')
    user_password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
    insert_password(domain, description, user_id, user_password, folder)

@vault.command()
@click.argument('folder', required=False)
def show(folder):
    ensure_authenticated()
    current_dir = load_current_directory()
    if folder:
        target_dir = current_dir / folder
        if target_dir.exists() and target_dir.is_dir():
            click.echo(f"{target_dir.name}/")  # Print the target directory
            show_passwords(target_dir, indent_level=1)  # Indent subfolders and files
        else:
            click.echo(f"Folder '{folder}' does not exist.")
    else:
        click.echo(f"{current_dir.name}/")  # Print the current directory
        show_passwords(current_dir, indent_level=1)  # Indent subfolders and files

@vault.command()
@click.argument('folder_vault_id', nargs=-1)
def remove(folder_vault_id):
    ensure_authenticated()
    if len(folder_vault_id) == 0:
        click.echo("No vault ID provided.")
        return
    elif len(folder_vault_id) == 1:
        folder = None
        vault_id = folder_vault_id[0]
    else:
        folder = folder_vault_id[0]
        vault_id = folder_vault_id[1]
    remove_password(vault_id, folder)

@vault.command()
@click.argument('folder_vault_id', nargs=-1)
def generate(folder_vault_id):
    ensure_authenticated()
    if len(folder_vault_id) < 2:
        click.echo("You must provide at least a domain and length.")
        return
    elif len(folder_vault_id) == 2:
        folder = None
        domain = folder_vault_id[0]
        length = int(folder_vault_id[1])
    else:
        folder = folder_vault_id[0]
        domain = folder_vault_id[1]
        length = int(folder_vault_id[2])

    description = click.prompt('Description')
    user_id = click.prompt('User ID')
    generate_password(domain, length, description, user_id, folder)

@vault.command()
def reformat():
    ensure_authenticated()
    reformat_passwords()

@vault.command()
@click.argument('folder_vault_id', nargs=-1)
def update(folder_vault_id):
    ensure_authenticated()
    if len(folder_vault_id) == 0:
        click.echo("No vault ID provided.")
        return
    elif len(folder_vault_id) == 1:
        folder = None
        vault_id = folder_vault_id[0]
    else:
        folder = folder_vault_id[0]
        vault_id = folder_vault_id[1]

    new_description = click.prompt('New Description')
    new_user_id = click.prompt('New User ID')
    new_password = click.prompt('New Password', hide_input=True, confirmation_prompt=True)
    update_password(vault_id, new_description, new_user_id, new_password, folder)

@vault.command(name="install-completion")
def install_completion():
    click.echo('source ./vault_completion.zsh')

@vault.command(name="rotate-key")
def rotate_key():
    ensure_authenticated()
    click.echo("Re-encrypting all passwords with the new key...")
    try:
        old_cipher = cipher_singleton.get_cipher()
        cipher_singleton.refresh_cipher()  # Refresh the cipher for key rotation
        new_cipher = cipher_singleton.get_cipher()
    except ValueError:
        click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
        return

    reencrypt_passwords(old_cipher, new_cipher)
    click.echo("Key rotation completed successfully.")

@vault.command(name="delete-all")
def delete_all():
    ensure_authenticated()
    delete_all_passwords()

@vault.command()
@click.argument('description')
def search(description):
    ensure_authenticated()
    search_passwords(description)

@vault.command(name="create-folder")
@click.argument('folder_name')
def create_folder_cmd(folder_name):
    ensure_authenticated()
    create_folder(folder_name)

@vault.command(name="goto")
@click.argument('directory')
def goto(directory):
    ensure_authenticated()
    current_dir = load_current_directory()
    
    if directory == './':
        new_dir = DATA_DIR
    elif directory == '../':
        new_dir = current_dir.parent.resolve() if current_dir != DATA_DIR else DATA_DIR
    else:
        new_dir = (current_dir / directory).resolve()

    if new_dir.exists() and new_dir.is_dir() and str(DATA_DIR) in str(new_dir.resolve()):
        save_current_directory(new_dir)
        click.echo(f"Current directory changed to '{new_dir if new_dir != DATA_DIR else '/'}'.")
    else:
        click.echo(f"Directory '{directory}' does not exist.")

def start_periodic_key_rotation(interval):
    def periodic_task():
        while True:
            time.sleep(interval)
            with key_lock:
                click.echo("Performing periodic key rotation...")
                try:
                    old_cipher = cipher_singleton.get_cipher()
                    cipher_singleton.refresh_cipher()
                    new_cipher = cipher_singleton.get_cipher()
                    reencrypt_passwords(old_cipher, new_cipher)
                    logging.info("Periodic key rotation completed.")
                except ValueError as e:
                    logging.error(f"Error during periodic key rotation: {e}")
                    continue
    
    rotation_thread = threading.Thread(target=periodic_task, daemon=True)
    rotation_thread.start()

@vault.command()
def pwd():
    ensure_authenticated()
    current_dir = load_current_directory()
    if current_dir == DATA_DIR:
        click.echo("Current directory: data")
    else:
        relative_path = current_dir.relative_to(DATA_DIR)
        click.echo(f"Current directory: data/{relative_path}")

if __name__ == "__main__":
    interval = 1800  # Rotate key every 1800 seconds (30 minutes)
    start_periodic_key_rotation(interval)
    vault()
