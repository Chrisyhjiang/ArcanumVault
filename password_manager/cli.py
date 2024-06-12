import os
import getpass
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

cipher = None
periodic_task_started = False

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

def generate_secure_key():
    """Generate and store a secure key for encryption."""
    key = Fernet.generate_key()
    with open(SECURE_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    set_permissions(SECURE_KEY_FILE)
    return key

def load_secure_key():
    """Load the secure key from the file."""
    if SECURE_KEY_FILE.exists():
        with open(SECURE_KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        return generate_secure_key()

def encrypt_master_password(password: str):
    """Encrypt and store the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    encrypted_password = fernet.encrypt(password.encode())
    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_password)
    set_permissions(MASTER_PASSWORD_FILE)
    logging.info("Master password stored in encrypted form on disk.")

def decrypt_master_password():
    """Decrypt and return the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_password = f.read()
    password = fernet.decrypt(encrypted_password).decode()
    return password

def load_cipher():
    if not MASTER_PASSWORD_FILE.exists():
        raise ValueError("Master password is not set.")
    password = decrypt_master_password()
    key = derive_key(password)
    return Fernet(key)

def store_master_password(password: str):
    if MASTER_PASSWORD_FILE.exists():
        old_cipher = load_cipher()
        encrypt_master_password(password)
        new_key = derive_key(password)
        new_cipher = Fernet(new_key)
        reencrypt_passwords(old_cipher, new_cipher)
    else:
        encrypt_master_password(password)
    set_permissions(MASTER_PASSWORD_FILE)
    logging.info("Master password stored.")


def load_master_password():
    global cipher
    if MASTER_PASSWORD_FILE.exists():
        password = decrypt_master_password()
        key = derive_key(password)
        cipher = Fernet(key)
        return password
    else:
        password = click.prompt('Master Password', hide_input=True)
        store_master_password(password)
        key = derive_key(password)
        cipher = Fernet(key)
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

def load_key(master_password):
    global cipher
    if master_password is None:
        raise ValueError("Master password is not set")
    key = derive_key(master_password)
    cipher = Fernet(key)

def get_password_file_path(domain, folder=None):
    current_dir = load_current_directory()
    if folder:
        target_dir = (current_dir / folder).resolve()
    else:
        target_dir = current_dir
    return target_dir / f"{domain}.pass"

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
@click.pass_context
def authenticate(ctx):
    """Authenticate the user."""
    authenticate_user()

@vault.command()
@click.pass_context
def set_master_password(ctx):
    master_password = click.prompt('Master Password', hide_input=True)
    store_master_password(master_password)
    click.echo("Master password set successfully.")

@vault.command()
@click.argument('folder', required=False)
@click.pass_context
def insert(ctx, folder):
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
        vault_id = str(uuid.uuid4())
        domain = click.prompt('Domain Name')
        description = click.prompt('Description')
        user_id = click.prompt('User ID')
        user_password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
        encrypted_password = cipher.encrypt(user_password.encode())
        password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
        file_path = get_password_file_path(domain, folder)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(password_entry)
        click.echo(f"Password for {domain} inserted with description, User ID, and vaultID {vault_id}.")

def show_passwords(directory, indent_level=0):
    """Recursively show passwords and folders."""
    for file_path in directory.iterdir():
        if file_path.is_dir():
            click.echo(f"{' ' * (indent_level * 2)}{file_path.name}/")
            show_passwords(file_path, indent_level + 1)
        elif file_path.suffix == '.pass':
            try:
                with open(file_path, 'r') as f:
                    lines = f.read().splitlines()
                    if len(lines) < 4:
                        click.echo(f"{' ' * (indent_level * 2)}Invalid password file format for {file_path.stem}.")
                        continue
                    vault_id = lines[0]
                    description = lines[1]
                    user_id = lines[2]
                    encrypted_password = lines[3].encode()
                    try:
                        user_password = cipher.decrypt(encrypted_password).decode()
                    except InvalidToken:
                        click.echo(f"{' ' * (indent_level * 2)}Failed to decrypt password for {file_path.stem}.")
                        continue
                click.echo(f"{' ' * (indent_level * 2)}Domain: {file_path.stem}")
                click.echo(f"{' ' * (indent_level * 2)}  Description: {description}")
                click.echo(f"{' ' * (indent_level * 2)}  User ID: {user_id}")
                click.echo(f"{' ' * (indent_level * 2)}  Password: {user_password}")
                click.echo(f"{' ' * (indent_level * 2)}  Vault ID: {vault_id}")
            except FileNotFoundError:
                click.echo(f"{' ' * (indent_level * 2)}No password found for {file_path.stem}")

@vault.command()
@click.argument('folder', required=False)
@click.pass_context
def show(ctx, folder):
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
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
@click.pass_context
def remove(ctx, folder_vault_id):
    master_password = load_master_password()
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
    
    with key_lock:
        current_dir = load_current_directory()
        if folder:
            current_dir = current_dir / folder
        if not current_dir.exists():
            click.echo(f"Folder '{folder}' does not exist.")
            return
        for file_path in current_dir.glob('*.pass'):
            with open(file_path, 'r') as f:
                lines = f.read().splitlines()
            if len(lines) < 4:
                continue
            existing_vault_id = lines[0]
            if existing_vault_id == vault_id:
                os.remove(file_path)
                click.echo(f"Password with vault ID {vault_id} removed.")
                break
        else:
            click.echo(f"No entry found with vault ID {vault_id}")

@vault.command()
@click.argument('folder_vault_id', nargs=-1)
@click.pass_context
def generate(ctx, folder_vault_id):
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
        import random
        import string
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

        generated_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        encrypted_password = cipher.encrypt(generated_password.encode())
        vault_id = str(uuid.uuid4())
        description = click.prompt('Description')
        user_id = click.prompt('User ID')
        password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
        file_path = get_password_file_path(domain, folder)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(password_entry)
        click.echo(f"Generated password for {domain} with description, User ID, and vaultID {vault_id}: {generated_password}")

@vault.command()
@click.pass_context
def reformat(ctx):
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
        current_dir = load_current_directory()
        for file_path in current_dir.glob('*.pass'):
            domain_name = file_path.stem
            with open(file_path, 'r') as f:
                lines = f.read().splitlines()
            if len(lines) == 3:
                description = lines[0]
                user_id = lines[1]
                encrypted_password = lines[2]
                vault_id = str(uuid.uuid4())
                password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password}"
                with open(file_path, 'w') as f:
                    f.write(password_entry)
                click.echo(f"Reformatted {domain_name} with vault ID {vault_id}.")
            elif len(lines) < 3:
                click.echo(f"Skipping {domain_name}, invalid format.")

@vault.command()
@click.argument('folder_vault_id', nargs=-1)
@click.pass_context
def update(ctx, folder_vault_id):
    master_password = load_master_password()
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
    
    with key_lock:
        current_dir = load_current_directory()
        if folder:
            current_dir = current_dir / folder
        if not current_dir.exists():
            click.echo(f"Folder '{folder}' does not exist.")
            return
        for file_path in current_dir.glob('*.pass'):
            with open(file_path, 'r') as f:
                lines = f.read().splitlines()
            if len(lines) < 4:
                continue
            existing_vault_id = lines[0]
            if existing_vault_id == vault_id:
                description = lines[1]
                user_id = lines[2]
                encrypted_password = lines[3]
                break
        else:
            click.echo(f"No entry found with vault ID {vault_id}")
            return

        new_description = click.prompt('New Description', default=description)
        new_user_id = click.prompt('New User ID', default=user_id)
        new_password = click.prompt('New Password', hide_input=True, confirmation_prompt=True)
        encrypted_password = cipher.encrypt(new_password.encode()).decode()
        password_entry = f"{vault_id}\n{new_description}\n{new_user_id}\n{encrypted_password}"
        with open(file_path, 'w') as f:
            f.write(password_entry)
        click.echo(f"Updated entry with vault ID {vault_id}.")

@vault.command(name="install-completion")
def install_completion():
    click.echo('source ./vault_completion.zsh')

@vault.command(name="rotate-key")
@click.pass_context
def rotate_key(ctx):
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
        click.echo("Re-encrypting all passwords with the new key...")
        rotate_key_for_directory(DATA_DIR)
        click.echo("Key rotation completed successfully.")

def rotate_key_for_directory(directory):
    """Rotate key for all password files in the given directory."""
    global cipher
    for root, _, files in os.walk(directory):
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
                        decrypted_password = cipher.decrypt(encrypted_password)
                    except InvalidToken:
                        click.echo(f"Failed to decrypt {file_path.stem}. Skipping.")
                        continue
                    new_encrypted_password = cipher.encrypt(decrypted_password)
                    password_entry = f"{lines[0]}\n{description}\n{user_id}\n{new_encrypted_password.decode()}"
                    with open(file_path, 'w') as f:
                        f.write(password_entry)
    logging.info(f"Re-encryption completed for directory: {directory}")

@vault.command(name="delete-all")
@click.pass_context
def delete_all(ctx):
    """Delete all password entries and directories."""
    master_password = load_master_password()
    ensure_authenticated()
    with key_lock:
        for root, dirs, files in os.walk(DATA_DIR, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        click.echo("All password entries and directories have been deleted.")

@vault.command()
@click.argument('description')
@click.pass_context
def search(ctx, description):
    """Search for passwords by description."""
    master_password = load_master_password()
    ensure_authenticated()
    results = []

    def search_passwords(dir_path, description):
        for file_path in dir_path.glob('*.pass'):
            with open(file_path, 'r') as f:
                lines = f.read().splitlines()
                if len(lines) < 4:
                    click.echo(f"Invalid password file format for {file_path.stem}. Skipping.")
                    continue
                vault_id = lines[0]
                desc = lines[1]
                user_id = lines[2]
                encrypted_password = lines[3].encode()
                if description.lower() in desc.lower():
                    try:
                        password = cipher.decrypt(encrypted_password).decode()
                        results.append((file_path.stem, vault_id, desc, user_id, password))
                    except InvalidToken:
                        click.echo(f"Failed to decrypt password for {file_path.stem}. Skipping.")
                        continue
        for sub_dir in dir_path.iterdir():
            if sub_dir.is_dir():
                search_passwords(sub_dir, description)

    current_dir = load_current_directory()
    search_passwords(current_dir, description)

    if results:
        for domain, vault_id, desc, user_id, password in results:
            click.echo(f"\nDomain: {domain}\nVault ID: {vault_id}\nDescription: {desc}\nUser ID: {user_id}\nPassword: {password}\n")
    else:
        click.echo("No matching descriptions found.")



"""
creates the desiganted folder at the specified location in the file system.
"""
@vault.command(name="create-folder")
@click.argument('folder_name')
@click.pass_context
def create_folder(ctx, folder_name):
    """Create a new directory for storing passwords."""
    master_password = load_master_password()
    ensure_authenticated()
    current_dir = load_current_directory()
    new_folder = current_dir / folder_name
    new_folder.mkdir(parents=True, exist_ok=True)
    click.echo(f"Folder '{folder_name}' created.")

"""
navigates to the specified directory provided in the command line
"""

@vault.command(name="goto")
@click.argument('directory')
@click.pass_context
def goto(ctx, directory):
    """Change the current directory for storing passwords."""
    master_password = load_master_password()
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


"""
prints the current directory of the password manager instance
"""
@vault.command()
@click.pass_context
def pwd(ctx):
    """Print the current directory."""
    master_password = load_master_password()
    ensure_authenticated()
    current_dir = load_current_directory()
    if current_dir == DATA_DIR:
        click.echo("Current directory: data")
    else:
        relative_path = current_dir.relative_to(DATA_DIR)
        click.echo(f"Current directory: data/{relative_path}")


if __name__ == "__main__":
    vault()
