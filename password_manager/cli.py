import os
import getpass
import click
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import pam
import time
import uuid
import ctypes
from ctypes import CDLL, c_void_p, c_long
import threading
import logging
import base64

# Setup logging to redirect to a file
logging.basicConfig(filename='vault.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Logging initialized")  # Initial log message to verify logging setup

# Setup directories and files
DATA_DIR = Path.home() / ".password_manager" / "data"
KEY_FILE = Path.home() / ".password_manager" / "key.key"
SESSION_FILE = Path.home() / ".password_manager" / ".session"
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

authenticated_password = None
cipher = None
periodic_task_started = False  # Flag to ensure the periodic task starts only once

def set_permissions(path):
    """Set secure permissions for the file."""
    os.chmod(path, 0o600)  # Owner can read and write

def get_password_file_path(domain):
    return DATA_DIR / f"{domain}.pass"

def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def derive_system_password(system_id: str) -> str:
    # Use a fixed salt for deriving the system password
    fixed_salt = b'some_fixed_salt_value'  # Ensure this value is consistent
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=fixed_salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(system_id.encode())
    return base64.urlsafe_b64encode(derived_key).decode()

def load_key():
    global authenticated_password
    if authenticated_password is None:
        raise ValueError("Authenticated password is not set")
    if not KEY_FILE.exists():
        salt = generate_salt()
        key = derive_key(authenticated_password, salt)
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(salt + key)
        set_permissions(KEY_FILE)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            salt = key_file.read(16)
            stored_key = key_file.read()
            key = derive_key(authenticated_password, salt)
            if key != stored_key:
                raise ValueError("Invalid master password.")
    logging.info("Loaded key with KDF")
    return Fernet(key)

def reload_cipher():
    global cipher
    cipher = load_key()
    logging.info("Cipher reloaded with KDF")

def generate_new_key():
    salt = generate_salt()
    return derive_key(authenticated_password, salt), salt

def reencrypt_passwords(old_cipher, new_cipher):
    for file_path in DATA_DIR.glob('*.pass'):
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
    logging.info("Re-encryption completed")

def store_new_key(new_key, salt):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(salt + new_key)
    set_permissions(KEY_FILE)
    reload_cipher()
    logging.info("New key stored successfully with KDF")

def rotate_key_periodically():
    while True:
        with key_lock:
            logging.info("Running periodic key rotation")
            old_key = cipher._signing_key
            new_key, salt = generate_new_key()
            old_cipher = cipher
            new_cipher = Fernet(new_key)
            reencrypt_passwords(old_cipher, new_cipher)
            store_new_key(new_key, salt)
            logging.info("Completed periodic key rotation")
        time.sleep(1800)  # Rotate key every 30 minutes (1800 seconds)

def start_periodic_task():
    if not hasattr(start_periodic_task, 'task_thread'):
        start_periodic_task.task_thread = threading.Thread(target=rotate_key_periodically, daemon=True)
        start_periodic_task.task_thread.start()
        logging.info(f"Periodic task thread started: {start_periodic_task.task_thread.is_alive()}")

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

def is_authenticated():
    if not SESSION_FILE.exists() or os.stat(SESSION_FILE).st_size == 0:
        return False
    with open(SESSION_FILE, 'r') as f:
        timestamp = int(f.read().strip())
    if time.time() - timestamp > SESSION_TIMEOUT:
        os.remove(SESSION_FILE)
        return False
    return True

def ensure_authenticated():
    if not is_authenticated():
        click.echo("You need to authenticate first. Run 'vault authenticate' to authenticate.")
        exit(1)
    else:
        refresh_session()

def refresh_session():
    with open(SESSION_FILE, 'w') as f:
        f.write(str(int(time.time())))
    reload_cipher()

def authenticate_user():
    global cipher, authenticated_password, periodic_task_started
    pam_auth = pam.pam()
    
    try:
        username = os.getlogin()
        if username == 'root':
            username = getpass.getuser()
    except Exception:
        username = getpass.getuser()

    choice = click.prompt('Choose authentication method: [P]assword/[F]ingerprint', type=str).lower()

    if choice == 'p':
        password = click.prompt('System Password', hide_input=True)
        if not pam_auth.authenticate(username, password, service='login'):
            click.echo("Authentication failed.")
            exit(1)
        else:
            click.echo("Authentication succeeded.")
            authenticated_password = password
            cipher = load_key()
            with open(SESSION_FILE, 'w') as f:
                f.write(str(int(time.time())))
    elif choice == 'f':
        if os.uname().sysname == "Darwin":
            if not authenticate_fingerprint_mac():
                click.echo("Fingerprint authentication failed.")
                exit(1)
            else:
                click.echo("Fingerprint authentication succeeded.")
                # Derive a consistent password for fingerprint authentication
                system_id = f"{username}-{os.uname().nodename}"
                authenticated_password = derive_system_password(system_id)
                cipher = load_key()
                with open(SESSION_FILE, 'w') as f:
                    f.write(str(int(time.time())))
        else:
            click.echo("Fingerprint authentication is not supported on this system.")
            exit(1)
    else:
        click.echo("Invalid choice.")
        exit(1)

    # Start periodic task after successful authentication if not already started
    if not periodic_task_started:
        start_periodic_task()
        periodic_task_started = True

@click.group(invoke_without_command=True)
@click.pass_context
def vault(ctx):
    if not is_authenticated():
        click.echo("You need to authenticate first.")
        ctx.invoke(authenticate)
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@vault.command()
def authenticate():
    authenticate_user()

@vault.command()
def insert():
    ensure_authenticated()
    with key_lock:
        vault_id = str(uuid.uuid4())
        domain = click.prompt('Domain Name')
        description = click.prompt('Description')
        user_id = click.prompt('User ID')
        password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
        encrypted_password = cipher.encrypt(password.encode())
        password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
        with open(get_password_file_path(domain), 'w') as f:
            f.write(password_entry)
        click.echo(f"Password for {domain} inserted with description, User ID, and vaultID {vault_id}.")

@vault.command()
@click.argument('domain', required=False)
def show(domain):
    ensure_authenticated()
    with key_lock:
        if domain:
            try:
                with open(get_password_file_path(domain), 'r') as f:
                    lines = f.read().splitlines()
                    if len(lines) < 4:
                        click.echo(f"Invalid password file format for {domain}. File content: {lines}")
                        return
                    vault_id = lines[0]
                    description = lines[1]
                    user_id = lines[2]
                    encrypted_password = lines[3].encode()
                    try:
                        password = cipher.decrypt(encrypted_password).decode()
                    except InvalidToken:
                        click.echo(f"Failed to decrypt password for {domain}.")
                        return
                click.echo(f"Vault ID: {vault_id}\nDescription: {description}\nUser ID: {user_id}\nPassword for {domain}: {password}")
            except FileNotFoundError:
                click.echo(f"No password found for {domain}")
        else:
            for file_path in DATA_DIR.glob('*.pass'):
                domain_name = file_path.stem
                try:
                    with open(file_path, 'r') as f:
                        lines = f.read().splitlines()
                        if len(lines) < 4:
                            click.echo(f"Invalid password file format for {domain_name}. File content: {lines}")
                            continue
                        vault_id = lines[0]
                        description = lines[1]
                        user_id = lines[2]
                        encrypted_password = lines[3].encode()
                        try:
                            password = cipher.decrypt(encrypted_password).decode()
                        except InvalidToken:
                            click.echo(f"Failed to decrypt password for {domain_name}.")
                            continue
                    click.echo(f"\nDomain: {domain_name}\nVault ID: {vault_id}\nDescription: {description}\nUser ID: {user_id}\nPassword: {password}\n")
                except FileNotFoundError:
                    click.echo(f"No password found for {domain_name}")

@vault.command()
@click.argument('vault_id')
def remove(vault_id):
    ensure_authenticated()
    with key_lock:
        for file_path in DATA_DIR.glob('*.pass'):
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
@click.argument('domain')
@click.argument('length', type=int)
def generate(domain, length):
    ensure_authenticated()
    with key_lock:
        import random
        import string
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
        encrypted_password = cipher.encrypt(password.encode())
        vault_id = str(uuid.uuid4())
        description = click.prompt('Description')
        user_id = click.prompt('User ID')
        password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
        with open(get_password_file_path(domain), 'w') as f:
            f.write(password_entry)
        click.echo(f"Generated password for {domain} with description, User ID, and vaultID {vault_id}: {password}")

@vault.command()
def reformat():
    ensure_authenticated()
    with key_lock:
        for file_path in DATA_DIR.glob('*.pass'):
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
@click.argument('vault_id')
def update(vault_id):
    ensure_authenticated()
    with key_lock:
        for file_path in DATA_DIR.glob('*.pass'):
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
    click.echo('To activate completion for this session, source the script:')
    click.echo('source ~/.password_manager_completion/vault_completion.zsh')

@vault.command(name="rotate-key")
def rotate_key():
    ensure_authenticated()
    with key_lock:
        old_key = cipher._signing_key
        new_key, salt = generate_new_key()
        old_cipher = cipher
        new_cipher = Fernet(new_key)
        click.echo("Re-encrypting all passwords with the new key...")
        for file_path in DATA_DIR.glob('*.pass'):
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
                    click.echo(f"Failed to decrypt {file_path.stem} with the old key. Skipping.")
                    continue
                new_encrypted_password = new_cipher.encrypt(decrypted_password)
                password_entry = f"{lines[0]}\n{description}\n{user_id}\n{new_encrypted_password.decode()}"
                with open(file_path, 'w') as f:
                    f.write(password_entry)
        store_new_key(new_key, salt)
        click.echo("Key rotation completed successfully.")

@vault.command(name="delete-all")
def delete_all():
    """Delete all password entries."""
    ensure_authenticated()
    with key_lock:
        for file_path in DATA_DIR.glob('*.pass'):
            os.remove(file_path)
        click.echo("All password entries have been deleted.")

@vault.command()
@click.argument('description')
def search(description):
    """Search for passwords by description."""
    ensure_authenticated()
    results = []
    with key_lock:
        for file_path in DATA_DIR.glob('*.pass'):
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
    if results:
        for domain, vault_id, desc, user_id, password in results:
            click.echo(f"\nDomain: {domain}\nVault ID: {vault_id}\nDescription: {desc}\nUser ID: {user_id}\nPassword: {password}\n")
    else:
        click.echo("No matching descriptions found.")

if __name__ == "__main__":
    vault()
