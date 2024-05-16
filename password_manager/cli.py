import os
import getpass
import click
from cryptography.fernet import Fernet
from pathlib import Path
import pam
import time
import uuid
import ctypes
from ctypes import CDLL, c_void_p, c_long

if os.uname().sysname == "Darwin":
    import objc
    from Foundation import NSObject
    from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthenticationWithBiometrics

# Load the libdispatch library
libdispatch = CDLL('/usr/lib/system/libdispatch.dylib')

# Define function signatures for dispatch semaphores
libdispatch.dispatch_semaphore_create.argtypes = [c_long]
libdispatch.dispatch_semaphore_create.restype = c_void_p

libdispatch.dispatch_semaphore_wait.argtypes = [c_void_p, c_long]
libdispatch.dispatch_semaphore_wait.restype = c_long

libdispatch.dispatch_semaphore_signal.argtypes = [c_void_p]
libdispatch.dispatch_semaphore_signal.restype = c_long

# Define the data directory
DATA_DIR = Path.home() / ".password_manager" / "data"
KEY_FILE = Path.home() / ".password_manager" / "key.key"
SESSION_FILE = Path.home() / ".password_manager" / ".session"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

SESSION_TIMEOUT = 3600  # Set session timeout to 3600 seconds

def authenticate_user():
    """Authenticate the user using PAM and optionally fingerprint."""
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
                # click.echo("Fingerprint authentication succeeded.")
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

def load_key():
    """Load the previously generated key"""
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return Fernet(key)

cipher = load_key()

def get_password_file_path(domain):
    return DATA_DIR / f"{domain}.pass"

def is_authenticated():
    """Check if the user is authenticated."""
    if not SESSION_FILE.exists():
        return False
    with open(SESSION_FILE, 'r') as f:
        timestamp = int(f.read().strip())
    if time.time() - timestamp > SESSION_TIMEOUT:  # Adjusted session timeout
        os.remove(SESSION_FILE)
        return False
    return True

def ensure_authenticated():
    """Ensure the user is authenticated before proceeding."""
    if not is_authenticated():
        click.echo("You need to authenticate first. Run 'vault authenticate' to authenticate.")
        exit(1)

@click.group(invoke_without_command=True)
@click.pass_context
def vault(ctx):
    """Simple CLI password manager."""
    if not is_authenticated():
        click.echo("You need to authenticate first.")
        ctx.invoke(authenticate)
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

@vault.command()
def authenticate():
    """Authenticate the user."""
    authenticate_user()

@vault.command()
def insert():
    """Insert a new password."""
    ensure_authenticated()
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
    """Show passwords."""
    ensure_authenticated()
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
                password = cipher.decrypt(encrypted_password).decode()
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
                    password = cipher.decrypt(encrypted_password).decode()
                click.echo(f"\nDomain: {domain_name}\nVault ID: {vault_id}\nDescription: {description}\nUser ID: {user_id}\nPassword: {password}\n")
            except FileNotFoundError:
                click.echo(f"No password found for {domain_name}")

@vault.command()
@click.argument('vault_id')
def remove(vault_id):
    """Remove a password by vault ID."""
    ensure_authenticated()
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
    """Generate a random password."""
    ensure_authenticated()
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
    """Reformat existing password files."""
    ensure_authenticated()
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
    """Update a password entry by vault ID."""
    ensure_authenticated()
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

if __name__ == "__main__":
    vault()
