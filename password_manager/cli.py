import os
import getpass
import click
from cryptography.fernet import Fernet
from pathlib import Path
import pam
import time
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
        # Debug print to check values
        click.echo(f"Debug: username={username}, password={password}")
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
                click.echo("Fingerprint authentication succeeded.")
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

def get_password_file_path(name):
    return DATA_DIR / f"{name}.pass"

def is_authenticated():
    """Check if the user is authenticated."""
    if not SESSION_FILE.exists():
        click.echo("Debug: Session file does not exist.")
        return False
    with open(SESSION_FILE, 'r') as f:
        timestamp = int(f.read().strip())
    click.echo(f"Debug: Session timestamp: {timestamp}")
    if time.time() - timestamp > 3600:  # Session is valid for 1 hour
        click.echo("Debug: Session expired.")
        os.remove(SESSION_FILE)
        return False
    click.echo("Debug: Session is valid.")
    return True

@click.group()
@click.pass_context
def cli(ctx):
    """Simple CLI password manager."""
    if not is_authenticated():
        authenticate_user()

@cli.command()
@click.argument('name')
def insert(name):
    """Insert a new password."""
    password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
    encrypted_password = cipher.encrypt(password.encode())
    
    with open(get_password_file_path(name), 'wb') as f:
        f.write(encrypted_password)
    click.echo(f"Password for {name} inserted.")

@cli.command()
@click.argument('name')
def show(name):
    """Show a password."""
    try:
        with open(get_password_file_path(name), 'rb') as f:
            encrypted_password = f.read()
        password = cipher.decrypt(encrypted_password).decode()
        click.echo(f"Password for {name}: {password}")
    except FileNotFoundError:
        click.echo(f"No password found for {name}")

@cli.command()
@click.argument('name')
def remove(name):
    """Remove a password."""
    try:
        os.remove(get_password_file_path(name))
        click.echo(f"Password for {name} removed.")
    except FileNotFoundError:
        click.echo(f"No password found for {name}")

@cli.command()
@click.argument('name')
@click.argument('length', type=int)
def generate(name, length):
    """Generate a random password."""
    import random
    import string
    
    password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    encrypted_password = cipher.encrypt(password.encode())
    
    with open(get_password_file_path(name), 'wb') as f:
        f.write(encrypted_password)
    click.echo(f"Generated password for {name}: {password}")

if __name__ == '__main__':
    cli()
