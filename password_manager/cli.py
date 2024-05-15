import os
import click
from cryptography.fernet import Fernet
from pathlib import Path
import pam

# Define the data directory
DATA_DIR = Path.home() / ".password_manager" / "data"
KEY_FILE = Path.home() / ".password_manager" / "key.key"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

def authenticate_user():
    """Authenticate the user using PAM."""
    pam_auth = pam.pam()
    username = os.getlogin()
    password = click.prompt('System Password', hide_input=True)
    if not pam_auth.authenticate(username, password):
        click.echo("Authentication failed.")
        exit(1)

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

@click.group()
def cli():
    """Simple CLI password manager."""
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
