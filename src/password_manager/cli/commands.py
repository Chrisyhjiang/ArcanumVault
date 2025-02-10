import click
import os
import json
import base64
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

# Import your existing modules
from password_manager.core.auth import HashBasedAuth
from password_manager.core.encryption import AES256Encryption
from password_manager.core.vault import PasswordVault
from password_manager.cli.session import current_session

# Import pyotp for TOTP-based 2FA
import pyotp

# Set the data directory to a subdirectory in the user's home directory
DATA_DIR = Path(os.path.expanduser('~/.password_manager_data'))
MASTER_PASSWORD_FILE = DATA_DIR / 'master.key'
# A file to store the TOTP secret
TOTP_SECRET_FILE = DATA_DIR / 'totp.secret'

# Initialize auth service
auth_service = HashBasedAuth(MASTER_PASSWORD_FILE)

# Global variables for the encryption service and vault;
# they will be initialized upon successful authentication.
encryption_service = None
vault = None

def initialize_services(master_key: bytes):
    """Initialize encryption service and vault using the persisted salt."""
    global encryption_service, vault
    # Reuse the salt from the auth service to ensure consistent key derivation.
    encryption_service = AES256Encryption(master_key=master_key, salt=auth_service.salt)
    vault = PasswordVault(encryption_service, DATA_DIR)

def require_auth(f):
    """Decorator to require authentication before executing a command."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        # Use is_valid() to check if the session has expired
        if not current_session.is_valid():
            password = click.prompt("Enter master password", hide_input=True).strip()
            if auth_service.authenticate(password):
                initialize_services(auth_service.get_master_key())
                current_session.login()  # sets last_activity and is_authenticated
            else:
                click.echo("Authentication failed.")
                return
        else:
            # If session is valid, refresh the last_activity to extend the timeout
            current_session.refresh()
        return f(*args, **kwargs)
    return wrapped

@click.group()
def cli():
    """Password Manager CLI

    This tool allows you to securely manage your passwords.
    Use the commands below to add, search, and manage your passwords.
    """
    pass

@cli.command()
def set_master_password():
    """
    Set or update the master password for authentication.
    
    For extra security, this command requires 2FA via TOTP. If a TOTP secret
    does not exist yet, it will be generated and you will be given instructions
    to add it to your authenticator app (e.g., Google Authenticator). Then you must
    run the command again.
    """
    # Ensure the data directory exists and is secured
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)

    # Check if a TOTP secret is already stored
    if not TOTP_SECRET_FILE.exists():
        totp_secret = pyotp.random_base32()
        TOTP_SECRET_FILE.write_text(totp_secret)
        os.chmod(TOTP_SECRET_FILE, 0o600)
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name="password_manager", issuer_name="YourAppName")
        click.echo("A new 2FA secret has been generated.")
        click.echo("Please add the following URI to your authenticator app (or manually enter the secret):")
        click.echo(provisioning_uri)
        click.echo("Once you have registered your authenticator, run this command again to change the master password.")
        return
    else:
        totp_secret = TOTP_SECRET_FILE.read_text().strip()
    
    # Ask for the current TOTP code from the authenticator
    totp = pyotp.TOTP(totp_secret)
    code = click.prompt("Enter the current 2FA code from your authenticator app").strip()
    if not totp.verify(code):
        click.echo("Invalid 2FA code. Aborting master password change.")
        return

    # Proceed to set the new master password
    password = click.prompt('Enter new master password', hide_input=True, confirmation_prompt=True).strip()
    auth_service.set_master_password(password)
    initialize_services(auth_service.get_master_key())
    click.echo("Master password set successfully.")

@cli.command()
def authenticate():
    """Authenticate with the master password."""
    password = click.prompt("Enter master password", hide_input=True).strip()
    if auth_service.authenticate(password):
        initialize_services(auth_service.get_master_key())
        current_session.login()  # This resets the session timeout
        click.echo("Authentication successful.")
    else:
        click.echo("Authentication failed.")

@cli.command()
@require_auth
def add_password():
    """Add a new password to the vault."""
    domain = click.prompt('Domain')
    username = click.prompt('Username')
    password = click.prompt('Password', hide_input=True).strip()
    description = click.prompt('Description', default='', show_default=False)
    password_entry = vault.add_password(domain, username, password, description)
    click.echo(f"Password for {domain} added successfully with ID: {password_entry.id}")

@cli.command()
@require_auth
def list():
    """List all stored passwords with their details."""
    passwords = vault.list_passwords()
    if not passwords:
        click.echo("No passwords stored.")
        return
    for pwd in passwords:
        click.echo(f"\nDomain: {pwd.domain}")
        click.echo(f"Username: {pwd.username}")
        click.echo(f"Description: {pwd.description}")
        click.echo(f"ID: {pwd.id}")

@cli.command()
@require_auth
def show():
    """Show details of a specific password by domain or username."""
    query = click.prompt('Enter domain or username to search')
    matching_passwords = [
        pwd for pwd in vault.list_passwords()
        if query.lower() in pwd.domain.lower() or query.lower() in pwd.username.lower()
    ]
    
    if not matching_passwords:
        click.echo("No matching passwords found.")
        return
    
    if len(matching_passwords) == 1:
        selected_password = matching_passwords[0]
    else:
        click.echo("Multiple matches found:")
        for i, pwd in enumerate(matching_passwords, start=1):
            click.echo(f"{i}: Domain: {pwd.domain}, Username: {pwd.username}")
        choice = click.prompt("Select a password by number", type=int)
        if choice < 1 or choice > len(matching_passwords):
            click.echo("Invalid selection.")
            return
        selected_password = matching_passwords[choice - 1]
    
    click.echo(f"\nDomain: {selected_password.domain}")
    click.echo(f"Username: {selected_password.username}")
    click.echo(f"Description: {selected_password.description}")
    
    if click.confirm("Show password?"):
        try:
            decrypted = vault.get_decrypted_password(selected_password.id)
            click.echo(f"Password: {decrypted}")
        except Exception as e:
            click.echo("Failed to decrypt password.")

@cli.command()
@require_auth
def delete():
    """Delete a password from the vault by ID."""
    pwd_id = click.prompt('Password ID')
    if vault.delete_password(pwd_id):
        click.echo("Password deleted successfully!")
    else:
        click.echo("Password not found.")

@cli.command()
def install_completion():
    """Install shell completion for the vault command."""
    click.echo("To enable shell completion, add the following line to your shell's configuration file:")
    click.echo('eval "$(_VAULT_COMPLETE=source_bash vault)"')

def main():
    """Main entry point."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    cli()

if __name__ == '__main__':
    main()
