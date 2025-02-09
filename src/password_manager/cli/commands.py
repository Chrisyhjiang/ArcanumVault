import click
from typing import Optional
from pathlib import Path
import os
from datetime import datetime, timedelta
import threading
from password_manager.core.vault import PasswordVault
from password_manager.core.encryption import AES256Encryption
from password_manager.core.auth import HashBasedAuth
from password_manager.cli.session import current_session, require_auth
import cryptography.exceptions

# Set the data directory to a subdirectory in the user's home directory
DATA_DIR = Path(os.path.expanduser('~/.password_manager_data'))
auth_service = HashBasedAuth(DATA_DIR)
encryption_service = AES256Encryption()
vault = PasswordVault(encryption_service, DATA_DIR)

# Define the CLI group
@click.group()
def cli():
    """Password Manager CLI

    This tool allows you to securely manage your passwords.
    Use the commands below to add, search, and manage your passwords.
    """
    pass

@cli.command()
@require_auth(auth_service)
def search():
    """Search for passwords by domain or description."""
    query = click.prompt('Search')
    passwords = vault.list_passwords()
    
    found = False
    for pwd in passwords:
        if query.lower() in pwd.domain.lower() or query.lower() in pwd.description.lower():
            found = True
            click.echo(f"\nDomain: {pwd.domain}")
            click.echo(f"Username: {pwd.username}")
            click.echo(f"Description: {pwd.description}")
            click.echo(f"ID: {pwd.id}")
            
            if click.confirm("Show password?"):
                decrypted = vault.get_decrypted_password(pwd.id)
                click.echo(f"Password: {decrypted}")
    
    if not found:
        click.echo("No matching passwords found.")

@cli.command()
@require_auth(auth_service)
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
@require_auth(auth_service)
def show():
    """Show details of a specific password by ID."""
    id = click.prompt('Password ID')
    pwd = vault.get_password(id)
    
    if not pwd:
        click.echo("Password not found.")
        return
    
    click.echo(f"\nDomain: {pwd.domain}")
    click.echo(f"Username: {pwd.username}")
    click.echo(f"Description: {pwd.description}")
    
    if click.confirm("Show password?"):
        decrypted = vault.get_decrypted_password(id)
        click.echo(f"Password: {decrypted}")

@cli.command()
@require_auth(auth_service)
def delete():
    """Delete a password from the vault by ID."""
    id = click.prompt('Password ID')
    if vault.delete_password(id):
        click.echo("Password deleted successfully!")
    else:
        click.echo("Password not found.")

@cli.command()
def set_master_password():
    """Set or update the master password for authentication."""
    password = click.prompt('Enter new master password', hide_input=True, confirmation_prompt=True)
    auth_service.set_master_password(password)
    click.echo("Master password set successfully.")

@cli.command()
def authenticate():
    """Authenticate with the master password."""
    password = click.prompt("Enter master password", hide_input=True)
    if auth_service.authenticate(password):
        current_session.login()
        click.echo("Authentication successful.")
    else:
        click.echo("Authentication failed.")

@cli.command()
@require_auth(auth_service)
def add_password():
    """Add a new password to the vault."""
    domain = click.prompt('Domain')
    username = click.prompt('Username')
    password = click.prompt('Password', hide_input=True)
    description = click.prompt('Description', default='', show_default=False)
    
    password_entry = vault.add_password(domain, username, password, description)
    click.echo(f"Password for {domain} added successfully with ID: {password_entry.id}")

@cli.command()
def install_completion():
    """Install shell completion for the vault command."""
    click.echo("To enable shell completion, add the following line to your shell's configuration file:")
    click.echo('eval "$(_VAULT_COMPLETE=source_bash vault)"')

def start_key_rotation():
    """Start background key rotation thread."""
    def rotate_keys():
        # Initial wait before starting the first key rotation
        threading.Event().wait(3600)  # Wait for 1 hour before the first rotation

        while True:
            click.echo("Performing key rotation...")
            # Generate a new key
            new_key = encryption_service._derive_key()
            
            # Re-encrypt all passwords with the new key
            for password in vault.list_passwords():
                try:
                    # Decrypt with the old key
                    decrypted_password = encryption_service.decrypt(password.encrypted_password)
                    
                    # Temporarily set the new key for encryption
                    encryption_service._key = new_key
                    
                    # Re-encrypt with the new key
                    new_encrypted_password = encryption_service.encrypt(decrypted_password)
                    password.encrypted_password = new_encrypted_password
                except cryptography.exceptions.InvalidTag:
                    click.echo(f"Failed to rotate key for password ID: {password.id}")
                    continue
            
            # Save the updated passwords
            vault._save_passwords()
            
            # Update the encryption service with the new key
            encryption_service._key = new_key
            
            click.echo("Key rotation complete.")
            threading.Event().wait(3600)  # Rotate every hour

    thread = threading.Thread(target=rotate_keys, daemon=True)
    thread.start()

def main():
    """Main entry point."""
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Start key rotation
    start_key_rotation()
    
    # Start CLI
    cli()

if __name__ == '__main__':
    main() 