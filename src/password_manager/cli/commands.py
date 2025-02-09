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
from functools import wraps

# Set the data directory to a subdirectory in the user's home directory
DATA_DIR = Path(os.path.expanduser('~/.password_manager_data'))
MASTER_PASSWORD_FILE = DATA_DIR / 'master.key'

# Initialize auth service
auth_service = HashBasedAuth(MASTER_PASSWORD_FILE)

# Initialize encryption service with None - will be set after authentication
encryption_service = None
vault = None

def initialize_services(master_key: bytes):
    """Initialize encryption service and vault with the master key."""
    global encryption_service, vault
    encryption_service = AES256Encryption(master_key=master_key)
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
        decrypted = vault.get_decrypted_password(selected_password.id)
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
    initialize_services(auth_service.get_master_key())
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

def main():
    """Main entry point."""
    # Ensure data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Start CLI
    cli()

if __name__ == '__main__':
    main() 