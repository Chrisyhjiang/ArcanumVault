import click
import os
import json
import base64
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
import qrcode
import pyotp

# Import your modules
from password_manager.core.auth import HashBasedAuth
from password_manager.core.encryption import AES256Encryption
from password_manager.core.vault import PasswordVault
from password_manager.cli.session import current_session

# Set the data directory (e.g., ~/.password_manager_data)
DATA_DIR = Path(os.path.expanduser('~/.password_manager_data'))
MASTER_PASSWORD_FILE = DATA_DIR / 'master.key'
TOTP_SECRET_FILE = DATA_DIR / 'totp.secret'

# Initialize auth service
auth_service = HashBasedAuth(MASTER_PASSWORD_FILE)

# Global variables for encryption service and vault; these will be set upon authentication.
encryption_service = None
vault = None

def initialize_services(master_key: bytes):
    """Initialize encryption service and vault using the persisted salt."""
    global encryption_service, vault
    encryption_service = AES256Encryption(master_key=master_key, salt=auth_service.salt)
    vault = PasswordVault(encryption_service, DATA_DIR)

def require_auth(f):
    """Decorator to require authentication before executing a command."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_session.is_valid() or current_session.master_key is None:
            password = click.prompt("Enter master password", hide_input=True).strip()
            if auth_service.authenticate(password):
                master_key = auth_service.get_master_key()
                initialize_services(master_key)
                current_session.login(master_key)
            else:
                click.echo("Authentication failed.")
                return
        else:
            current_session.refresh()
            try:
                initialize_services(current_session.master_key)
            except Exception as e:
                click.echo("Failed to reinitialize services. Please authenticate again.")
                return
        return f(*args, **kwargs)
    return wrapped

@click.group()
def cli():
    """Password Manager CLI

    This tool allows you to securely manage your passwords in a tree-based structure.
    Use the commands below to add, search, and manage your passwords and folders.
    """
    pass

@cli.command()
def set_master_password():
    """
    Set or update the master password for authentication.
    
    Users can optionally set up 2FA via TOTP for extra security.
    If 2FA is set up, it will be required to change the master password in the future.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)

    if not TOTP_SECRET_FILE.exists():
        if click.confirm("Do you want to set up 2FA for extra security?"):
            totp_secret = pyotp.random_base32()
            TOTP_SECRET_FILE.write_text(totp_secret)
            os.chmod(TOTP_SECRET_FILE, 0o600)
            totp = pyotp.TOTP(totp_secret)
            provisioning_uri = totp.provisioning_uri(name="password_manager", issuer_name="YourAppName")
            qr = qrcode.make(provisioning_uri)
            qr.show()
            click.echo("A new 2FA secret has been generated and a QR code has been displayed.")
            click.echo("Please scan the QR code with your authenticator app, then run this command again to change the master password.")
            return
        else:
            click.echo("Proceeding without 2FA. Master password will be set, but future changes won't require 2FA.")
    else:
        totp_secret = TOTP_SECRET_FILE.read_text().strip()
        totp = pyotp.TOTP(totp_secret)
        code = click.prompt("Enter the current 2FA code from your authenticator app").strip()
        if not totp.verify(code):
            click.echo("Invalid 2FA code. Aborting master password change.")
            return

    password = click.prompt('Enter new master password', hide_input=True, confirmation_prompt=True).strip()
    auth_service.set_master_password(password)
    master_key = auth_service.get_master_key()
    initialize_services(master_key)
    current_session.login(master_key)
    click.echo("Master password set successfully.")

@cli.command()
def authenticate():
    """Authenticate with the master password."""
    password = click.prompt("Enter master password", hide_input=True).strip()
    if auth_service.authenticate(password):
        master_key = auth_service.get_master_key()
        initialize_services(master_key)
        current_session.login(master_key)
        click.echo("Authentication successful.")
    else:
        click.echo("Authentication failed.")

@cli.command()
@require_auth
@click.option('--path', default=None, help='Folder path where to add the password. If omitted, uses the current directory.')
def add_password(path):
    """Add a new password to the vault in the specified folder."""
    if path is None:
        path = current_session.current_path
    domain = click.prompt('Domain')
    username = click.prompt('Username')
    pwd = click.prompt('Password', hide_input=True).strip()
    description = click.prompt('Description', default='', show_default=False)
    try:
        password_entry = vault.add_password(path, domain, username, pwd, description)
        click.echo(f"Password for {domain} added successfully with ID: {password_entry.id}")
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command(name="remove")
@require_auth
@click.option('--path', default='/', help='Folder path where the password is stored (default: root "/").')
def remove_password(path):
    """Remove a password by ID from the specified folder."""
    pwd_id = click.prompt('Password ID')
    if vault.delete_password(pwd_id, path):
        click.echo("Password deleted successfully!")
    else:
        click.echo("Password not found.")

@cli.command()
@require_auth
@click.option('--path', default=None, help='Folder path to list. If omitted, uses the current directory.')
def ls(path):
    """List the contents of the specified folder."""
    if path is None:
        path = current_session.current_path
    try:
        folder = vault.list_folder(path)
        click.echo(f"Contents of folder '{path}':")
        if folder.folders:
            click.echo("Folders:")
            for name in folder.folders:
                click.echo(f"  {name}/")
        if folder.passwords:
            click.echo("Passwords:")
            for pid, pwd in folder.passwords.items():
                click.echo(f"  {pid}: {pwd.domain} ({pwd.username})")
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
@require_auth
@click.argument('folder_path')
def mkdir(folder_path):
    """Create a new folder under the specified parent folder path."""
    new_folder_name = click.prompt("Enter new folder name")
    try:
        new_folder = vault.add_folder(folder_path, new_folder_name)
        click.echo(f"Folder '{new_folder_name}' created under '{folder_path}'.")
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
@require_auth
@click.argument('folder_path')
def rmdir(folder_path):
    """Delete the specified folder (by its full path)."""
    if vault.delete_folder(folder_path):
        click.echo(f"Folder '{folder_path}' deleted.")
    else:
        click.echo(f"Folder '{folder_path}' not found or could not be deleted.")

@cli.command()
@require_auth
@click.option('--path', default='/', help='Folder path to search in (default: root "/").')
def show(path):
    """Search for a password by domain or username in the specified folder."""
    query = click.prompt('Enter domain or username to search')
    try:
        folder = vault.list_folder(path)
    except Exception as e:
        click.echo(f"Error: {str(e)}")
        return
    matching_passwords = [
        pwd for pwd in folder.passwords.values()
        if query.lower() in pwd.domain.lower() or query.lower() in pwd.username.lower()
    ]
    if not matching_passwords:
        click.echo("No matching passwords found in this folder.")
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
            decrypted = vault.get_decrypted_password(selected_password.id, folder_path=path)
            click.echo(f"Password: {decrypted}")
        except Exception as e:
            click.echo("Failed to decrypt password.")

@cli.command()
@require_auth
@click.option('--path', default='/', help='Folder path where the password is stored (default: root "/").')
def delete(path):
    """Delete a password by ID from the specified folder."""
    pwd_id = click.prompt('Password ID')
    if vault.delete_password(pwd_id, path):
        click.echo("Password deleted successfully!")
    else:
        click.echo("Password not found.")

@cli.command()
@require_auth
@click.argument('folder_path')
def cd(folder_path):
    """Change the current directory in the vault."""
    import os
    norm_path = os.path.normpath(folder_path)
    if norm_path in ['.', './']:
        norm_path = "/"
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    try:
        _ = vault.list_folder(norm_path)
        current_session.current_path = norm_path
        current_session.save_session()
        click.echo(f"Changed current directory to: {norm_path}")
    except Exception as e:
        click.echo(f"Error: {str(e)}")

@cli.command()
def install_completion():
    """Install shell completion for the vault command."""
    click.echo("To enable shell completion, add the following line to your shell's configuration file:")
    click.echo('eval "$(_VAULT_COMPLETE=source_bash vault)"')

# --- Git integration ---

def get_active_vault():
    """Return the active vault, or None if not available."""
    global vault
    return vault

@click.group()
def git():
    """Git operations for vault history."""
    pass

@git.command()
@require_auth
@click.option('--count', default=10, help='Number of commits to show')
@click.option('--detailed/--simple', default=False, help='Show detailed change information')
def history(count, detailed):
    """Show vault change history with details about what changed."""
    active_vault = get_active_vault()
    if not active_vault:
        click.echo("No active vault. Please authenticate first.")
        return

    commits = active_vault.get_history(max_count=count)
    if not commits:
        click.echo("No history found.")
        return

    for commit in commits:
        click.echo(f"\nCommit: {commit['hash'][:8]}")
        click.echo(f"Author: {commit['author']}")
        click.echo(f"Date: {commit['date']}")
        click.echo(f"Action: {commit['message']}")
        if detailed and commit.get('changes'):
            click.echo("Changed files:")
            for change in commit['changes']:
                click.echo(f"  - {change['change_type']}: {change['path']}")

cli.add_command(git)

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    cli()

if __name__ == '__main__':
    main()
