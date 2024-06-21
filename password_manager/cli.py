import click
from .auth import ensure_authenticated, authenticate_user, encrypt_master_password
from .password_operations import (insert_password, show_passwords, remove_password, generate_password, update_password, reformat_passwords, delete_all_passwords, search_passwords, reencrypt_passwords)
from .folder_operations import create_folder, goto_directory
from .utils import cipher_singleton, load_current_directory
from .constants import DATA_DIR

@click.group()
def vault():
    pass

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
    goto_directory(directory)

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
    vault()
