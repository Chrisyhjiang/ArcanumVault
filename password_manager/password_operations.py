import os
import click
import uuid
import logging
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from .constants import DATA_DIR
from .utils import key_lock, load_current_directory, get_password_file_path, cipher_singleton, derive_key

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

def insert_password(domain, description, user_id, user_password, folder=None):
    with key_lock:
        try:
            cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
        except ValueError:
            click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
            return

        vault_id = str(uuid.uuid4())
        encrypted_password = cipher.encrypt(user_password.encode())
        password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
        file_path = get_password_file_path(domain, folder)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write(password_entry)
        click.echo(f"Password for {domain} inserted with description, User ID, and vaultID {vault_id}.")

def show_passwords(directory, indent_level=0):
    """Recursively show passwords and folders."""
    try:
        cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
    except ValueError:
        click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
        return

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

def remove_password(vault_id, folder=None):
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

def generate_password(domain, length, description, user_id, folder=None):
    import random
    import string
    generated_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    try:
        cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
    except ValueError:
        click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
        return

    encrypted_password = cipher.encrypt(generated_password.encode())
    vault_id = str(uuid.uuid4())
    password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
    file_path = get_password_file_path(domain, folder)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        f.write(password_entry)
    click.echo(f"Generated password for {domain} with description, User ID, and vaultID {vault_id}: {generated_password}")

def update_password(vault_id, new_description, new_user_id, new_password, folder=None):
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

        try:
            cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
        except ValueError:
            click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
            return

        encrypted_password = cipher.encrypt(new_password.encode()).decode()
        password_entry = f"{vault_id}\n{new_description}\n{new_user_id}\n{encrypted_password}"
        with open(file_path, 'w') as f:
            f.write(password_entry)
        click.echo(f"Updated entry with vault ID {vault_id}.")

def reformat_passwords():
    with key_lock:
        current_dir = load_current_directory()
        try:
            cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
        except ValueError:
            click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
            return

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

def delete_all_passwords():
    with key_lock:
        for root, dirs, files in os.walk(DATA_DIR, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        click.echo("All password entries and directories have been deleted.")

def search_passwords(description):
    results = []

    def search_passwords_in_dir(dir_path, description):
        try:
            cipher = cipher_singleton.get_cipher()  # Get the cipher from the singleton
        except ValueError:
            click.echo("Cipher not initialized. Run 'vault set-master-password' to set it.")
            return

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
                search_passwords_in_dir(sub_dir, description)

    current_dir = load_current_directory()
    search_passwords_in_dir(current_dir, description)

    if results:
        for domain, vault_id, desc, user_id, password in results:
            click.echo(f"\nDomain: {domain}\nVault ID: {vault_id}\nDescription: {desc}\nUser ID: {user_id}\nPassword: {password}\n")
    else:
        click.echo("No matching descriptions found.")
