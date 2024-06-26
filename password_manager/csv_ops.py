# csv_ops.py
import csv
import click
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from .cipher import CipherSingleton
from .utils import DATA_DIR, get_password_file_path, load_current_directory
from .master_password_ops import store_master_password

def export_passwords_to_csv(file_path):
    """Export passwords to a CSV file."""
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['Folder', 'Domain', 'Description', 'User ID', 'Password', 'Vault ID']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        cipher = CipherSingleton().get_cipher()
        current_directory = load_current_directory()
        for root, _, files in os.walk(current_directory):
            relative_folder = os.path.relpath(root, current_directory)
            for file in files:
                if file.endswith('.pass'):
                    file_path = Path(root) / file
                    with open(file_path, 'r') as f:
                        lines = f.read().splitlines()
                        if len(lines) < 4:
                            continue
                        vault_id = lines[0]
                        description = lines[1]
                        user_id = lines[2]
                        encrypted_password = lines[3].encode()
                        password = cipher.decrypt(encrypted_password).decode()
                        writer.writerow({
                            'Folder': relative_folder,
                            'Domain': file_path.stem,
                            'Description': description,
                            'User ID': user_id,
                            'Password': password,
                            'Vault ID': vault_id
                        })
    click.echo(f"Passwords exported to {file_path}")

def import_passwords_from_csv(file_path):
    from .cipher import cipher_singleton
    """Import passwords from a CSV file.
        First we need to set the master password on the old device
    """
    store_master_password(click.prompt('Enter the master password used for exporting', hide_input=True))
    cipher_singleton.refresh_cipher()
    
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        current_directory = load_current_directory()
        for row in reader:
            folder = row['Folder']
            domain = row['Domain']
            description = row['Description']
            user_id = row['User ID']
            password = row['Password']
            vault_id = row['Vault ID']

            encrypted_password = cipher.encrypt(password.encode())
            password_entry = f"{vault_id}\n{description}\n{user_id}\n{encrypted_password.decode()}"
            target_folder = current_directory / folder
            target_file_path = get_password_file_path(domain, target_folder)
            target_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_file_path, 'w') as f:
                f.write(password_entry)
    click.echo(f"Passwords imported from {file_path}")
