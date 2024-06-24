import logging
import os
import click
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from .cipher import cipher_singleton
from .utils import (MASTER_PASSWORD_FILE, set_permissions, load_secure_key, DATA_DIR)

def encrypt_master_password(password: str):
    """Encrypt and store the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    encrypted_password = fernet.encrypt(password.encode())
    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_password)
    set_permissions(MASTER_PASSWORD_FILE)
    logging.info("Master password stored in encrypted form on disk.")


def store_master_password(password: str):
    """Store the master password and refresh the cipher."""
    encrypt_master_password(password)
    cipher_singleton.refresh_cipher()

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

def decrypt_master_password():
    """Decrypt and return the master password using the secure key."""
    secure_key = load_secure_key()
    fernet = Fernet(secure_key)
    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_password = f.read()
    password = fernet.decrypt(encrypted_password).decode()
    return password
