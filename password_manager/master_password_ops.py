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
