import json
import os
from getpass import getpass
from pysrp import User, Verifier
from cryptography.fernet import Fernet

# Constants for file paths and keys
DATA_FILE = 'password_store.json'
KEY_FILE = 'secret.key'

# Generate or load encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return Fernet(key)

# Encrypt and decrypt functions
def encrypt_data(data, fernet):
    return fernet.encrypt(data.encode())

def decrypt_data(data, fernet):
    return fernet.decrypt(data).decode()

# Load or initialize password store
def load_password_store(fernet):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, fernet)
        return json.loads(decrypted_data)

def save_password_store(password_store, fernet):
    with open(DATA_FILE, 'wb') as file:
        data = json.dumps(password_store)
        encrypted_data = encrypt_data(data, fernet)
        file.write(encrypted_data)

# SRP User setup
def setup_srp_user(username, password):
    user = User(username, password)
    verifier, salt = user.verifier
    return verifier, salt

# SRP Authentication
def authenticate_srp(username, password, verifier, salt):
    user = User(username, password, salt=salt)
    A = user.start_authentication()
    server = Verifier(username, salt, verifier, A)
    M = user.process_challenge(server.B)
    HAMK = server.verify_session(A, M)
    return user.verify_session(HAMK)

# CLI Functions
def add_password(username, password_store, fernet):
    service = input('Service: ')
    password = getpass('Password: ')
    password_store[service] = password
    save_password_store(password_store, fernet)
    print(f'Password for {service} added.')

def get_password(service, password_store):
    if service in password_store:
        print(f'Password for {service}: {password_store[service]}')
    else:
        print(f'No password found for {service}.')

def main():
    username = input('Username: ')
    master_password = getpass('Master Password: ')

    verifier, salt = setup_srp_user(username, master_password)
    fernet = load_key()
    password_store = load_password_store(fernet)

    if not authenticate_srp(username, master_password, verifier, salt):
        print('Authentication failed.')
        return

    while True:
        action = input('Choose an action (add, get, exit): ')
        if action == 'add':
            add_password(username, password_store, fernet)
        elif action == 'get':
            service = input('Service: ')
            get_password(service, password_store)
        elif action == 'exit':
            break
        else:
            print('Invalid action.')

if __name__ == '__main__':
    main()
