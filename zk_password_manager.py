import os
import json
import base64
import nacl.secret
import nacl.utils
from nacl.hash import blake2b
from nacl.encoding import RawEncoder

# Key derivation function
def derive_key(password):
    return blake2b(password.encode(), digest_size=32, encoder=RawEncoder)

# Save encrypted password
def save_password(service, password, master_password):
    key = derive_key(master_password)
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(password.encode(), nonce)
    data = {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(encrypted.ciphertext).decode()
    }
    with open(f"{service}.json", "w") as f:
        json.dump(data, f)

# Load and decrypt a password
def load_password(service, master_password):
    key = derive_key(master_password)
    box = nacl.secret.SecretBox(key)
    try:
        with open(f"{service}.json", "r") as f:
            data = json.load(f)
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        plaintext = box.decrypt(ciphertext, nonce)
        return plaintext.decode()
    except FileNotFoundError:
        return "Service not found."
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# List all saved services
def list_services():
    return [file.split('.')[0] for file in os.listdir('.') if file.endswith('.json')]

# Main function to handle the command line interface
def main():
    while True:
        print("\nPassword Manager")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. List all services")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            password = input("Enter the password: ")
            master_password = input("Enter your master password: ")
            save_password(service, password, master_password)
            print("Password saved successfully!")
        elif choice == '2':
            service = input("Enter the service name: ")
            master_password = input("Enter your master password: ")
            result = load_password(service, master_password)
            print(f"Password: {result}")
        elif choice == '3':
            services = list_services()
            print("Saved services:")
            for service in services:
                print(service)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
