# password_manager/core/vault.py

import json
import base64
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from password_manager.core.password import Password
import os

class PasswordVault:
    """Manages the storage and retrieval of passwords."""
    
    def __init__(self, encryption_service, storage_path: Path):
        self.encryption = encryption_service
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._passwords: Dict[str, Password] = {}
        self._load_passwords()
    
    def add_password(self, domain: str, username: str, password: str, description: Optional[str] = None) -> Password:
        """Add a new password to the vault."""
        encrypted_password = self.encryption.encrypt(password.encode())
        password_entry = Password.create(
            domain=domain,
            username=username,
            encrypted_password=encrypted_password,
            description=description
        )
        self._passwords[password_entry.id] = password_entry
        self._save_passwords()
        return password_entry
    
    def get_password(self, password_id: str) -> Optional[Password]:
        """Retrieve a password by its ID."""
        return self._passwords.get(password_id)
    
    def get_decrypted_password(self, password_id: str) -> Optional[str]:
        """Get the decrypted password string for a given password ID."""
        password_entry = self.get_password(password_id)
        if password_entry:
            decrypted = self.encryption.decrypt(password_entry.encrypted_password)
            return decrypted.decode()
        return None
    
    def list_passwords(self) -> List[Password]:
        """List all passwords in the vault."""
        return list(self._passwords.values())
    
    def delete_password(self, password_id: str) -> bool:
        """Delete a password from the vault."""
        if password_id in self._passwords:
            del self._passwords[password_id]
            self._save_passwords()
            return True
        return False
    
    def _save_passwords(self):
        """Save passwords to storage."""
        passwords_data = {
            id_: {
                'id': p.id,
                'domain': p.domain,
                'username': p.username,
                'encrypted_password': base64.b64encode(p.encrypted_password).decode(),
                'description': p.description,
                'created_at': p.created_at.isoformat(),
                'modified_at': p.modified_at.isoformat()
            }
            for id_, p in self._passwords.items()
        }
        
        file_path = self.storage_path / 'passwords.json'
        with open(file_path, 'w') as f:
            json.dump(passwords_data, f, indent=2)
        # Set file permission to read/write for owner only
        os.chmod(file_path, 0o600)
    
    def _load_passwords(self):
        """Load passwords from storage."""
        try:
            with open(self.storage_path / 'passwords.json', 'r') as f:
                passwords_data = json.load(f)
                
            self._passwords = {
                id_: Password(
                    id=data['id'],
                    domain=data['domain'],
                    username=data['username'],
                    encrypted_password=base64.b64decode(data['encrypted_password']),
                    description=data['description'],
                    created_at=datetime.fromisoformat(data['created_at']),
                    modified_at=datetime.fromisoformat(data['modified_at'])
                )
                for id_, data in passwords_data.items()
            }
        except FileNotFoundError:
            self._passwords = {}
