# password_manager/core/vault.py
import json
import base64
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from password_manager.core.folder import Folder
from password_manager.core.password import Password
from .git_manager import GitManager

class PasswordVault:
    """Manages password storage in a tree-based folder structure."""
    
    def __init__(self, encryption_service, storage_path: Path):
        self.encryption = encryption_service
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.root = self._load_tree()
        self.git_manager = GitManager(storage_path)
        self.git_manager.initialize_repo()

    def _get_tree_file(self) -> Path:
        return self.storage_path / 'vault_tree.json'

    def _save_tree(self) -> None:
        tree_dict = self._folder_to_dict(self.root)
        file_path = self._get_tree_file()
        with open(file_path, 'w') as f:
            json.dump(tree_dict, f, indent=2)
        os.chmod(file_path, 0o600)

    def _load_tree(self) -> Folder:
        file_path = self._get_tree_file()
        if file_path.exists():
            with open(file_path, 'r') as f:
                tree_dict = json.load(f)
            return self._dict_to_folder(tree_dict)
        else:
            return Folder(name="root")

    def _folder_to_dict(self, folder: Folder) -> dict:
        return {
            "name": folder.name,
            "folders": {name: self._folder_to_dict(subfolder) for name, subfolder in folder.folders.items()},
            "passwords": {pid: self._password_to_dict(pwd) for pid, pwd in folder.passwords.items()}
        }

    def _password_to_dict(self, pwd: Password) -> dict:
        return {
            "id": pwd.id,
            "domain": pwd.domain,
            "username": pwd.username,
            "encrypted_password": base64.b64encode(pwd.encrypted_password).decode(),
            "description": pwd.description,
            "created_at": pwd.created_at.isoformat(),
            "modified_at": pwd.modified_at.isoformat()
        }

    def _dict_to_folder(self, d: dict) -> Folder:
        folder = Folder(name=d.get("name", "root"))
        folder.folders = {name: self._dict_to_folder(subfolder) for name, subfolder in d.get("folders", {}).items()}
        folder.passwords = {}
        for pid, p_data in d.get("passwords", {}).items():
            pwd = Password(
                id=p_data["id"],
                domain=p_data["domain"],
                username=p_data["username"],
                encrypted_password=base64.b64decode(p_data["encrypted_password"]),
                description=p_data.get("description"),
                created_at=datetime.fromisoformat(p_data["created_at"]),
                modified_at=datetime.fromisoformat(p_data["modified_at"])
            )
            folder.passwords[pid] = pwd
        return folder

    def _get_folder_by_path(self, folder_path: str) -> Optional['Folder']:
        # Normalize the path to handle relative paths.
        norm_path = os.path.normpath(folder_path)
        # Treat '.' or './' as root.
        if norm_path in ['.', './']:
            norm_path = '/'
        # If the normalized path does not start with '/', assume it's relative to the root.
        if not norm_path.startswith('/'):
            norm_path = '/' + norm_path
        # If the normalized path is empty or root, return the root folder.
        if norm_path.strip() in ["", "/"]:
            return self.root
        parts = norm_path.strip("/").split("/")
        current = self.root
        for part in parts:
            if part in current.folders:
                current = current.folders[part]
            else:
                return None
        return current

    # New tree-based operations:
    def add_password(self, folder_path: str, domain: str, username: str, password: str, description: Optional[str] = None) -> Password:
        folder = self._get_folder_by_path(folder_path)
        if folder is None:
            raise ValueError(f"Folder path '{folder_path}' does not exist.")
        encrypted_password = self.encryption.encrypt(password.encode())
        password_entry = Password.create(domain, username, encrypted_password, description)
        folder.add_password(password_entry)
        self._save_tree()
        self.git_manager.commit_changes(f"Added password for {domain} in {folder_path}")
        return password_entry

    def delete_password(self, password_id: str, folder_path: str) -> bool:
        folder = self._get_folder_by_path(folder_path)
        if folder is None:
            return False
        password = folder.passwords.get(password_id)
        result = folder.delete_password(password_id)
        if result and password:
            self._save_tree()
            self.git_manager.commit_changes(f"Deleted password for {password.domain} from {folder_path}")
        return result

    def get_decrypted_password(self, password_id: str, folder_path: str = "/") -> Optional[str]:
        folder = self._get_folder_by_path(folder_path)
        if folder is None:
            return None
        if password_id in folder.passwords:
            decrypted = self.encryption.decrypt(folder.passwords[password_id].encrypted_password)
            return decrypted.decode()
        return None

    def add_folder(self, folder_path: str, new_folder_name: str) -> Folder:
        folder = self._get_folder_by_path(folder_path)
        if folder is None:
            raise ValueError(f"Folder path '{folder_path}' does not exist.")
        new_folder = folder.add_folder(new_folder_name)
        self._save_tree()
        self.git_manager.commit_changes(f"Created new folder '{new_folder_name}' in {folder_path}")
        return new_folder

    def delete_folder(self, folder_path: str) -> bool:
        parts = folder_path.strip("/").split("/")
        if not parts:
            raise ValueError("Invalid folder path.")
        folder_name = parts[-1]
        parent_path = "/" + "/".join(parts[:-1]) if parts[:-1] else "/"
        parent_folder = self._get_folder_by_path(parent_path)
        if parent_folder is None:
            return False
        result = parent_folder.delete_folder(folder_name)
        if result:
            self._save_tree()
            self.git_manager.commit_changes(f"Deleted folder '{folder_name}' from {parent_path}")
        return result

    def list_folder(self, folder_path: str) -> Folder:
        folder = self._get_folder_by_path(folder_path)
        if folder is None:
            raise ValueError(f"Folder path '{folder_path}' does not exist.")
        return folder

    def save(self):
        """Save the vault and commit changes to git."""
        self._save_tree()
        
        # Commit changes to git
        self.git_manager.commit_changes("Updated vault contents")

    def get_history(self, max_count: int = 10):
        """Get vault change history from git."""
        return self.git_manager.get_history(max_count)
