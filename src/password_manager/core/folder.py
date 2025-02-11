# password_manager/core/folder.py
from dataclasses import dataclass, field
from typing import Dict
from password_manager.core.password import Password

@dataclass
class Folder:
    name: str
    folders: Dict[str, 'Folder'] = field(default_factory=dict)
    passwords: Dict[str, Password] = field(default_factory=dict)

    def add_folder(self, folder_name: str) -> 'Folder':
        if folder_name in self.folders:
            raise ValueError(f"Folder '{folder_name}' already exists.")
        new_folder = Folder(folder_name)
        self.folders[folder_name] = new_folder
        return new_folder

    def delete_folder(self, folder_name: str) -> bool:
        if folder_name in self.folders:
            del self.folders[folder_name]
            return True
        return False

    def add_password(self, password: Password) -> None:
        self.passwords[password.id] = password

    def delete_password(self, password_id: str) -> bool:
        if password_id in self.passwords:
            del self.passwords[password_id]
            return True
        return False
