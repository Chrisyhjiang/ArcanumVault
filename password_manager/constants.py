import os
from pathlib import Path

# Setup directories and files
DATA_DIR = Path.home() / ".password_manager" / "data"
SECURE_KEY_FILE = Path.home() / ".password_manager" / "secure_key.key"
MASTER_PASSWORD_FILE = Path.home() / ".password_manager" / "master_password.enc"
SESSION_FILE = Path.home() / ".password_manager" / ".session"
CURRENT_DIRECTORY_FILE = Path.home() / ".password_manager" / ".current_directory"
SALT_FILE = Path.home() / ".password_manager" / "salt"
DATA_DIR.mkdir(parents=True, exist_ok=True)

SESSION_TIMEOUT = 3600  # Set session timeout to 3600 seconds (1 hour)
