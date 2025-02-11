import json
from datetime import datetime, timedelta
from pathlib import Path

SESSION_FILE = Path.home() / ".password_manager_session.json"

class Session:
    def __init__(self, timeout_minutes: int = 30):
        self.timeout_minutes = timeout_minutes
        self.last_activity = None
        self.is_authenticated = False
        self.master_key = None  # Store the master key (as bytes) if available.
        self.current_path = "/"  # Default current directory is root.
        self.load_session()

    def login(self, master_key: bytes):
        self.last_activity = datetime.now()
        self.is_authenticated = True
        self.master_key = master_key
        # Set current_path to root by default on login.
        self.current_path = "/"
        self.save_session()

    def logout(self):
        self.last_activity = None
        self.is_authenticated = False
        self.master_key = None
        self.current_path = "/"
        self.save_session()

    def is_valid(self):
        if not self.is_authenticated or not self.last_activity:
            return False
        return (datetime.now() - self.last_activity) < timedelta(minutes=self.timeout_minutes)

    def refresh(self):
        if self.is_authenticated:
            self.last_activity = datetime.now()
            self.save_session()

    def save_session(self):
        session_data = {
            "is_authenticated": self.is_authenticated,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "master_key": self.master_key.hex() if self.master_key else None,
            "current_path": self.current_path,
        }
        with open(SESSION_FILE, "w") as f:
            json.dump(session_data, f)

    def load_session(self):
        if SESSION_FILE.exists():
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
                self.is_authenticated = data.get("is_authenticated", False)
                if data.get("last_activity"):
                    self.last_activity = datetime.fromisoformat(data["last_activity"])
                else:
                    self.last_activity = None
                master_key_hex = data.get("master_key")
                if master_key_hex:
                    self.master_key = bytes.fromhex(master_key_hex)
                else:
                    self.master_key = None
                self.current_path = data.get("current_path", "/")

# Global session instance with a 30-minute timeout
current_session = Session(timeout_minutes=30)
