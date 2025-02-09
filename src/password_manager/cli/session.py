from datetime import datetime, timedelta
from typing import Optional
from functools import wraps
import click
from password_manager.core.auth import AuthenticationService, HashBasedAuth

class Session:
    """Manages user authentication session."""
    
    def __init__(self, timeout_minutes: int = 10):
        self.timeout_minutes = timeout_minutes
        self.last_activity: Optional[datetime] = None
        self.is_authenticated: bool = False
    
    def login(self) -> None:
        """Start a new session."""
        self.last_activity = datetime.now()
        self.is_authenticated = True
    
    def logout(self) -> None:
        """End the current session."""
        self.last_activity = None
        self.is_authenticated = False
    
    def is_valid(self) -> bool:
        """Check if the current session is valid."""
        if not self.is_authenticated or not self.last_activity:
            return False
        
        time_elapsed = datetime.now() - self.last_activity
        return time_elapsed < timedelta(minutes=self.timeout_minutes)
    
    def refresh(self) -> None:
        """Refresh the session timeout."""
        if self.is_authenticated:
            self.last_activity = datetime.now()

# Global session instance
current_session = Session()

def require_auth(auth_service):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_session.is_authenticated:
                # Strip any extra whitespace from the input
                password = click.prompt("Enter master password", hide_input=True).strip()
                if auth_service.authenticate(password):
                    from password_manager.cli.commands import initialize_services
                    initialize_services(auth_service.get_master_key())
                    current_session.login()
                else:
                    click.echo("Authentication failed.")
                    return
            return f(*args, **kwargs)
        return wrapped
    return decorator
# ... rest of the session.py content ... 