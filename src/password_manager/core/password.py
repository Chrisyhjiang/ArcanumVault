from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import uuid

@dataclass
class Password:
    """Represents a stored password entry."""
    id: str
    domain: str
    username: str
    encrypted_password: bytes
    description: Optional[str] = None
    created_at: datetime = datetime.now()
    modified_at: datetime = datetime.now()
    
    @classmethod
    def create(cls, domain: str, username: str, encrypted_password: bytes, description: Optional[str] = None) -> 'Password':
        """Create a new password entry."""
        return cls(
            id=str(uuid.uuid4()),
            domain=domain,
            username=username,
            encrypted_password=encrypted_password,
            description=description
        ) 