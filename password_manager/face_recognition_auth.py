from .face_data import capture_face, authenticate_face

def capture_user_face():
    """Capture and store user's face data."""
    capture_face()

def authenticate_user_face():
    """Authenticate user using facial recognition."""
    return authenticate_face()
