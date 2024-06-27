import cv2
import face_recognition
import os
import pickle

FACE_DATA_DIR = "face_data"
FACE_DATA_FILE = os.path.join(FACE_DATA_DIR, "face_encoding.pkl")

def capture_face():
    if not os.path.exists(FACE_DATA_DIR):
        os.makedirs(FACE_DATA_DIR)

    cap = cv2.VideoCapture(0)
    print("Capturing face. Please look at the camera...")
    while True:
        ret, frame = cap.read()
        if not ret:
            print("Failed to capture image")
            break

        cv2.imshow('Press "q" to capture', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

    if ret:
        face_encodings = face_recognition.face_encodings(frame)
        if face_encodings:
            face_encoding = face_encodings[0]
            with open(FACE_DATA_FILE, "wb") as f:
                pickle.dump(face_encoding, f)
            print("Face data captured and stored.")
        else:
            print("No face detected. Please try again.")
    else:
        print("Camera capture failed. Please try again.")

def load_face_data():
    if not os.path.exists(FACE_DATA_FILE):
        print("No face data found. Please capture face first.")
        return None
    with open(FACE_DATA_FILE, "rb") as f:
        face_encoding = pickle.load(f)
    return face_encoding

def authenticate_face():
    saved_face_encoding = load_face_data()
    if saved_face_encoding is None:
        return False

    cap = cv2.VideoCapture(0)
    print("Authenticating. Please look at the camera...")
    while True:
        ret, frame = cap.read()
        if not ret:
            print("Failed to capture image")
            break

        cv2.imshow('Press "q" to authenticate', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

    if ret:
        face_encodings = face_recognition.face_encodings(frame)
        if face_encodings:
            face_encoding = face_encodings[0]
            matches = face_recognition.compare_faces([saved_face_encoding], face_encoding)
            if matches[0]:
                print("Authentication successful!")
                return True
            else:
                print("Authentication failed.")
                return False
        else:
            print("No face detected. Please try again.")
            return False
    else:
        print("Camera capture failed. Please try again.")
        return False
