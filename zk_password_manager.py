import hashlib
import secrets


# One-way hash function
def H(*args):
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

# Random number generator
def cryptrand(n=1024):
    return secrets.randbits(n)

# Large safe prime N (2048-bit) and base g (generator)
N = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5F4385B9E8A3B1469B1A7E3F4ABE83B203F1B96F64B9F9C8B9E3F8B53FC8D20F51E5D69EE1C2973C14C5066CC8043546A99F56E0E1BA77DB39BB6363E8D0D512F83C16D353BEE7AC7234A835A1456B33C9CC36A189F04868D3319D7DF77A89B5453DA6D0EBCD9C2C2F7B782A58F33', 16)
g = 2
k = H(N, g)  # Multiplier parameter

class PasswordManager:
    def __init__(self):
        self.users = {}

    def register(self, username, password):
        salt = cryptrand(64)
        x = H(salt, username, password)
        v = pow(g, x, N)
        self.users[username] = {"salt": salt, "verifier": v}
        print(f"User {username} registered successfully.")

    def authenticate(self, username, password):
        if username not in self.users:
            print(f"User {username} not found.")
            return False
        
        try:
            user = self.users[username]
            salt, v = user["salt"], user["verifier"]

            # SRP protocol
            a, b = cryptrand(), cryptrand()
            A, B = pow(g, a, N), (k * v + pow(g, b, N)) % N

            u = H(A, B)
            x = H(salt, username, password)
            S_c = pow(B - k * pow(g, x, N), a + u * x, N)
            K_c = H(S_c)

            S_s = pow(A * pow(v, u, N), b, N)
            K_s = H(S_s)

            if K_c == K_s:
                print(f"User {username} authenticated successfully.")
                return True
            else:
                print("Authentication failed.")
                return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    def change_password(self, username, old_password, new_password):
        if self.authenticate(username, old_password):
            salt = cryptrand(64)
            x = H(salt, username, new_password)
            v = pow(g, x, N)
            self.users[username] = {"salt": salt, "verifier": v}
            print(f"Password changed successfully for user {username}.")
        else:
            print("Failed to change password due to failed authentication.")
