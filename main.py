import tkinter as tk
from tkinter import messagebox, simpledialog
import os

from zk_password_manager import PasswordManager  # Import your PasswordManager class

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.password_manager = PasswordManager()

        if not self.password_manager.users:
            self.register_first_time()

        self.authenticate_user()

    def register_first_time(self):
        # Prompt the user to register for the first time
        username = os.getlogin()
        password = simpledialog.askstring("Register", f"Enter your password or fingerprint to register as user {username}:")
        self.password_manager.register(username, password)

    def authenticate_user(self):
        # Prompt the user for authentication
        username = os.getlogin()
        password = simpledialog.askstring("Authenticate", f"Enter your password or fingerprint to log in as user {username}:")
        if not self.password_manager.authenticate(username, password):
            messagebox.showerror("Authentication Failed", "Authentication failed. Exiting...")
            self.master.destroy()

def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
