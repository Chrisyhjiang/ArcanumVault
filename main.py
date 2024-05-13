import tkinter as tk
from tkinter import messagebox, simpledialog
import os

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.username = ""
        self.password = ""

        self.password_manager = PasswordManager()

        self.username_label = tk.Label(master, text="Username:")
        self.username_label.grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = tk.Entry(master)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=5)
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        self.login_button = tk.Button(master, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.change_password_button = tk.Button(master, text="Change Password", command=self.change_password)
        self.change_password_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.delete_account_button = tk.Button(master, text="Delete Account", command=self.delete_account)
        self.delete_account_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.load_data()

    def load_data(self):
        try:
            with open("password_manager_data.txt", "r") as file:
                data = file.readlines()
                if len(data) == 2:
                    self.username = data[0].strip()
                    self.password = data[1].strip()
        except FileNotFoundError:
            pass

    def save_data(self):
        with open("password_manager_data.txt", "w") as file:
            file.write(self.username + "\n")
            file.write(self.password)

    def login(self):
        self.username = self.username_entry.get()
        self.password = self.password_entry.get()
        if self.password_manager.authenticate(self.username, self.password):
            messagebox.showinfo("Success", f"User {self.username} authenticated successfully.")
            self.save_data()
        else:
            messagebox.showerror("Error", "Authentication failed. Please try again.")

    def change_password(self):
        new_password = simpledialog.askstring("Change Password", "Enter new password:")
        if new_password:
            self.password_manager.change_password(self.username, self.password, new_password)
            messagebox.showinfo("Success", "Password changed successfully.")
            self.password = new_password
            self.save_data()

    def delete_account(self):
        confirm = messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?")
        if confirm:
            self.password_manager.delete_user(self.username, self.password)
            messagebox.showinfo("Success", "Account deleted successfully.")
            self.master.destroy()


def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
