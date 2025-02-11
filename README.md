# Password Manager Vault

A secure, command-line password manager written in Python that uses a tree-based folder structure to organize your passwords. It leverages strong encryption, hash-based authentication, optional two-factor authentication (2FA) via TOTP, and integrates Git to track changes to your vault.

## Overview

Password Manager Vault is designed for users who need a secure and flexible way to store passwords and sensitive information on their local machine. It uses AES-256 encryption to protect your data, a hash-based mechanism for authentication, and offers an optional 2FA setup for an additional layer of security when changing the master password. The vault is organized as a tree (folders and sub-folders) allowing you to group related passwords, and every change is tracked with Git for version history.

## Features

- **Strong Security:**

  - Uses AES-256 encryption with a key derived via PBKDF2-HMAC.
  - Hash-based authentication with a salt stored on disk.
  - Optional TOTP-based 2FA integration (via [pyotp](https://pypi.org/project/pyotp/)) for master password changes.

- **Tree-Based Structure:**

  - Organize your passwords into folders and sub-folders.
  - Navigate your vault using commands like `cd`, `ls`, `mkdir`, and `rmdir`.

- **Git Integration:**

  - Every change to your vault (adding, updating, or deleting passwords and folders) is committed to a Git repository.
  - View vault history with detailed change information.

- **Command-Line Interface:**
  - Built using [Click](https://click.palletsprojects.com/) for an easy-to-use CLI.
  - Supports a variety of commands including:
    - `set-master-password`: Set or update your master password (with optional 2FA setup).
    - `authenticate`: Authenticate to the vault.
    - `add-password`: Add a new password to a specified folder.
    - `remove` / `delete`: Remove a password from the vault.
    - `ls`: List contents of a folder.
    - `mkdir` and `rmdir`: Create or remove folders.
    - `cd`: Change the current folder in the vault.
    - `show`: Search for a password by domain or username.
    - `git history`: View Git commit history for vault changes.

## Installation

### Prerequisites

- Python 3.7 or newer
- [pip](https://pip.pypa.io/)

### Dependencies

The project relies on several Python packages:

- [Click](https://pypi.org/project/click/)
- [cryptography](https://pypi.org/project/cryptography/)
- [pyotp](https://pypi.org/project/pyotp/)
- [qrcode](https://pypi.org/project/qrcode/)
- [GitPython](https://pypi.org/project/GitPython/)

### Installation Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Chrisyhjiang/ArcanumVault.git
   cd password-manager-vault
   ```

2. **Create a Virtual Environment and Activate It:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   cd password-manager
   pip install -e .
   ```

4. **Run the Application:**

   ```bash
   vault
   ```

## Usage

The vault CLI provides several commands for managing your passwords:

### Core Commands

- `set-master-password`: Set up or change your master password. During setup, you can optionally enable two-factor authentication (2FA) for additional security.

- `authenticate`: Log in to your vault using your master password (and 2FA code if enabled). Authentication is required before accessing any vault contents.

### Password Management

- `add-password`: Add a new password entry to the current folder. You'll be prompted to enter the domain, username, and password. Passwords are encrypted before storage.

- `remove` (or `delete`): Delete a password entry from the vault. You'll need to specify the domain and username of the entry to remove.

- `show`: Search and display password entries by domain or username. The password will be decrypted and displayed securely.

### Folder Navigation

- `ls`: List all contents (passwords and subfolders) in the current folder.

- `mkdir`: Create a new folder to organize your passwords.

- `rmdir`: Remove an empty folder from the vault.

- `cd`: Navigate between folders in the vault, similar to terminal navigation.

### Version Control

- `git history`: View a chronological list of changes made to the vault, including additions, modifications, and deletions of passwords and folders.

## Future Improvements

The following enhancements are planned for future releases:

### Security Enhancements

- **Re-encryption on Master Password Change**: Implement automatic re-encryption of all stored passwords when the master password is changed to maintain security.

### User Experience

- **Graphical User Interface**: Develop a web-based or desktop GUI application for users who prefer visual interfaces over command-line tools.

### Infrastructure

- **Cloud Synchronization**: Add secure cloud backup and synchronization capabilities to enable access across multiple devices.

- **Enhanced Audit Trails**: Provide more comprehensive logging and reporting features:
  - Detailed access logs
  - Password change history
  - Security event monitoring

### Development

- **Automated Testing & CI/CD Pipeline**:
  - Implement comprehensive test suite
  - Set up continuous integration
  - Automate security scanning
  - Streamline deployment process

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes and commit them
4. Push your changes to your fork
5. Create a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
