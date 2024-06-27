# Password Manager

## Overview

This Password Manager is a secure CLI-based tool designed to store and manage passwords. It uses strong encryption methods to ensure the confidentiality and integrity of stored passwords. The tool supports various features including inserting, showing, updating, and removing passwords, as well as managing directories and rotating encryption keys.

## Features

- **Master Password Encryption**: Securely encrypts and stores the master password.
- **Password Storage**: Encrypts and stores passwords with user-provided descriptions and user IDs.
- **Directory Management**: Supports hierarchical directory structures for organizing passwords.
- **Fingerprint Authentication**: Supports fingerprint authentication on macOS for enhanced security.
- **Session Management**: Implements session timeout to automatically log out the user after a specified period of inactivity.
- **Key Rotation**: Allows re-encryption of all stored passwords with a new encryption key to enhance security.
- **Password Generation**: Generates strong passwords for users.
- **Logging**: Maintains logs for all operations for audit and debugging purposes.

## Technology Stack

- **Python**: Core programming language used to build the CLI tool.
- **Click**: Python package used for creating the command-line interface.
- **Cryptography**: Python package used for encryption and decryption.
- **Fernet**: Symmetric encryption method from the `cryptography` package, using AES in CBC mode with a 128-bit key, PKCS7 padding, and HMAC for integrity.
- **PBKDF2HMAC**: Key derivation function used to derive encryption keys from the master password.
- **UUID**: Used to generate unique identifiers for password entries.
- **Threading**: Ensures thread-safe operations for encryption key management.
- **Logging**: Python’s built-in logging module used to log all operations.

## Security Aspects

- **Encryption**: All passwords are encrypted using Fernet, which implements AES encryption.
- **Key Derivation**: Master password is derived using PBKDF2HMAC with SHA256, ensuring strong key derivation practices.
- **Secure Storage**: Master password and secure key are stored in encrypted form.
- **Permissions**: Files storing sensitive information have restricted permissions (read/write for the owner only).
- **Authentication**: Supports both password-based and fingerprint-based authentication on macOS.
- **Session Management**: Automatically logs out the user after 3600 seconds (1 hour) of inactivity.
- **Key Rotation**: Periodic re-encryption of passwords to maintain security.

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/password-manager.git
   cd ArcanumVault
   ```

2. **Install dependencies**:

   ```bash
   pip install .
   ```

3. **Run the password manager**:

   ```bash
   vault
   ```

4. **Install autocompletion for the CLI**:

   Add the following code to your `.zshrc` file:

   ```bash
   autoload -U compinit
   compinit
   source /Users/chris/Documents/GitHub/ArcanumVault

   _vault() {
     eval $(env COMMANDLINE="${words[1,$CURRENT]}" _VAULT_COMPLETE=complete-zsh  vault)
   }
   if [[ "$(basename -- ${(%):-%x})" != "_vault" ]]; then
     compdef _vault vault
   }
   ```

   Source your `.zshrc` file to apply the changes:

   ```bash
   source ~/.zshrc
   ```

   Close and repoen another instance of your terminal. Then, run the following command to get instructions for installing the autocompletion component:

   ```bash
   vault install-completion
   ```

## Usage

#### Set Master Password

```bash
vault set-master-password
```

#### Authentication

```bash
vault authenticate
```

#### Insert Password Entry

```bash
vault insert [folder]
```

#### Remove Password Entry

```bash
vault remove <vault_id>
```

#### Update Password Entry

```bash
vault update <vault_id>
```

#### Show Password Entries

```bash
vault show [folder]
```

#### Generate Password Entry

```bash
vault generate [folder] <domain> <length>
```

#### Re-encrypt All Password Entries

```bash
vault rotate-key
```

#### Search for Password Entry

```bash
vault search <description>
```

#### Create Folder

```bash
vault create-folder <folder_name>
```

#### Navigate to Folder

```bash
vault goto <directory>
```

#### Print Current Directory

```bash
vault pwd
```

#### export passwords to a CSV file

```bash
vault export <folder_name/file_name>
```

#### import passwords from a CSV file (perviously exported)

```bash
vault export <folder_name/file_name>
```
