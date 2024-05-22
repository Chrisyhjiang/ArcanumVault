#!/bin/bash

# Paths to the directories
PASSWORD_MANAGER_DIR="$HOME/.password_manager"
COMPLETION_DIR="$HOME/.password_manager_completion"

# Check and remove .password_manager directory
if [ -d "$PASSWORD_MANAGER_DIR" ]; then
    rm -rf "$PASSWORD_MANAGER_DIR"
    echo "Removed $PASSWORD_MANAGER_DIR"
else
    echo "$PASSWORD_MANAGER_DIR does not exist"
fi

# Check and remove .password_manager_completion directory
if [ -d "$COMPLETION_DIR" ]; then
    rm -rf "$COMPLETION_DIR"
    echo "Removed $COMPLETION_DIR"
else
    echo "$COMPLETION_DIR does not exist"
fi

# Optionally, remove the package installed by pip
pip uninstall password_manager -y

echo "Uninstallation complete."
