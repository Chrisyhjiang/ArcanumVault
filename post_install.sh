#!/bin/bash

# Ensure the completion script directory exists
mkdir -p ~/.password_manager_completion

# Move the completion script to the correct location
cp vault_completion.zsh ~/.password_manager_completion/

# Add source command to .zshrc if not already present
if ! grep -q "source ~/.password_manager_completion/vault_completion.zsh" ~/.zshrc; then
    echo "# Vault CLI completion" >> ~/.zshrc
    echo "source ~/.password_manager_completion/vault_completion.zsh" >> ~/.zshrc
fi

# Source the .zshrc file to activate the changes
source ~/.zshrc

echo "Post-installation steps completed. Shell completion is now active."
