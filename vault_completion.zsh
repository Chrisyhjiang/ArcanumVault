#compdef vault

_vault_completion() {
    local -a commands
    commands=(
        'authenticate:Authenticate the user'
        'insert:Insert a new password'
        'show:Show passwords'
        'remove:Remove a password by vault ID'
        'generate:Generate a random password'
        'update:Update a password entry by vault ID'
        'install-completion:Install the shell completion'
        'rotate-key:Rotate the encryption key and re-encrypt all stored passwords'
        'delete-all:Delete all passwords'
        'search:Returns all relevant entries based on your input description'
        'create-folder:Create a new directory for storing passwords'
    )

    _describe -t commands 'vault commands' commands
}

compdef _vault_completion vault
