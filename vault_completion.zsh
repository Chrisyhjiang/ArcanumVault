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
        'goto:Change current directory'
        'pwd:prints current directory'
        'set-master-password:reset the master password to another one'
        'export:exports all current encrypted passwords into a csv'
        'import:imports all encrypted passwords and sets up the file structure accordingly'
    )

    _describe -t commands 'vault commands' commands
}

compdef _vault_completion vault
