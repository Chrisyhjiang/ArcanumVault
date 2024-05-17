# password_manager/post_install.py

import os

def add_source_line():
    zshrc_path = os.path.expanduser("~/.zshrc")
    source_line = "source ~/.password_manager_completion/vault_completion.zsh"

    # Check if the source line is already in .zshrc
    if os.path.exists(zshrc_path):
        with open(zshrc_path, 'r') as file:
            lines = file.readlines()
            if any(source_line in line for line in lines):
                return

    # Append the source line to .zshrc
    with open(zshrc_path, 'a') as file:
        file.write(f"\n{source_line}\n")

def copy_completion_script():
    completion_dir = os.path.expanduser("~/.password_manager_completion")
    if not os.path.exists(completion_dir):
        os.makedirs(completion_dir)

    script_source = os.path.join(os.path.dirname(__file__), "../vault_completion.zsh")
    script_destination = os.path.join(completion_dir, "vault_completion.zsh")

    with open(script_source, 'r') as src, open(script_destination, 'w') as dst:
        dst.write(src.read())

if __name__ == "__main__":
    copy_completion_script()
    add_source_line()
