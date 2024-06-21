import os
import click
from pathlib import Path
from .utils import load_current_directory, save_current_directory, DATA_DIR
from .auth import ensure_authenticated

def create_folder(folder_name):
    ensure_authenticated()
    current_dir = load_current_directory()
    new_folder = current_dir / folder_name
    new_folder.mkdir(parents=True, exist_ok=True)
    click.echo(f"Folder '{folder_name}' created.")

def goto_directory(directory):
    ensure_authenticated()
    current_dir = load_current_directory()
    
    if directory == './':
        new_dir = DATA_DIR
    elif directory == '../':
        new_dir = current_dir.parent.resolve() if current_dir != DATA_DIR else DATA_DIR
    else:
        new_dir = (current_dir / directory).resolve()

    if new_dir.exists() and new_dir.is_dir() and str(DATA_DIR) in str(new_dir.resolve()):
        save_current_directory(new_dir)
        click.echo(f"Current directory changed to '{new_dir if new_dir != DATA_DIR else '/'}'.")
    else:
        click.echo(f"Directory '{directory}' does not exist.")
