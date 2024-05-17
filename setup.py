from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import sys

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        # Ensure vault_completion.zsh is sourced in .zshrc
        os.system(f"{sys.executable} -m password_manager.post_install")

setup(
    name='password_manager',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'cryptography',
        'python-pam',
        'pathlib',
        'pyobjc',
        # Add other dependencies if needed
    ],
    entry_points='''
        [console_scripts]
        vault=password_manager.cli:vault
    ''',
    package_data={
        '': ['*.zsh'],
    },
    cmdclass={
        'install': PostInstallCommand,
    },
)
