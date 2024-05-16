from setuptools import setup, find_packages

setup(
    name='password_manager',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'click',
        'cryptography',
        'pam',
        'pyobjc-framework-Cocoa',
        'pyobjc-framework-LocalAuthentication',
        'pyobjc-core',
    ],
    entry_points={
        'console_scripts': [
            'vault=password_manager.cli:vault',
        ],
    },
)
