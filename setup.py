from setuptools import setup, find_packages

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
        'pyobjc'
    ],
    entry_points='''
        [console_scripts]
        vault=password_manager.cli:vault
    ''',
    data_files=[
        ('~/.password_manager_completion', ['vault_completion.zsh']),
    ]
)
