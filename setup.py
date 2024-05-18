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
        'schedule',
        'pyobjc-framework-Cocoa'  # Ensure you have the correct pyobjc package
    ],
    entry_points='''
        [console_scripts]
        vault=password_manager.cli:vault
    ''',
    data_files=[
        ('share/zsh/site-functions', ['vault_completion.zsh']),
    ],
    package_data={
        '': ['*.zsh'],
    },
)
