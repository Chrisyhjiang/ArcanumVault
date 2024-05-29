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
        'pyobjc-framework-Cocoa',
        'pyobjc-framework-Quartz',
        'pyobjc-framework-LocalAuthentication',
        'six'
        # Add other dependencies if needed
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
