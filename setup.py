from setuptools import setup, find_packages

setup(
    name='password_manager',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'cryptography',
        'click',
        'python-pam',
        'six', 
        'click-completion'
    ],
    entry_points='''
        [console_scripts]
        vault=password_manager.cli:vault
    ''',
)
