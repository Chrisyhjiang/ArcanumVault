from setuptools import setup, find_packages

setup(
    name='password_manager',
    version='0.1.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'click>=8.0.0',
        'cryptography>=41.0.0',
        'pathlib>=1.0.1',
    ],
    entry_points={
        'console_scripts': [
            'vault=password_manager.cli.commands:main',
        ],
    },
) 