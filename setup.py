from setuptools import setup, find_packages

setup(
    name='password_manager',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'click',
        'python-pam',
        # 'dbus-python',  # Comment out this line temporarily
    ],
    entry_points={
        'console_scripts': [
            'password_manager=password_manager.cli:cli',
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='A simple CLI password manager',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/password_manager',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
