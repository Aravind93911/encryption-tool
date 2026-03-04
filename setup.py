"""Setup configuration for FileCryptor package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name='filecryptor',
    version='1.0.0',
    author='Aravind Dhakuri',
    author_email='aravinddhakuri@gmail.com',
    description='Enterprise-grade file encryption utility using Fernet (AES-128 + HMAC-SHA256)',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Aravind93911/file-cryptor',
    packages=find_packages(exclude=['tests*']),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',
    install_requires=[
        'click>=8.0.0',
        'cryptography>=41.0.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'filecryptor=filecryptor.cli:cli',
        ],
    },
    keywords='encryption, security, cryptography, fernet, aes, file-encryption, cli',
    project_urls={
        'Bug Reports': 'https://github.com/Aravind93911/file-cryptor/issues',
        'Source': 'https://github.com/Aravind93911/file-cryptor',
        'Documentation': 'https://github.com/Aravind93911/file-cryptor#readme',
    },
)
