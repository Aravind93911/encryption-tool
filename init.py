"""
FileCryptor: Enterprise-grade file encryption utility using Fernet (AES-128-CBC + HMAC-SHA256).

Author: Aravind Dhakuri
License: MIT
Repository: https://github.com/Aravind93911/file-cryptor
"""

__version__ = "1.0.0"
__author__ = "Aravind Dhakuri"
__license__ = "MIT"

from .core import FileCryptor
from .exceptions import (
    CryptorError,
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    InvalidKeyError
)

__all__ = [
    'FileCryptor',
    'CryptorError',
    'KeyGenerationError',
    'EncryptionError',
    'DecryptionError',
    'InvalidKeyError',
]
