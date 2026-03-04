"""Core encryption/decryption logic for FileCryptor."""

import os
import logging
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode

from .exceptions import (
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    InvalidKeyError
)
from .utils import validate_file_path, set_secure_permissions, get_file_size_mb

logger = logging.getLogger(__name__)


class FileCryptor:
    """
    Handles file encryption and decryption using Fernet (AES-128 in CBC mode with HMAC-SHA256).

    Attributes:
        BUFFER_SIZE: Buffer size for processing large files (64KB).
        MAX_FILE_SIZE_MB: Maximum file size to process (500MB by default).
    """

    BUFFER_SIZE = 65536  # 64KB chunks for memory efficiency
    MAX_FILE_SIZE_MB = 500

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize FileCryptor with an optional encryption key.

        Args:
            key: 32-byte Fernet key. If None, must be set later.
        """
        self._key = key
        self._cipher = Fernet(key) if key else None

    @property
    def key(self) -> Optional[bytes]:
        """Get the current encryption key."""
        return self._key

    @key.setter
    def key(self, value: bytes) -> None:
        """
        Set the encryption key.

        Args:
            value: 32-byte Fernet key.

        Raises:
            InvalidKeyError: If key is invalid.
        """
        try:
            self._cipher = Fernet(value)
            self._key = value
            logger.debug("Encryption key set successfully")
        except Exception as e:
            raise InvalidKeyError(f"Invalid encryption key: {e}")

    @staticmethod
    def generate_key(output_path: Optional[str] = None) -> bytes:
        """
        Generate a new Fernet encryption key.

        Args:
            output_path: Optional path to save the key. If None, key is returned only.

        Returns:
            The generated 32-byte Fernet key.

        Raises:
            KeyGenerationError: If key generation or saving fails.
        """
        try:
            key = Fernet.generate_key()
            logger.info("Generated new Fernet encryption key")

            if output_path:
                key_path = validate_file_path(output_path, must_exist=False)
                with open(key_path, 'wb') as f:
                    f.write(key)
                set_secure_permissions(key_path)
                logger.info(f"Key saved to: {key_path}")

            return key
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise KeyGenerationError(f"Failed to generate encryption key: {e}")

    @staticmethod
    def load_key(key_path: str) -> bytes:
        """
        Load encryption key from file.

        Args:
            key_path: Path to key file.

        Returns:
            The loaded encryption key.

        Raises:
            InvalidKeyError: If key file is invalid or corrupted.
        """
        try:
            path = validate_file_path(key_path, must_exist=True)
            with open(path, 'rb') as f:
                key = f.read()

            # Validate key by attempting to create Fernet instance
            Fernet(key)
            logger.debug(f"Key loaded from: {path}")
            return key
        except FileNotFoundError as e:
            raise InvalidKeyError(f"Key file not found: {key_path}")
        except Exception as e:
            logger.error(f"Failed to load key from '{key_path}': {e}")
            raise InvalidKeyError(f"Invalid or corrupted key file: {e}")

    def encrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        overwrite: bool = False
    ) -> Path:
        """
        Encrypt a file using the configured key.

        Args:
            input_path: Path to file to encrypt.
            output_path: Optional output path. Defaults to <input>.enc
            overwrite: Allow overwriting existing output file.

        Returns:
            Path to encrypted file.

        Raises:
            EncryptionError: If encryption fails.
            ValueError: If output file exists and overwrite=False.
        """
        if not self._cipher:
            raise EncryptionError("No encryption key set. Load or generate a key first.")

        try:
            input_file = validate_file_path(input_path, must_exist=True)
            
            # Check file size
            size_mb = get_file_size_mb(input_file)
            if size_mb > self.MAX_FILE_SIZE_MB:
                logger.warning(f"File size ({size_mb:.2f}MB) exceeds recommended limit ({self.MAX_FILE_SIZE_MB}MB)")

            # Determine output path
            if output_path is None:
                output_file = input_file.with_suffix(input_file.suffix + '.enc')
            else:
                output_file = validate_file_path(output_path, must_exist=False)

            if output_file.exists() and not overwrite:
                raise ValueError(f"Output file already exists: {output_file}. Use --overwrite to replace.")

            # Encrypt
            logger.info(f"Encrypting: {input_file} -> {output_file}")
            with open(input_file, 'rb') as infile:
                plaintext = infile.read()

            ciphertext = self._cipher.encrypt(plaintext)

            with open(output_file, 'wb') as outfile:
                outfile.write(ciphertext)

            set_secure_permissions(output_file)
            logger.info(f"✓ Encryption successful: {output_file}")
            return output_file

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt file: {e}")

    def decrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        overwrite: bool = False
    ) -> Path:
        """
        Decrypt a file using the configured key.

        Args:
            input_path: Path to encrypted file.
            output_path: Optional output path. Defaults to input minus .enc
            overwrite: Allow overwriting existing output file.

        Returns:
            Path to decrypted file.

        Raises:
            DecryptionError: If decryption fails.
            ValueError: If output file exists and overwrite=False.
        """
        if not self._cipher:
            raise DecryptionError("No encryption key set. Load a key first.")

        try:
            input_file = validate_file_path(input_path, must_exist=True)

            # Determine output path
            if output_path is None:
                if input_file.suffix == '.enc':
                    output_file = input_file.with_suffix('')
                else:
                    output_file = input_file.with_suffix(input_file.suffix + '.dec')
            else:
                output_file = validate_file_path(output_path, must_exist=False)

            if output_file.exists() and not overwrite:
                raise ValueError(f"Output file already exists: {output_file}. Use --overwrite to replace.")

            # Decrypt
            logger.info(f"Decrypting: {input_file} -> {output_file}")
            with open(input_file, 'rb') as infile:
                ciphertext = infile.read()

            plaintext = self._cipher.decrypt(ciphertext)

            with open(output_file, 'wb') as outfile:
                outfile.write(plaintext)

            set_secure_permissions(output_file)
            logger.info(f"✓ Decryption successful: {output_file}")
            return output_file

        except InvalidToken:
            logger.error("Decryption failed: Invalid key or corrupted file")
            raise DecryptionError("Decryption failed. Key is incorrect or file is corrupted.")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt file: {e}")
