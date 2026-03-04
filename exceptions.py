"""Custom exception classes for FileCryptor."""


class CryptorError(Exception):
    """Base exception for all FileCryptor errors."""
    pass


class KeyGenerationError(CryptorError):
    """Raised when key generation fails."""
    pass


class EncryptionError(CryptorError):
    """Raised when encryption operation fails."""
    pass


class DecryptionError(CryptorError):
    """Raised when decryption operation fails."""
    pass


class InvalidKeyError(CryptorError):
    """Raised when the provided key is invalid or corrupted."""
    pass
