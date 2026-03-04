"""Unit tests for FileCryptor core functionality."""

import pytest
from pathlib import Path
from filecryptor.core import FileCryptor
from filecryptor.exceptions import EncryptionError, DecryptionError, InvalidKeyError


def test_key_generation(tmp_path):
    """Test key generation and loading."""
    key_file = tmp_path / "test.key"
    key = FileCryptor.generate_key(str(key_file))
    
    assert key_file.exists()
    assert len(key) == 44  # Fernet keys are 44 base64 chars
    
    loaded_key = FileCryptor.load_key(str(key_file))
    assert key == loaded_key


def test_encrypt_decrypt_cycle(tmp_path):
    """Test full encrypt-decrypt cycle."""
    # Setup
    key = FileCryptor.generate_key()
    cryptor = FileCryptor(key=key)
    
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secret message")
    
    # Encrypt
    enc_file = cryptor.encrypt_file(str(test_file))
    assert enc_file.exists()
    assert enc_file.suffix == '.enc'
    
    # Decrypt
    dec_file = cryptor.decrypt_file(str(enc_file))
    assert dec_file.read_text() == "Secret message"


def test_invalid_key_fails(tmp_path):
    """Test that decryption fails with wrong key."""
    key1 = FileCryptor.generate_key()
    key2 = FileCryptor.generate_key()
    
    cryptor1 = FileCryptor(key=key1)
    cryptor2 = FileCryptor(key=key2)
    
    test_file = tmp_path / "test.txt"
    test_file.write_text("Secret")
    
    enc_file = cryptor1.encrypt_file(str(test_file))
    
    with pytest.raises(DecryptionError):
        cryptor2.decrypt_file(str(enc_file))
