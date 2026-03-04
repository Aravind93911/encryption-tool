"""Utility functions for FileCryptor."""

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the application.

    Args:
        verbose: Enable debug-level logging if True.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def validate_file_path(filepath: str, must_exist: bool = True) -> Path:
    """
    Validate and normalize file path.

    Args:
        filepath: Path to validate.
        must_exist: If True, raise error if file doesn't exist.

    Returns:
        Normalized Path object.

    Raises:
        FileNotFoundError: If must_exist=True and file doesn't exist.
        ValueError: If path is invalid.
    """
    try:
        path = Path(filepath).resolve()
        
        if must_exist and not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        if must_exist and not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")
        
        return path
    except Exception as e:
        logger.error(f"Path validation failed for '{filepath}': {e}")
        raise


def secure_delete(filepath: Path) -> None:
    """
    Securely delete a file by overwriting with random data before removal.

    Args:
        filepath: Path to file to delete.
    """
    try:
        if filepath.exists():
            file_size = filepath.stat().st_size
            with open(filepath, 'ba+') as f:
                f.write(os.urandom(file_size))
            filepath.unlink()
            logger.debug(f"Securely deleted: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to securely delete '{filepath}': {e}")


def get_file_size_mb(filepath: Path) -> float:
    """
    Get file size in megabytes.

    Args:
        filepath: Path to file.

    Returns:
        File size in MB.
    """
    return filepath.stat().st_size / (1024 * 1024)


def set_secure_permissions(filepath: Path) -> None:
    """
    Set restrictive permissions on a file (owner read/write only).

    Args:
        filepath: Path to file.
    """
    try:
        os.chmod(filepath, 0o600)  # rw-------
        logger.debug(f"Set secure permissions on: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to set permissions on '{filepath}': {e}")
