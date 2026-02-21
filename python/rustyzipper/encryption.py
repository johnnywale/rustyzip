"""Encryption detection functions."""

from ._core import _rust
from .enums import EncryptionMethod


def detect_encryption(input_path: str) -> EncryptionMethod:
    """Detect the encryption method used in a ZIP file.

    This function examines the ZIP archive and returns the encryption method
    used for the first encrypted file found. If no files are encrypted,
    returns EncryptionMethod.NONE.

    Args:
        input_path: Path to the ZIP file.

    Returns:
        EncryptionMethod: The detected encryption method.
            - EncryptionMethod.AES256: AES-256 encryption
            - EncryptionMethod.ZIPCRYPTO: Legacy ZipCrypto encryption
            - EncryptionMethod.NONE: No encryption

    Raises:
        IOError: If file operations fail.
        FileNotFoundError: If the file does not exist.

    Example:
        >>> method = detect_encryption("archive.zip")
        >>> if method == EncryptionMethod.AES256:
        ...     print("Archive uses AES-256 encryption")
        >>> elif method == EncryptionMethod.ZIPCRYPTO:
        ...     print("Archive uses legacy ZipCrypto (weak)")
        >>> else:
        ...     print("Archive is not encrypted")
    """
    result = _rust.detect_encryption(input_path)
    return EncryptionMethod(result)


def detect_encryption_bytes(data: bytes) -> EncryptionMethod:
    """Detect the encryption method from ZIP data in memory.

    This function examines the ZIP archive data and returns the encryption
    method used for the first encrypted file found. If no files are encrypted,
    returns EncryptionMethod.NONE.

    Args:
        data: The ZIP archive data as bytes.

    Returns:
        EncryptionMethod: The detected encryption method.
            - EncryptionMethod.AES256: AES-256 encryption
            - EncryptionMethod.ZIPCRYPTO: Legacy ZipCrypto encryption
            - EncryptionMethod.NONE: No encryption

    Raises:
        IOError: If the data is not a valid ZIP archive.

    Example:
        >>> with open("archive.zip", "rb") as f:
        ...     data = f.read()
        >>> method = detect_encryption_bytes(data)
        >>> print(f"Encryption: {method.name}")
    """
    result = _rust.detect_encryption_bytes(data)
    return EncryptionMethod(result)
