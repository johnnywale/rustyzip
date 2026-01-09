"""
RustyZip Exceptions

Custom exception classes for RustyZip operations.
Note: Most exceptions are raised as standard Python exceptions (IOError, ValueError)
from the Rust layer. These classes are provided for compatibility and future use.
"""


class RustyZipError(Exception):
    """Base exception for RustyZip errors."""
    pass


class CompressionError(RustyZipError):
    """Raised when compression fails."""
    pass


class DecompressionError(RustyZipError):
    """Raised when decompression fails."""
    pass


class InvalidPasswordError(RustyZipError, ValueError):
    """Raised when the provided password is incorrect."""
    pass


class FileNotFoundError(RustyZipError, IOError):
    """Raised when a specified file is not found."""
    pass


class UnsupportedEncryptionError(RustyZipError, ValueError):
    """Raised when an unsupported encryption method is specified."""
    pass


__all__ = [
    "RustyZipError",
    "CompressionError",
    "DecompressionError",
    "InvalidPasswordError",
    "FileNotFoundError",
    "UnsupportedEncryptionError",
]
