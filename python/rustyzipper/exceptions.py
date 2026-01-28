"""
RustyZip Exceptions

Custom exception classes for RustyZip operations.
These exceptions are defined in Rust and exposed to Python, allowing you to
catch specific error types and inspect error codes.

Example usage:
    >>> from rustyzipper import decompress_file
    >>> from rustyzipper.exceptions import (
    ...     RustyZipError,
    ...     InvalidPasswordError,
    ...     ZipBombError,
    ...     ErrorCode,
    ... )
    >>>
    >>> try:
    ...     decompress_file("archive.zip", "output/", password="wrong")
    ... except InvalidPasswordError as e:
    ...     print(f"Wrong password! Error code: {e.code}")
    ... except ZipBombError as e:
    ...     print(f"ZIP bomb detected! Error code: {e.code}")
    ... except RustyZipError as e:
    ...     print(f"Error: {e}, Code: {e.code}")
"""

from typing import Optional, Type

# Import the Rust extension module
from . import rustyzip as _rust

# =============================================================================
# ErrorCode Enum (from Rust)
# =============================================================================

# Re-export ErrorCode enum from Rust
ErrorCode = _rust.ErrorCode

# =============================================================================
# Exception Classes
# =============================================================================

# These wrapper classes provide a Pythonic interface to the Rust exceptions.
# They inherit from both the Rust exception and standard Python exceptions
# for compatibility with existing code that catches ValueError, IOError, etc.


class RustyZipError(Exception):
    """Base exception for all RustyZip errors.

    Attributes:
        message: Human-readable error message
        code: ErrorCode enum value identifying the error type

    Example:
        >>> try:
        ...     decompress_file("bad.zip", "output/")
        ... except RustyZipError as e:
        ...     print(f"Error: {e.message}")
        ...     print(f"Code: {e.code}")
        ...     if e.code == ErrorCode.InvalidPassword:
        ...         print("Try a different password")
    """

    def __init__(
        self, message: str = "", code: Optional["ErrorCode"] = None, *args, **kwargs
    ):
        super().__init__(message, *args, **kwargs)
        self._message = message
        self._code = code if code is not None else ErrorCode.Unknown

    @property
    def message(self) -> str:
        """Human-readable error message."""
        return self._message

    @property
    def code(self) -> "ErrorCode":
        """Error code identifying the type of error."""
        return self._code

    def __str__(self) -> str:
        return self._message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._message!r}, code={self._code!r})"


class CompressionError(RustyZipError):
    """Raised when compression fails."""

    pass


class DecompressionError(RustyZipError):
    """Raised when decompression fails."""

    pass


class InvalidPasswordError(RustyZipError, ValueError):
    """Raised when the provided password is incorrect.

    Also inherits from ValueError for compatibility with code that
    catches ValueError for invalid input.
    """

    pass


class FileNotFoundError(RustyZipError, IOError):
    """Raised when a specified file is not found.

    Also inherits from IOError for compatibility with code that
    catches IOError for file operations.

    Note: This shadows the built-in FileNotFoundError. Import explicitly
    if you need both:
        from rustyzipper.exceptions import FileNotFoundError as RustyFileNotFoundError
    """

    pass


class UnsupportedEncryptionError(RustyZipError, ValueError):
    """Raised when an unsupported encryption method is specified."""

    pass


# Security-related exceptions (define base class first)
class SecurityError(RustyZipError):
    """Base class for security-related exceptions.

    Includes PathTraversalError and ZipBombError.
    """

    pass


class PathTraversalError(SecurityError):
    """Raised when a path traversal attack is detected.

    This is a security exception that indicates a malicious archive
    attempted to write files outside the target directory.
    """

    pass


class ZipBombError(SecurityError):
    """Raised when a ZIP bomb is detected.

    This exception is raised when:
    - Decompressed size exceeds the maximum allowed size
    - Compression ratio exceeds the maximum allowed ratio

    These limits protect against denial-of-service attacks using
    specially crafted archives.
    """

    pass


class SymlinkError(SecurityError):
    """Raised when symlink extraction is not allowed."""

    pass


# =============================================================================
# Exception Mapping
# =============================================================================

# Map ErrorCode values to exception classes
_CODE_TO_EXCEPTION: dict[ErrorCode, Type[RustyZipError]] = {
    ErrorCode.IoError: RustyZipError,
    ErrorCode.ZipError: RustyZipError,
    ErrorCode.InvalidPassword: InvalidPasswordError,
    ErrorCode.UnsupportedEncryption: UnsupportedEncryptionError,
    ErrorCode.FileNotFound: FileNotFoundError,
    ErrorCode.InvalidPath: RustyZipError,
    ErrorCode.PatternError: RustyZipError,
    ErrorCode.WalkDirError: RustyZipError,
    ErrorCode.PathTraversal: PathTraversalError,
    ErrorCode.ZipBombDetected: ZipBombError,
    ErrorCode.SuspiciousRatio: ZipBombError,
    ErrorCode.CompressionFailed: CompressionError,
    ErrorCode.DecompressionFailed: DecompressionError,
    ErrorCode.SymlinkNotAllowed: SymlinkError,
    ErrorCode.Unknown: RustyZipError,
}


def get_exception_class(code: "ErrorCode") -> Type[RustyZipError]:
    """Get the appropriate exception class for an error code.

    Args:
        code: ErrorCode enum value

    Returns:
        Exception class to use for this error code
    """
    return _CODE_TO_EXCEPTION.get(code, RustyZipError)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Error code enum
    "ErrorCode",
    # Exception classes
    "RustyZipError",
    "CompressionError",
    "DecompressionError",
    "InvalidPasswordError",
    "FileNotFoundError",
    "UnsupportedEncryptionError",
    "SecurityError",
    "PathTraversalError",
    "ZipBombError",
    "SymlinkError",
    # Utilities
    "get_exception_class",
]
