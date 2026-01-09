"""
RustyZip - A high-performance, secure file compression library.

RustyZip provides fast ZIP compression with multiple encryption methods,
serving as a modern, maintained replacement for pyminizip.

Example usage:
    >>> from rustyzip import compress_file, decompress_file, EncryptionMethod
    >>>
    >>> # Secure compression with AES-256 (recommended)
    >>> compress_file("document.pdf", "secure.zip", password="MyP@ssw0rd")
    >>>
    >>> # Windows Explorer compatible (weak security)
    >>> compress_file(
    ...     "public.pdf",
    ...     "compatible.zip",
    ...     password="simple",
    ...     encryption=EncryptionMethod.ZIPCRYPTO,
    ...     suppress_warning=True
    ... )
    >>>
    >>> # Decompress
    >>> decompress_file("secure.zip", "extracted/", password="MyP@ssw0rd")
"""

from enum import Enum
from typing import List, Optional

# Import the Rust extension module
from rustyzip import rustyzip as _rust

__version__ = _rust.__version__
__all__ = [
    "compress_file",
    "compress_files",
    "compress_directory",
    "decompress_file",
    "EncryptionMethod",
    "CompressionLevel",
    "__version__",
]


class EncryptionMethod(Enum):
    """Encryption method for password-protected archives.

    Attributes:
        AES256: Strong AES-256 encryption. Requires 7-Zip, WinRAR, or WinZip to open.
                Recommended for sensitive data.
        ZIPCRYPTO: Legacy ZIP encryption. Compatible with Windows Explorer but weak.
                   Only use for non-sensitive files requiring maximum compatibility.
        NONE: No encryption. Archive can be opened by any tool.
    """
    AES256 = "aes256"
    ZIPCRYPTO = "zipcrypto"
    NONE = "none"


class CompressionLevel(Enum):
    """Compression level (speed vs size trade-off).

    Attributes:
        STORE: No compression (fastest, largest files)
        FAST: Fast compression (good speed, reasonable size)
        DEFAULT: Balanced compression (default, recommended)
        BEST: Maximum compression (slowest, smallest files)
    """
    STORE = 0
    FAST = 1
    DEFAULT = 6
    BEST = 9


def compress_file(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> None:
    """Compress a single file to a ZIP archive.

    Args:
        input_path: Path to the file to compress.
        output_path: Path for the output ZIP file.
        password: Optional password for encryption. If None, no encryption is used.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).
        suppress_warning: If True, suppresses security warnings for weak encryption.

    Raises:
        IOError: If file operations fail.
        ValueError: If parameters are invalid.

    Example:
        >>> compress_file("document.pdf", "archive.zip", password="secret")
    """
    enc_value = encryption.value if isinstance(encryption, EncryptionMethod) else encryption
    level = compression_level.value if isinstance(compression_level, CompressionLevel) else compression_level

    _rust.compress_file(
        input_path,
        output_path,
        password,
        enc_value,
        level,
        suppress_warning,
    )


def compress_files(
    input_paths: List[str],
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    prefixes: Optional[List[Optional[str]]] = None,
) -> None:
    """Compress multiple files to a ZIP archive.

    Args:
        input_paths: List of paths to files to compress.
        output_path: Path for the output ZIP file.
        password: Optional password for encryption.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).
        prefixes: Optional list of archive path prefixes for each file.

    Raises:
        IOError: If file operations fail.
        ValueError: If parameters are invalid.

    Example:
        >>> compress_files(
        ...     ["file1.txt", "file2.txt"],
        ...     "archive.zip",
        ...     password="secret",
        ...     prefixes=["docs", "docs"]
        ... )
    """
    enc_value = encryption.value if isinstance(encryption, EncryptionMethod) else encryption
    level = compression_level.value if isinstance(compression_level, CompressionLevel) else compression_level

    if prefixes is None:
        prefixes = [None] * len(input_paths)

    _rust.compress_files(
        input_paths,
        prefixes,
        output_path,
        password,
        enc_value,
        level,
    )


def compress_directory(
    input_dir: str,
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
) -> None:
    """Compress a directory to a ZIP archive.

    Args:
        input_dir: Path to the directory to compress.
        output_path: Path for the output ZIP file.
        password: Optional password for encryption.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).
        include_patterns: Optional list of glob patterns to include (e.g., ["*.py", "*.md"]).
        exclude_patterns: Optional list of glob patterns to exclude (e.g., ["__pycache__", "*.pyc"]).

    Raises:
        IOError: If file operations fail.
        ValueError: If parameters are invalid.

    Example:
        >>> compress_directory(
        ...     "my_project/",
        ...     "backup.zip",
        ...     password="secret",
        ...     exclude_patterns=["__pycache__", "*.pyc", ".git"]
        ... )
    """
    enc_value = encryption.value if isinstance(encryption, EncryptionMethod) else encryption
    level = compression_level.value if isinstance(compression_level, CompressionLevel) else compression_level

    _rust.compress_directory(
        input_dir,
        output_path,
        password,
        enc_value,
        level,
        include_patterns,
        exclude_patterns,
    )


def decompress_file(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
) -> None:
    """Decompress a ZIP archive.

    Args:
        input_path: Path to the ZIP file to decompress.
        output_path: Path for the output directory.
        password: Optional password for encrypted archives.

    Raises:
        IOError: If file operations fail.
        ValueError: If password is incorrect.

    Example:
        >>> decompress_file("archive.zip", "extracted/", password="secret")
    """
    _rust.decompress_file(input_path, output_path, password)
