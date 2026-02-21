"""File-based compression and decompression functions."""

from typing import List, Optional, Union

from ._core import _rust, _enc_value, _level_value
from .enums import CompressionLevel, EncryptionMethod
from .security import SecurityPolicy


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
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

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
    suppress_warning: bool = False,
) -> None:
    """Compress multiple files to a ZIP archive.

    Args:
        input_paths: List of paths to files to compress.
        output_path: Path for the output ZIP file.
        password: Optional password for encryption.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).
        prefixes: Optional list of archive path prefixes for each file.
        suppress_warning: If True, suppresses security warnings for weak encryption.

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
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    if prefixes is None:
        prefixes = [None] * len(input_paths)

    _rust.compress_files(
        input_paths,
        prefixes,
        output_path,
        password,
        enc_value,
        level,
        suppress_warning,
    )


def compress_directory(
    input_dir: str,
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    suppress_warning: bool = False,
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
        suppress_warning: If True, suppresses security warnings for weak encryption.

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
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    _rust.compress_directory(
        input_dir,
        output_path,
        password,
        enc_value,
        level,
        include_patterns,
        exclude_patterns,
        suppress_warning,
    )


def decompress_file(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    *,
    withoutpath: bool = False,
    policy: Optional[SecurityPolicy] = None,
) -> None:
    """Decompress a ZIP archive with optional security policy.

    This function is secure by default, with built-in protection against
    ZIP bombs and path traversal attacks.

    Args:
        input_path: Path to the ZIP file to decompress.
        output_path: Path for the output directory.
        password: Optional password for encrypted archives.
        withoutpath: If True, extract files without their directory paths
            (flatten all files into the destination directory). Default is False.
        policy: Optional SecurityPolicy to configure extraction limits.
            If None, uses secure defaults (2GB max, 500:1 ratio).

    Raises:
        IOError: If file operations fail.
        ValueError: If password is incorrect.
        RustyZipError: If ZIP bomb limits are exceeded.

    Examples:
        >>> # Basic usage with default security
        >>> decompress_file("archive.zip", "extracted/", password="secret")

        >>> # Extract files without directory structure
        >>> decompress_file("archive.zip", "flat/", withoutpath=True)

        >>> # With custom policy for large archives
        >>> policy = SecurityPolicy(max_size="10GB", max_ratio=1000)
        >>> decompress_file("large.zip", "extracted/", policy=policy)

        >>> # Unlimited policy for trusted archives
        >>> decompress_file("trusted.zip", "out/", policy=SecurityPolicy.unlimited())
    """
    max_size = policy.max_size if policy else None
    max_ratio = policy.max_ratio if policy else None

    _rust.decompress_file(
        input_path,
        output_path,
        password,
        withoutpath,
        max_size,
        max_ratio,
    )
