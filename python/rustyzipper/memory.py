"""In-memory compression and decompression functions."""

from typing import List, Optional, Tuple, Union

from ._core import _rust, _enc_value, _level_value
from .enums import CompressionLevel, EncryptionMethod
from .security import SecurityPolicy


def compress_bytes(
    files: List[Tuple[str, bytes]],
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> bytes:
    """Compress bytes directly to a ZIP archive in memory.

    This function allows compressing data without writing to the filesystem,
    useful for web applications, APIs, or processing data in memory.

    Args:
        files: List of (archive_name, data) tuples. Each tuple contains:
               - archive_name: The filename to use in the ZIP archive (can include paths like "subdir/file.txt")
               - data: The bytes content to compress
        password: Optional password for encryption. If None, no encryption is used.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level (0-9 or CompressionLevel enum). Defaults to DEFAULT (6).
        suppress_warning: If True, suppresses security warnings for weak encryption.

    Returns:
        The compressed ZIP archive as bytes.

    Raises:
        IOError: If compression fails.
        ValueError: If parameters are invalid.

    Example:
        >>> # Compress multiple files to bytes
        >>> files = [
        ...     ("hello.txt", b"Hello, World!"),
        ...     ("data/info.json", b'{"key": "value"}'),
        ... ]
        >>> zip_data = compress_bytes(files, password="secret")
        >>>
        >>> # Write to file if needed
        >>> with open("archive.zip", "wb") as f:
        ...     f.write(zip_data)
        >>>
        >>> # Or send over network, store in database, etc.
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    return bytes(_rust.compress_bytes(
        files,
        password,
        enc_value,
        level,
        suppress_warning,
    ))


def decompress_bytes(
    data: bytes,
    password: Optional[str] = None,
    *,
    policy: Optional[SecurityPolicy] = None,
) -> List[Tuple[str, bytes]]:
    """Decompress a ZIP archive from bytes in memory.

    This function allows decompressing ZIP data without reading from the filesystem,
    useful for web applications, APIs, or processing data in memory. It is secure
    by default with ZIP bomb protection.

    Args:
        data: The ZIP archive data as bytes.
        password: Optional password for encrypted archives.
        policy: Optional SecurityPolicy to configure extraction limits.
            If None, uses secure defaults (2GB max, 500:1 ratio).

    Returns:
        List of (filename, content) tuples. Each tuple contains:
        - filename: The name of the file in the archive (may include path like "subdir/file.txt")
        - content: The decompressed bytes content

    Raises:
        IOError: If decompression fails.
        ValueError: If password is incorrect.
        RustyZipError: If ZIP bomb limits are exceeded.

    Example:
        >>> # Decompress from bytes with default security
        >>> files = decompress_bytes(zip_data, password="secret")
        >>> for filename, content in files:
        ...     print(f"{filename}: {len(content)} bytes")
        ...
        hello.txt: 13 bytes
        data/info.json: 16 bytes
        >>>
        >>> # Decompress with custom policy
        >>> policy = SecurityPolicy(max_size="1GB")
        >>> files = decompress_bytes(zip_data, policy=policy)
    """
    max_size = policy.max_size if policy else None
    max_ratio = policy.max_ratio if policy else None

    result = _rust.decompress_bytes(data, password, max_size, max_ratio)
    return [(name, bytes(content)) for name, content in result]
