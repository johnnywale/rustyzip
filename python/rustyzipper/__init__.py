"""
RustyZipper - A high-performance, secure file compression library.

RustyZipper provides fast ZIP compression with multiple encryption methods,
serving as a modern, maintained replacement for pyminizip.

Example usage:
    >>> from rustyzipper import compress_file, decompress_file, EncryptionMethod
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
    >>> # Decompress with default security (protected against ZIP bombs)
    >>> decompress_file("secure.zip", "extracted/", password="MyP@ssw0rd")
    >>>
    >>> # Decompress with custom security policy
    >>> from rustyzipper import SecurityPolicy
    >>> policy = SecurityPolicy(max_size="10GB", max_ratio=1000)
    >>> decompress_file("large.zip", "extracted/", policy=policy)
    >>>
    >>> # Decompress with unlimited policy (for trusted archives only)
    >>> decompress_file("trusted.zip", "out/", policy=SecurityPolicy.unlimited())
    >>>
    >>> # In-memory compression (no filesystem I/O)
    >>> from rustyzipper import compress_bytes, decompress_bytes
    >>> files = [("hello.txt", b"Hello World"), ("data.bin", b"\\x00\\x01\\x02")]
    >>> zip_data = compress_bytes(files, password="secret")
    >>> extracted = decompress_bytes(zip_data, password="secret")
"""

from . import rustyzip as _rust

# Version
__version__ = _rust.__version__

# ErrorCode enum from Rust
ErrorCode = _rust.ErrorCode

# Exception classes from Rust module
RustyZipException = _rust.RustyZipException
InvalidPasswordException = _rust.InvalidPasswordException
FileNotFoundException = _rust.FileNotFoundException
UnsupportedEncryptionException = _rust.UnsupportedEncryptionException
PathTraversalException = _rust.PathTraversalException
ZipBombException = _rust.ZipBombException
SecurityException = _rust.SecurityException
CompressionException = _rust.CompressionException
DecompressionException = _rust.DecompressionException

# Enums
from .enums import CompressionLevel, EncryptionMethod

# Security
from .security import (
    DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_DECOMPRESSED_SIZE,
    SecurityPolicy,
)

# File-based compression
from .compression import (
    compress_directory,
    compress_file,
    compress_files,
    decompress_file,
)

# Encryption detection
from .encryption import detect_encryption, detect_encryption_bytes

# In-memory compression
from .memory import compress_bytes, decompress_bytes

# Streaming
from .streaming import (
    ZipFileStreamReader,
    ZipStreamReader,
    compress_stream,
    decompress_stream,
    open_zip_stream,
    open_zip_stream_from_file,
)

# Archive inspection
from .inspection import (
    ArchiveInfo,
    FileInfo,
    get_all_file_info,
    get_all_file_info_bytes,
    get_archive_info,
    get_archive_info_bytes,
    get_file_info,
    get_file_info_bytes,
    has_file,
    has_file_bytes,
    list_archive,
    list_archive_bytes,
)

# Archive modification
from .modification import (
    add_bytes_to_archive,
    add_to_archive,
    add_to_archive_bytes,
    remove_from_archive,
    remove_from_archive_bytes,
    rename_in_archive,
    rename_in_archive_bytes,
    update_in_archive,
    update_in_archive_bytes,
)

__all__ = [
    # File-based compression
    "compress_file",
    "compress_files",
    "compress_directory",
    "decompress_file",
    # In-memory compression
    "compress_bytes",
    "decompress_bytes",
    # Streaming compression
    "compress_stream",
    "decompress_stream",
    # Streaming iterator (per-file streaming)
    "open_zip_stream",
    "open_zip_stream_from_file",
    "ZipStreamReader",
    "ZipFileStreamReader",
    # Archive inspection
    "list_archive",
    "list_archive_bytes",
    "get_archive_info",
    "get_archive_info_bytes",
    "get_file_info",
    "get_file_info_bytes",
    "get_all_file_info",
    "get_all_file_info_bytes",
    "has_file",
    "has_file_bytes",
    # Info classes
    "FileInfo",
    "ArchiveInfo",
    # Archive modification
    "add_to_archive",
    "add_bytes_to_archive",
    "remove_from_archive",
    "rename_in_archive",
    "update_in_archive",
    "add_to_archive_bytes",
    "remove_from_archive_bytes",
    "rename_in_archive_bytes",
    "update_in_archive_bytes",
    # Encryption detection
    "detect_encryption",
    "detect_encryption_bytes",
    # Security
    "SecurityPolicy",
    "DEFAULT_MAX_DECOMPRESSED_SIZE",
    "DEFAULT_MAX_COMPRESSION_RATIO",
    # Enums
    "EncryptionMethod",
    "CompressionLevel",
    "ErrorCode",
    # Exceptions (from Rust)
    "RustyZipException",
    "InvalidPasswordException",
    "FileNotFoundException",
    "UnsupportedEncryptionException",
    "PathTraversalException",
    "ZipBombException",
    "SecurityException",
    "CompressionException",
    "DecompressionException",
    # Version
    "__version__",
]
