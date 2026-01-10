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
    >>> # Decompress
    >>> decompress_file("secure.zip", "extracted/", password="MyP@ssw0rd")
    >>>
    >>> # In-memory compression (no filesystem I/O)
    >>> from rustyzipper import compress_bytes, decompress_bytes
    >>> files = [("hello.txt", b"Hello World"), ("data.bin", b"\\x00\\x01\\x02")]
    >>> zip_data = compress_bytes(files, password="secret")
    >>> extracted = decompress_bytes(zip_data, password="secret")
"""

from enum import Enum
from typing import BinaryIO, List, Optional, Tuple, Union

# Import the Rust extension module
from . import rustyzip as _rust


__version__ = _rust.__version__
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
    # Enums
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
        suppress_warning,
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


# =============================================================================
# In-Memory Compression Functions
# =============================================================================


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
    enc_value = encryption.value if isinstance(encryption, EncryptionMethod) else encryption
    level = compression_level.value if isinstance(compression_level, CompressionLevel) else compression_level

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
) -> List[Tuple[str, bytes]]:
    """Decompress a ZIP archive from bytes in memory.

    This function allows decompressing ZIP data without reading from the filesystem,
    useful for web applications, APIs, or processing data in memory.

    Args:
        data: The ZIP archive data as bytes.
        password: Optional password for encrypted archives.

    Returns:
        List of (filename, content) tuples. Each tuple contains:
        - filename: The name of the file in the archive (may include path like "subdir/file.txt")
        - content: The decompressed bytes content

    Raises:
        IOError: If decompression fails.
        ValueError: If password is incorrect.

    Example:
        >>> # Decompress from bytes
        >>> files = decompress_bytes(zip_data, password="secret")
        >>> for filename, content in files:
        ...     print(f"{filename}: {len(content)} bytes")
        ...
        hello.txt: 13 bytes
        data/info.json: 16 bytes
        >>>
        >>> # Access specific file
        >>> content_dict = {name: data for name, data in files}
        >>> hello_content = content_dict["hello.txt"]
    """
    result = _rust.decompress_bytes(data, password)
    return [(name, bytes(content)) for name, content in result]


# =============================================================================
# Streaming Compression Functions
# =============================================================================


def compress_stream(
    files: List[Tuple[str, "BinaryIO"]],
    output: "BinaryIO",
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> None:
    """Compress files from file-like objects to an output stream.

    This function reads data in chunks and writes compressed output without
    loading entire files into memory. Ideal for large files or when you want
    to avoid memory spikes.

    Args:
        files: List of (archive_name, file_object) tuples. Each file_object must
               be a file-like object with a read() method (e.g., open file, BytesIO).
        output: Output file-like object with write() and seek() methods.
                Must be opened in binary write mode (e.g., open('out.zip', 'wb') or BytesIO()).
        password: Optional password for encryption.
        encryption: Encryption method to use. Defaults to AES256.
        compression_level: Compression level (0-9 or CompressionLevel enum). Defaults to DEFAULT (6).
        suppress_warning: If True, suppresses security warnings for weak encryption.

    Raises:
        IOError: If compression fails.
        ValueError: If parameters are invalid.

    Example:
        >>> import io
        >>> from rustyzipper import compress_stream, EncryptionMethod
        >>>
        >>> # Compress files to a BytesIO buffer (streaming)
        >>> output = io.BytesIO()
        >>> with open("large_file.bin", "rb") as f1:
        ...     compress_stream(
        ...         [("large_file.bin", f1)],
        ...         output,
        ...         password="secret"
        ...     )
        >>> zip_data = output.getvalue()
        >>>
        >>> # Stream directly to a file
        >>> with open("output.zip", "wb") as out:
        ...     with open("data.txt", "rb") as f:
        ...         compress_stream([("data.txt", f)], out, encryption=EncryptionMethod.NONE)
    """
    enc_value = encryption.value if isinstance(encryption, EncryptionMethod) else encryption
    level = compression_level.value if isinstance(compression_level, CompressionLevel) else compression_level

    _rust.compress_stream(
        files,
        output,
        password,
        enc_value,
        level,
        suppress_warning,
    )


def decompress_stream(
    input: "BinaryIO",
    password: Optional[str] = None,
) -> List[Tuple[str, bytes]]:
    """Decompress a ZIP archive from a file-like object (streaming).

    This function reads the ZIP archive from a seekable file-like object,
    allowing streaming decompression from files, network responses, etc.

    Note: The input must support seeking (seek() method) because ZIP files
    store their directory at the end. For non-seekable streams, read into
    a BytesIO first.

    Args:
        input: Input file-like object with read() and seek() methods.
               Must be opened in binary read mode (e.g., open('in.zip', 'rb') or BytesIO()).
        password: Optional password for encrypted archives.

    Returns:
        List of (filename, content) tuples. Each tuple contains:
        - filename: The name of the file in the archive
        - content: The decompressed bytes content

    Raises:
        IOError: If decompression fails.
        ValueError: If password is incorrect.

    Example:
        >>> from rustyzipper import decompress_stream
        >>>
        >>> # Stream from a file
        >>> with open("archive.zip", "rb") as f:
        ...     files = decompress_stream(f, password="secret")
        ...     for filename, content in files:
        ...         print(f"{filename}: {len(content)} bytes")
        >>>
        >>> # Stream from BytesIO (e.g., from network response)
        >>> import io
        >>> zip_data = download_from_network()
        >>> buf = io.BytesIO(zip_data)
        >>> files = decompress_stream(buf)
    """
    result = _rust.decompress_stream(input, password)
    return [(name, bytes(content)) for name, content in result]


# =============================================================================
# Streaming Iterator Functions (Per-File Streaming)
# =============================================================================

# Re-export the ZipStreamReader classes directly from Rust
ZipStreamReader = _rust.ZipStreamReader
ZipFileStreamReader = _rust.ZipFileStreamReader


def open_zip_stream(
    data: bytes,
    password: Optional[str] = None,
) -> "ZipStreamReader":
    """Open a ZIP archive for streaming iteration (per-file).

    This function returns a ZipStreamReader that yields files one at a time,
    keeping only one decompressed file in memory at once. This is ideal for
    processing large ZIP archives with many files.

    Memory behavior:
    - The ZIP archive data is stored in memory (required for seeking)
    - Decompressed files are yielded one at a time
    - Only one decompressed file is in memory at any moment

    Args:
        data: The ZIP archive data as bytes.
        password: Optional password for encrypted archives.

    Returns:
        ZipStreamReader: An iterator yielding (filename, content) tuples.
        Also supports:
        - len(reader): Number of files in the archive
        - reader.namelist(): List of all filenames
        - reader.read(name): Extract a specific file by name
        - reader.file_count: Number of files (excluding directories)
        - reader.total_entries: Total entries including directories

    Example:
        >>> from rustyzipper import open_zip_stream, compress_bytes
        >>>
        >>> # Create a test ZIP
        >>> zip_data = compress_bytes([
        ...     ("file1.txt", b"Content 1"),
        ...     ("file2.txt", b"Content 2"),
        ...     ("file3.txt", b"Content 3"),
        ... ])
        >>>
        >>> # Process files one at a time (memory efficient)
        >>> for filename, content in open_zip_stream(zip_data):
        ...     print(f"Processing {filename}: {len(content)} bytes")
        ...     # Only this file's content is in memory
        ...
        Processing file1.txt: 9 bytes
        Processing file2.txt: 9 bytes
        Processing file3.txt: 9 bytes
        >>>
        >>> # Use as a random-access reader
        >>> reader = open_zip_stream(zip_data)
        >>> print(f"Files: {reader.namelist()}")
        >>> content = reader.read("file2.txt")
    """
    return _rust.open_zip_stream(data, password)


def open_zip_stream_from_file(
    input: BinaryIO,
    password: Optional[str] = None,
) -> "ZipFileStreamReader":
    """Open a ZIP archive from a file-like object for TRUE streaming iteration.

    This function provides maximum memory efficiency by reading directly from
    the file handle without loading the ZIP data into memory. The file handle
    must remain open during iteration.

    Memory behavior:
    - ZIP data is NOT loaded into memory
    - Only central directory metadata is cached
    - Decompressed files are yielded one at a time
    - File handle must remain open during iteration

    Args:
        input: A file-like object with read() and seek() methods.
               Must remain open during iteration.
        password: Optional password for encrypted archives.

    Returns:
        ZipFileStreamReader: An iterator yielding (filename, content) tuples.
        Also supports:
        - len(reader): Number of files in the archive
        - reader.namelist(): List of all filenames
        - reader.read(name): Extract a specific file by name
        - reader.file_count: Number of files (excluding directories)
        - reader.total_entries: Total entries including directories

    Example:
        >>> from rustyzipper import open_zip_stream_from_file
        >>>
        >>> # True streaming - ZIP data NOT loaded into memory
        >>> with open("huge_archive.zip", "rb") as f:
        ...     reader = open_zip_stream_from_file(f)
        ...     print(f"Archive contains {len(reader)} files")
        ...
        ...     for filename, content in reader:
        ...         # Only one file's decompressed content in memory
        ...         process_file(filename, content)
        ...
        ...     # Random access (still uses file handle)
        ...     specific = reader.read("important.txt")

    Note:
        The file handle MUST remain open during iteration. If you close
        the file before iteration completes, you'll get an error.

        For BytesIO or when you don't need true streaming, consider
        `open_zip_stream()` which loads ZIP data into memory but is
        simpler to use.
    """
    return _rust.open_zip_stream_from_file(input, password)
