"""Streaming compression and decompression functions."""

from typing import BinaryIO, List, Optional, Tuple, Union

from ._core import _rust, _enc_value, _level_value
from .enums import CompressionLevel, EncryptionMethod
from .security import SecurityPolicy


# Re-export the ZipStreamReader classes directly from Rust
ZipStreamReader = _rust.ZipStreamReader
ZipFileStreamReader = _rust.ZipFileStreamReader


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
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

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
    *,
    policy: Optional[SecurityPolicy] = None,
) -> List[Tuple[str, bytes]]:
    """Decompress a ZIP archive from a file-like object (streaming).

    This function reads the ZIP archive from a seekable file-like object,
    allowing streaming decompression from files, network responses, etc.
    It is secure by default with ZIP bomb protection.

    Note: The input must support seeking (seek() method) because ZIP files
    store their directory at the end. For non-seekable streams, read into
    a BytesIO first.

    Args:
        input: Input file-like object with read() and seek() methods.
               Must be opened in binary read mode (e.g., open('in.zip', 'rb') or BytesIO()).
        password: Optional password for encrypted archives.
        policy: Optional SecurityPolicy to configure extraction limits.
            If None, uses secure defaults (2GB max, 500:1 ratio).

    Returns:
        List of (filename, content) tuples. Each tuple contains:
        - filename: The name of the file in the archive
        - content: The decompressed bytes content

    Raises:
        IOError: If decompression fails.
        ValueError: If password is incorrect.
        RustyZipError: If ZIP bomb limits are exceeded.

    Example:
        >>> from rustyzipper import decompress_stream, SecurityPolicy
        >>>
        >>> # Stream from a file with default security
        >>> with open("archive.zip", "rb") as f:
        ...     files = decompress_stream(f, password="secret")
        ...     for filename, content in files:
        ...         print(f"{filename}: {len(content)} bytes")
        >>>
        >>> # Stream with custom policy
        >>> policy = SecurityPolicy(max_size="5GB")
        >>> with open("large.zip", "rb") as f:
        ...     files = decompress_stream(f, policy=policy)
    """
    max_size = policy.max_size if policy else None
    max_ratio = policy.max_ratio if policy else None

    result = _rust.decompress_stream(input, password, max_size, max_ratio)
    return [(name, bytes(content)) for name, content in result]


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
