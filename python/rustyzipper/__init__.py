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

import re
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
    # Encryption detection
    "detect_encryption",
    "detect_encryption_bytes",
    # Security
    "SecurityPolicy",
    # Enums
    "EncryptionMethod",
    "CompressionLevel",
    "__version__",
]


# =============================================================================
# Default Security Constants
# =============================================================================

# These match the Rust defaults
DEFAULT_MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_MAX_COMPRESSION_RATIO = 500  # 500:1


# =============================================================================
# Security Policy Class
# =============================================================================


class SecurityPolicy:
    """Security policy for decompression operations.

    This class provides a clean, reusable way to configure security limits
    for ZIP extraction. Instead of passing multiple parameters to each
    decompression function, you can create a SecurityPolicy object and
    reuse it across your application.

    Attributes:
        max_size: Maximum total decompressed size in bytes. Default is 2GB.
        max_ratio: Maximum compression ratio allowed. Default is 500:1.
        allow_symlinks: Whether to allow extracting symbolic links. Default is False.

    Default Protections:
        - Maximum decompressed size: 2 GB
        - Maximum compression ratio: 500:1
        - Path traversal: Always blocked (cannot be disabled)
        - Symlinks: Blocked by default

    Examples:
        >>> # Use default secure settings
        >>> decompress_file("archive.zip", "output/")

        >>> # Custom policy for large archives
        >>> policy = SecurityPolicy(max_size="10GB", max_ratio=1000)
        >>> decompress_file("large.zip", "output/", policy=policy)

        >>> # Unlimited policy for trusted archives
        >>> policy = SecurityPolicy.unlimited()
        >>> decompress_file("trusted.zip", "output/", policy=policy)

        >>> # Strict policy for untrusted content
        >>> strict = SecurityPolicy(max_size="100MB", max_ratio=50)
        >>> decompress_file("untrusted.zip", "sandbox/", policy=strict)

        >>> # Reuse policy across multiple operations
        >>> policy = SecurityPolicy(max_size="5GB")
        >>> for archive in archives:
        ...     decompress_file(archive, "output/", policy=policy)
    """

    def __init__(
        self,
        max_size: Optional[Union[int, str]] = None,
        max_ratio: Optional[int] = None,
        allow_symlinks: bool = False,
    ):
        """Create a new SecurityPolicy.

        Args:
            max_size: Maximum total decompressed size. Can be:
                - An integer (bytes)
                - A human-readable string like "500MB", "2GB", "10 GB"
                - None to use default (2GB)
                - 0 to disable size limit
            max_ratio: Maximum compression ratio allowed (e.g., 500 means 500:1).
                - None to use default (500)
                - 0 to disable ratio check
            allow_symlinks: Whether to allow extracting symbolic links.
                Default is False for security.

        Examples:
            >>> # Default policy (2GB max, 500:1 ratio)
            >>> policy = SecurityPolicy()

            >>> # Custom size using human-readable string
            >>> policy = SecurityPolicy(max_size="10GB")

            >>> # Custom size using bytes
            >>> policy = SecurityPolicy(max_size=10 * 1024 * 1024 * 1024)

            >>> # Strict policy
            >>> policy = SecurityPolicy(max_size="100MB", max_ratio=100)
        """
        self._max_size = self._parse_size(max_size) if max_size is not None else None
        self._max_ratio = max_ratio
        self._allow_symlinks = allow_symlinks

    @classmethod
    def unlimited(cls) -> "SecurityPolicy":
        """Create a policy with no size or ratio limits.

        Warning: Only use this for archives you trust completely. Disabling
        security limits can allow ZIP bombs to consume all available disk
        space or memory.

        Returns:
            A SecurityPolicy with all limits disabled.

        Example:
            >>> # For trusted internal archives only
            >>> policy = SecurityPolicy.unlimited()
            >>> decompress_file("internal_backup.zip", "/backup/", policy=policy)
        """
        return cls(max_size=0, max_ratio=0, allow_symlinks=False)

    @classmethod
    def strict(cls, max_size: Union[int, str] = "100MB", max_ratio: int = 100) -> "SecurityPolicy":
        """Create a strict policy for untrusted content.

        This factory method creates a policy suitable for handling untrusted
        ZIP files, such as user uploads. It uses conservative limits to
        minimize risk.

        Args:
            max_size: Maximum decompressed size. Default is "100MB".
            max_ratio: Maximum compression ratio. Default is 100.

        Returns:
            A SecurityPolicy with strict limits.

        Example:
            >>> # For user-uploaded files
            >>> policy = SecurityPolicy.strict()
            >>> decompress_file(user_upload, "sandbox/", policy=policy)
        """
        return cls(max_size=max_size, max_ratio=max_ratio, allow_symlinks=False)

    @staticmethod
    def _parse_size(size: Union[int, str]) -> int:
        """Parse a size value from int or human-readable string.

        Supports formats like:
        - 100, 1024 (plain integers, interpreted as bytes)
        - "100", "1024" (string integers, interpreted as bytes)
        - "500KB", "500 KB", "500kb" (kilobytes)
        - "100MB", "100 MB", "100mb" (megabytes)
        - "10GB", "10 GB", "10gb" (gigabytes)
        - "1TB", "1 TB", "1tb" (terabytes)

        Args:
            size: Size as integer (bytes) or human-readable string.

        Returns:
            Size in bytes as an integer.

        Raises:
            ValueError: If the size string format is invalid.
        """
        if isinstance(size, int):
            return size

        if not isinstance(size, str):
            raise ValueError(f"Invalid size type: {type(size)}")

        size = size.strip().upper()

        # Check if it's just a number
        if size.isdigit():
            return int(size)

        # Parse with units
        units = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
            "TB": 1024 * 1024 * 1024 * 1024,
            "K": 1024,
            "M": 1024 * 1024,
            "G": 1024 * 1024 * 1024,
            "T": 1024 * 1024 * 1024 * 1024,
        }

        # Match number with optional decimal and unit
        match = re.match(r"^(\d+(?:\.\d+)?)\s*([A-Z]+)$", size)
        if not match:
            raise ValueError(
                f"Invalid size format: '{size}'. "
                "Expected format like '500MB', '2GB', '1.5TB', etc."
            )

        value, unit = match.groups()
        if unit not in units:
            raise ValueError(
                f"Unknown size unit: '{unit}'. "
                f"Valid units are: {', '.join(sorted(units.keys()))}"
            )

        return int(float(value) * units[unit])

    @property
    def max_size(self) -> Optional[int]:
        """Maximum total decompressed size in bytes, or None for default."""
        return self._max_size

    @property
    def max_ratio(self) -> Optional[int]:
        """Maximum compression ratio allowed, or None for default."""
        return self._max_ratio

    @property
    def allow_symlinks(self) -> bool:
        """Whether symlink extraction is allowed."""
        return self._allow_symlinks

    def __repr__(self) -> str:
        """Return a string representation of the policy."""
        def format_size(size: Optional[int]) -> str:
            if size is None:
                return "default (2GB)"
            if size == 0:
                return "unlimited"
            if size >= 1024 * 1024 * 1024:
                return f"{size / (1024 * 1024 * 1024):.1f}GB"
            if size >= 1024 * 1024:
                return f"{size / (1024 * 1024):.1f}MB"
            if size >= 1024:
                return f"{size / 1024:.1f}KB"
            return f"{size}B"

        def format_ratio(ratio: Optional[int]) -> str:
            if ratio is None:
                return "default (500:1)"
            if ratio == 0:
                return "unlimited"
            return f"{ratio}:1"

        return (
            f"SecurityPolicy("
            f"max_size={format_size(self._max_size)}, "
            f"max_ratio={format_ratio(self._max_ratio)}, "
            f"allow_symlinks={self._allow_symlinks})"
        )


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
    *,
    policy: Optional[SecurityPolicy] = None,
) -> None:
    """Decompress a ZIP archive with optional security policy.

    This function is secure by default, with built-in protection against
    ZIP bombs and path traversal attacks.

    Args:
        input_path: Path to the ZIP file to decompress.
        output_path: Path for the output directory.
        password: Optional password for encrypted archives.
        policy: Optional SecurityPolicy to configure extraction limits.
            If None, uses secure defaults (2GB max, 500:1 ratio).

    Raises:
        IOError: If file operations fail.
        ValueError: If password is incorrect.
        RustyZipError: If ZIP bomb limits are exceeded.

    Examples:
        >>> # Basic usage with default security
        >>> decompress_file("archive.zip", "extracted/", password="secret")

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
        False,  # withoutpath
        max_size,
        max_ratio,
    )


# =============================================================================
# Encryption Detection Functions
# =============================================================================


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
