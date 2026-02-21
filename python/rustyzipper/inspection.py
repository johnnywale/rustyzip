"""Archive inspection functions and classes."""

from typing import List

from ._core import _rust


# Re-export info classes from Rust
FileInfo = _rust.FileInfo
ArchiveInfo = _rust.ArchiveInfo


def list_archive(path: str) -> List[str]:
    """List all files in a ZIP archive.

    Returns a list of file names (including paths within the archive).
    This function does not extract any files - it only reads metadata.

    Args:
        path: Path to the ZIP file.

    Returns:
        A list of file names in the archive, including directory entries.

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> files = list_archive("archive.zip")
        >>> for name in files:
        ...     print(name)
        document.txt
        images/photo.jpg
        data/config.json
    """
    return list(_rust.list_archive(path))


def list_archive_bytes(data: bytes) -> List[str]:
    """List all files in a ZIP archive from bytes.

    Args:
        data: The ZIP archive data as bytes.

    Returns:
        A list of file names in the archive.

    Raises:
        IOError: If the data is not a valid ZIP archive.

    Example:
        >>> with open("archive.zip", "rb") as f:
        ...     data = f.read()
        >>> files = list_archive_bytes(data)
    """
    return list(_rust.list_archive_bytes(data))


def get_archive_info(path: str) -> "ArchiveInfo":
    """Get detailed information about a ZIP archive.

    Returns an ArchiveInfo object with archive metadata including file count,
    total size, compression ratio, and encryption information.
    This function does not extract any files.

    Args:
        path: Path to the ZIP file.

    Returns:
        ArchiveInfo object with the following attributes:
        - total_entries (int): Total number of entries (files and directories)
        - file_count (int): Number of files (excluding directories)
        - dir_count (int): Number of directories
        - total_size (int): Total uncompressed size in bytes
        - total_compressed_size (int): Total compressed size in bytes
        - compression_ratio (float): Overall compression ratio
        - encryption (str): Encryption method ("aes256", "zipcrypto", or "none")
        - has_encrypted_files (bool): Whether the archive contains encrypted files
        - comment (str): Archive comment (if any)

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> info = get_archive_info("archive.zip")
        >>> print(f"Files: {info.file_count}")
        >>> print(f"Total size: {info.total_size} bytes")
        >>> print(f"Compression ratio: {info.compression_ratio:.1f}:1")
        >>> if info.has_encrypted_files:
        ...     print(f"Encryption: {info.encryption}")
    """
    return _rust.get_archive_info(path)


def get_archive_info_bytes(data: bytes) -> "ArchiveInfo":
    """Get detailed information about a ZIP archive from bytes.

    Args:
        data: The ZIP archive data as bytes.

    Returns:
        ArchiveInfo object with archive metadata (see get_archive_info for details).

    Raises:
        IOError: If the data is not a valid ZIP archive.
    """
    return _rust.get_archive_info_bytes(data)


def get_file_info(path: str, file_name: str) -> "FileInfo":
    """Get detailed information about a specific file in a ZIP archive.

    Returns metadata for a single file within the archive without extracting it.

    Args:
        path: Path to the ZIP file.
        file_name: Name of the file within the archive (must match exactly,
                   including any directory path like "subdir/file.txt").

    Returns:
        FileInfo object with the following attributes:
        - name (str): File name (including path within archive)
        - size (int): Uncompressed size in bytes
        - compressed_size (int): Compressed size in bytes
        - is_dir (bool): Whether this entry is a directory
        - is_encrypted (bool): Whether this file is encrypted
        - crc32 (int): CRC32 checksum
        - compression_method (str): Compression method name
        - last_modified (int | None): Last modified time as Unix timestamp
        - compression_ratio (float): Compression ratio for this file

    Raises:
        FileNotFoundError: If the ZIP file or the specified file doesn't exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> info = get_file_info("archive.zip", "document.txt")
        >>> print(f"Size: {info.size} bytes")
        >>> print(f"Compressed: {info.compressed_size} bytes")
        >>> print(f"Encrypted: {info.is_encrypted}")
        >>> print(f"CRC32: {info.crc32:08x}")
    """
    return _rust.get_file_info(path, file_name)


def get_file_info_bytes(data: bytes, file_name: str) -> "FileInfo":
    """Get detailed information about a specific file in a ZIP archive from bytes.

    Args:
        data: The ZIP archive data as bytes.
        file_name: Name of the file within the archive.

    Returns:
        FileInfo object with file metadata (see get_file_info for details).

    Raises:
        FileNotFoundError: If the specified file doesn't exist in the archive.
        IOError: If the data is not a valid ZIP archive.
    """
    return _rust.get_file_info_bytes(data, file_name)


def get_all_file_info(path: str) -> List["FileInfo"]:
    """Get information about all files in a ZIP archive.

    Returns a list of FileInfo objects, each containing metadata for one file.
    This is more efficient than calling get_file_info for each file.

    Args:
        path: Path to the ZIP file.

    Returns:
        A list of FileInfo objects (see get_file_info for attributes).

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> files = get_all_file_info("archive.zip")
        >>> for f in files:
        ...     if not f.is_dir:
        ...         print(f"{f.name}: {f.size} bytes ({f.compression_ratio:.1f}:1)")
    """
    return list(_rust.get_all_file_info(path))


def get_all_file_info_bytes(data: bytes) -> List["FileInfo"]:
    """Get information about all files in a ZIP archive from bytes.

    Args:
        data: The ZIP archive data as bytes.

    Returns:
        A list of FileInfo objects (see get_file_info for attributes).

    Raises:
        IOError: If the data is not a valid ZIP archive.
    """
    return list(_rust.get_all_file_info_bytes(data))


def has_file(path: str, file_name: str) -> bool:
    """Check if a file exists in a ZIP archive.

    This is more efficient than list_archive when you only need to check
    for a specific file, as it can return early once the file is found.

    Args:
        path: Path to the ZIP file.
        file_name: Name of the file to check for (must match exactly,
                   including any directory path).

    Returns:
        True if the file exists in the archive, False otherwise.

    Raises:
        FileNotFoundError: If the ZIP file does not exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> if has_file("archive.zip", "config.json"):
        ...     print("Config file found!")
        ... else:
        ...     print("Config file missing")
    """
    return _rust.has_file(path, file_name)


def has_file_bytes(data: bytes, file_name: str) -> bool:
    """Check if a file exists in a ZIP archive from bytes.

    Args:
        data: The ZIP archive data as bytes.
        file_name: Name of the file to check for.

    Returns:
        True if the file exists in the archive, False otherwise.

    Raises:
        IOError: If the data is not a valid ZIP archive.
    """
    return _rust.has_file_bytes(data, file_name)
