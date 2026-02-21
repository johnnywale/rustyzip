"""Archive modification functions (add, remove, rename, update)."""

from typing import List, Optional, Tuple, Union

from ._core import _rust, _enc_value, _level_value
from .enums import CompressionLevel, EncryptionMethod


# =============================================================================
# File-based Archive Modification Functions
# =============================================================================


def add_to_archive(
    archive_path: str,
    files: List[str],
    archive_names: List[str],
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
) -> None:
    """Add files to an existing ZIP archive.

    This function adds new files to an existing archive. Existing files in the
    archive are preserved.

    Args:
        archive_path: Path to the existing ZIP archive.
        files: List of file paths to add.
        archive_names: Names for the files in the archive. Must have the same
                       length as files. Can include paths (e.g., "subdir/file.txt").
        password: Optional password for encryption of new files.
        encryption: Encryption method for new files. Defaults to AES256.
        compression_level: Compression level for new files. Defaults to DEFAULT (6).

    Raises:
        FileNotFoundError: If the archive or any input file doesn't exist.
        ValueError: If the number of files doesn't match archive_names.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> # Add a single file
        >>> add_to_archive("archive.zip", ["new_file.txt"], ["docs/new_file.txt"])
        >>>
        >>> # Add multiple files with paths
        >>> add_to_archive(
        ...     "archive.zip",
        ...     ["file1.txt", "file2.txt"],
        ...     ["documents/file1.txt", "documents/file2.txt"],
        ...     password="secret"
        ... )
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    _rust.add_to_archive(
        archive_path,
        files,
        archive_names,
        password,
        enc_value,
        level,
    )


def add_bytes_to_archive(
    archive_path: str,
    data: bytes,
    archive_name: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
) -> None:
    """Add bytes data to an existing ZIP archive.

    This function adds in-memory data as a new file to an existing archive.

    Args:
        archive_path: Path to the existing ZIP archive.
        data: Data to add as a file.
        archive_name: Name for the file in the archive. Can include paths.
        password: Optional password for encryption.
        encryption: Encryption method. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).

    Raises:
        FileNotFoundError: If the archive doesn't exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> # Add JSON data to archive
        >>> config = b'{"setting": "value"}'
        >>> add_bytes_to_archive("archive.zip", config, "config.json")
        >>>
        >>> # Add encrypted data
        >>> add_bytes_to_archive(
        ...     "archive.zip",
        ...     b"secret data",
        ...     "secrets/data.txt",
        ...     password="p@ssw0rd"
        ... )
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    _rust.add_bytes_to_archive(
        archive_path,
        data,
        archive_name,
        password,
        enc_value,
        level,
    )


def remove_from_archive(archive_path: str, file_names: List[str]) -> int:
    """Remove files from a ZIP archive.

    This function removes one or more files from an existing archive.

    Args:
        archive_path: Path to the ZIP archive.
        file_names: Names of files to remove. Must match exactly,
                    including any directory paths.

    Returns:
        The number of files that were actually removed.

    Raises:
        FileNotFoundError: If the archive doesn't exist.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> # Remove a single file
        >>> removed = remove_from_archive("archive.zip", ["old_file.txt"])
        >>> print(f"Removed {removed} files")
        >>>
        >>> # Remove multiple files
        >>> removed = remove_from_archive("archive.zip", [
        ...     "temp/cache.dat",
        ...     "logs/debug.log",
        ...     "backup.bak"
        ... ])
    """
    return _rust.remove_from_archive(archive_path, file_names)


def rename_in_archive(archive_path: str, old_name: str, new_name: str) -> None:
    """Rename a file within a ZIP archive.

    This function renames a file inside an existing archive without
    extracting or recompressing its contents.

    Args:
        archive_path: Path to the ZIP archive.
        old_name: Current name of the file (must match exactly,
                  including any directory path).
        new_name: New name for the file. Can include different path.

    Raises:
        FileNotFoundError: If the archive doesn't exist or the file isn't found.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> # Simple rename
        >>> rename_in_archive("archive.zip", "old_name.txt", "new_name.txt")
        >>>
        >>> # Move to different directory
        >>> rename_in_archive(
        ...     "archive.zip",
        ...     "temp/file.txt",
        ...     "documents/file.txt"
        ... )
    """
    _rust.rename_in_archive(archive_path, old_name, new_name)


def update_in_archive(
    archive_path: str,
    file_name: str,
    new_data: bytes,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
) -> None:
    """Update (replace) a file's content within a ZIP archive.

    This function replaces the content of an existing file in the archive.
    The file must already exist in the archive.

    Args:
        archive_path: Path to the ZIP archive.
        file_name: Name of the file to update in the archive.
        new_data: New content for the file.
        password: Optional password for encryption.
        encryption: Encryption method. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).

    Raises:
        FileNotFoundError: If the archive doesn't exist or the file isn't found.
        IOError: If the file is not a valid ZIP archive.

    Example:
        >>> # Update a config file
        >>> new_config = b'{"version": 2, "updated": true}'
        >>> update_in_archive("archive.zip", "config.json", new_config)
        >>>
        >>> # Update with encryption
        >>> update_in_archive(
        ...     "archive.zip",
        ...     "secrets/api_key.txt",
        ...     b"new_api_key_12345",
        ...     password="secure"
        ... )
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    _rust.update_in_archive(
        archive_path,
        file_name,
        new_data,
        password,
        enc_value,
        level,
    )


# =============================================================================
# Bytes-based Archive Modification Functions
# =============================================================================


def add_to_archive_bytes(
    archive_data: bytes,
    files_data: List[Tuple[bytes, str]],
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
) -> bytes:
    """Add files to a ZIP archive in memory.

    This function adds new files to an in-memory archive and returns
    the modified archive data.

    Args:
        archive_data: Existing archive data as bytes.
        files_data: List of (data, name) tuples to add. Each tuple contains:
                    - data: The file content as bytes
                    - name: The archive name for the file
        password: Optional password for encryption.
        encryption: Encryption method. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).

    Returns:
        The modified archive data as bytes.

    Example:
        >>> # Add files to in-memory archive
        >>> with open("archive.zip", "rb") as f:
        ...     archive_data = f.read()
        >>>
        >>> new_data = add_to_archive_bytes(
        ...     archive_data,
        ...     [(b"content1", "file1.txt"), (b"content2", "file2.txt")]
        ... )
        >>>
        >>> # Write back to file
        >>> with open("archive.zip", "wb") as f:
        ...     f.write(new_data)
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    return bytes(_rust.add_to_archive_bytes(
        archive_data,
        files_data,
        password,
        enc_value,
        level,
    ))


def remove_from_archive_bytes(archive_data: bytes, file_names: List[str]) -> Tuple[bytes, int]:
    """Remove files from a ZIP archive in memory.

    Args:
        archive_data: Existing archive data as bytes.
        file_names: Names of files to remove.

    Returns:
        A tuple of (modified archive data, number of files removed).

    Example:
        >>> new_data, count = remove_from_archive_bytes(archive_data, ["old.txt"])
        >>> print(f"Removed {count} files")
    """
    result, count = _rust.remove_from_archive_bytes(archive_data, file_names)
    return bytes(result), count


def rename_in_archive_bytes(archive_data: bytes, old_name: str, new_name: str) -> bytes:
    """Rename a file within a ZIP archive in memory.

    Args:
        archive_data: Existing archive data as bytes.
        old_name: Current name of the file.
        new_name: New name for the file.

    Returns:
        The modified archive data as bytes.

    Example:
        >>> new_data = rename_in_archive_bytes(archive_data, "old.txt", "new.txt")
    """
    return bytes(_rust.rename_in_archive_bytes(archive_data, old_name, new_name))


def update_in_archive_bytes(
    archive_data: bytes,
    file_name: str,
    new_data: bytes,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
) -> bytes:
    """Update (replace) a file's content within a ZIP archive in memory.

    Args:
        archive_data: Existing archive data as bytes.
        file_name: Name of the file to update.
        new_data: New content for the file.
        password: Optional password for encryption.
        encryption: Encryption method. Defaults to AES256.
        compression_level: Compression level. Defaults to DEFAULT (6).

    Returns:
        The modified archive data as bytes.

    Example:
        >>> new_data = update_in_archive_bytes(
        ...     archive_data,
        ...     "config.json",
        ...     b'{"updated": true}'
        ... )
    """
    enc_value = _enc_value(encryption)
    level = _level_value(compression_level)

    return bytes(_rust.update_in_archive_bytes(
        archive_data,
        file_name,
        new_data,
        password,
        enc_value,
        level,
    ))
