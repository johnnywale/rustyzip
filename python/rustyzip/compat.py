"""
pyminizip Compatibility Layer

This module provides a drop-in replacement for pyminizip, allowing easy migration
to RustyZip without changing existing code.

Usage:
    # Change this:
    # import pyminizip

    # To this:
    from rustyzip.compat import pyminizip

    # Rest of your code works as-is!
    pyminizip.compress("file.txt", None, "output.zip", "password", 5)
    pyminizip.uncompress("output.zip", "password", "extracted/", False)

Note:
    For pyminizip compatibility, this module uses ZipCrypto encryption by default
    when a password is provided, matching pyminizip's behavior. For better security,
    consider using the modern rustyzip API with AES256 encryption.
"""

from typing import List, Optional, Union

from rustyzip import rustyzip as _rust


class _PyminizipCompat:
    """pyminizip compatibility class providing the same API as pyminizip."""

    @staticmethod
    def compress(
        src: Union[str, List[str]],
        src_prefix: Union[None, str, List[Optional[str]]],
        dst: str,
        password: Optional[str],
        compress_level: int,
    ) -> None:
        """Compress file(s) to a ZIP archive.

        This function provides API compatibility with pyminizip.compress().

        Args:
            src: Source file path (single file) or list of file paths.
            src_prefix: Prefix path in archive (single) or list of prefixes.
                       Use None for no prefix.
            dst: Destination ZIP file path.
            password: Password for encryption (uses ZipCrypto for compatibility).
                     Use None for no encryption.
            compress_level: Compression level (1-9).

        Raises:
            IOError: If file operations fail.

        Example:
            >>> pyminizip.compress("file.txt", None, "output.zip", "password", 5)
            >>> pyminizip.compress(
            ...     ["file1.txt", "file2.txt"],
            ...     ["dir1", "dir2"],
            ...     "output.zip",
            ...     "password",
            ...     5
            ... )
        """
        _rust.compress(src, src_prefix, dst, password, compress_level)

    @staticmethod
    def uncompress(
        src: str,
        password: Optional[str],
        dst: str,
        delete_zip: bool,
    ) -> None:
        """Extract a ZIP archive.

        This function provides API compatibility with pyminizip.uncompress().

        Args:
            src: Source ZIP file path.
            password: Password for encrypted archives. Use None if not encrypted.
            dst: Destination directory path.
            delete_zip: Whether to delete the ZIP file after extraction.

        Raises:
            IOError: If file operations fail.
            ValueError: If password is incorrect.

        Example:
            >>> pyminizip.uncompress("archive.zip", "password", "extracted/", False)
        """
        _rust.uncompress(src, password, dst, delete_zip)


# Create a module-like object for compatibility
pyminizip = _PyminizipCompat()

__all__ = ["pyminizip"]
