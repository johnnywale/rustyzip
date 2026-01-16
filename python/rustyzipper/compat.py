"""
pyminizip Compatibility Layer

This module provides a drop-in replacement for pyminizip, allowing easy migration
to RustyZip without changing existing code.

Usage:
    # Change this:
    # import pyminizip

    # To this:
    from rustyzipper.compat import pyminizip

    # Rest of your code works as-is!
    pyminizip.compress("file.txt", None, "output.zip", "password", 5)
    pyminizip.compress_multiple(["file1.txt", "file2.txt"], [], "output.zip", "password", 5, progress_callback)
    pyminizip.uncompress("output.zip", "password", "extracted/", 0)

Security Features:
    Unlike pyminizip, this module includes built-in protection against ZIP bombs
    and path traversal attacks. The uncompress() function supports optional
    security parameters:

    # Disable size limit for large archives
    pyminizip.uncompress("large.zip", "password", "extracted/", 0, max_size=0)

    # Custom limits
    pyminizip.uncompress("archive.zip", "password", "extracted/", 0,
                        max_size=10*1024*1024*1024,  # 10GB
                        max_ratio=1000)              # Allow 1000:1 ratio

    Default protections:
    - Maximum decompressed size: 2 GB
    - Maximum compression ratio: 500:1
    - Path traversal: Always blocked
    - Symlinks: Blocked by default

Note:
    For pyminizip compatibility, this module uses ZipCrypto encryption by default
    when a password is provided, matching pyminizip's behavior. For better security,
    consider using the modern rustyzipper API with AES256 encryption.
"""

from typing import Callable, List, Optional, Union

from rustyzipper import rustyzip as _rust


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
    def compress_multiple(
        src_files: List[str],
        src_prefixes: List[str],
        dst: str,
        password: Optional[str],
        compress_level: int,
        progress: Optional[Callable[[int], None]] = None,
    ) -> None:
        """Compress multiple files to a ZIP archive with optional progress callback.

        This function provides API compatibility with pyminizip.compress_multiple().

        Args:
            src_files: List of source file paths to compress.
            src_prefixes: List of prefix paths in archive for each file.
                         Use [] for no prefixes.
            dst: Destination ZIP file path.
            password: Password for encryption (uses ZipCrypto for compatibility).
                     Use None for no encryption.
            compress_level: Compression level (1-9).
            progress: Optional callback function that takes one argument - the count
                     of how many files have been compressed. Called after compression.

        Raises:
            IOError: If file operations fail.

        Example:
            >>> def on_progress(count):
            ...     print(f"Compressed {count} files")
            >>> pyminizip.compress_multiple(
            ...     ["file1.txt", "file2.txt"],
            ...     ["/path1", "/path2"],
            ...     "output.zip",
            ...     "password",
            ...     5,
            ...     on_progress
            ... )
        """
        # Convert empty list to None prefixes
        prefixes: List[Optional[str]]
        if not src_prefixes:
            prefixes = [None] * len(src_files)
        else:
            prefixes = [p if p else None for p in src_prefixes]

        _rust.compress(src_files, prefixes, dst, password, compress_level)

        # Call progress callback with total count after compression
        if progress is not None:
            progress(len(src_files))

    @staticmethod
    def uncompress(
        src: str,
        password: Optional[str],
        dst: Optional[str],
        withoutpath: int,
        *,
        max_size: Optional[int] = None,
        max_ratio: Optional[int] = None,
        allow_symlinks: bool = False,
    ) -> None:
        """Extract a ZIP archive with optional security settings.

        This function provides API compatibility with pyminizip.uncompress(),
        with additional security parameters for ZIP bomb protection.

        Args:
            src: Source ZIP file path.
            password: Password for encrypted archives. Use None if not encrypted.
            dst: Destination directory path, or None to extract to current working directory.
            withoutpath: If non-zero, extract files without their directory paths
                        (flatten all files into the destination directory).
            max_size: Maximum total decompressed size in bytes. Default is 2GB.
                     Set to 0 to disable size checking.
            max_ratio: Maximum compression ratio allowed. Default is 500.
                      Set to 0 to disable ratio checking.
            allow_symlinks: Whether to allow extracting symbolic links. Default is False.

        Returns:
            Always returns None.

        Raises:
            IOError: If file operations fail.
            ValueError: If password is incorrect.
            RustyZipError: If ZIP bomb limits are exceeded.

        Example:
            >>> # Basic usage (protected by secure defaults)
            >>> pyminizip.uncompress("archive.zip", "password", "extracted/", 0)

            >>> # Disable size limit for large archives
            >>> pyminizip.uncompress("large.zip", "password", "extracted/", 0, max_size=0)

            >>> # Custom limits
            >>> pyminizip.uncompress("archive.zip", "password", "extracted/", 0,
            ...                      max_size=10*1024*1024*1024,  # 10GB
            ...                      max_ratio=1000)
        """
        import os
        # Use current working directory if dst is None
        extract_dir = dst if dst is not None else os.getcwd()
        _rust.uncompress(src, password, extract_dir, withoutpath,
                        max_size=max_size, max_ratio=max_ratio,
                        allow_symlinks=allow_symlinks)


# Create a module-like object for compatibility
pyminizip = _PyminizipCompat()

__all__ = ["pyminizip"]
