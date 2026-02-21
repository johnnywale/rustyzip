"""Security policy configuration for RustyZipper decompression operations."""

import re
from typing import Optional, Union


# These match the Rust defaults
DEFAULT_MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_MAX_COMPRESSION_RATIO = 500  # 500:1


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
