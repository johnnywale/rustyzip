"""Enumerations for RustyZipper compression and encryption options."""

from enum import Enum


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
