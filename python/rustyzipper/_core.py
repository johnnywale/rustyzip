"""Internal core utilities for RustyZipper submodules."""

from enum import Enum
from typing import Union

# Import the Rust extension module
from . import rustyzip as _rust


def _enc_value(encryption: Union["_EncryptionLike", str]) -> str:
    """Extract the string value from an EncryptionMethod enum or pass through a string."""
    return encryption.value if isinstance(encryption, Enum) else encryption


def _level_value(compression_level: Union["_CompressionLike", int]) -> int:
    """Extract the int value from a CompressionLevel enum or pass through an int."""
    return compression_level.value if isinstance(compression_level, Enum) else compression_level
