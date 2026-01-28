# API Reference

Complete API reference for the RustyZip Python library.

## File Operations

### compress_file

```python
def compress_file(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> None
```

Compress a single file to a ZIP archive.

**Parameters:**

- `input_path`: Path to the file to compress
- `output_path`: Path for the output ZIP file
- `password`: Optional password for encryption
- `encryption`: Encryption method (default: AES256)
- `compression_level`: Compression level (default: 6)
- `suppress_warning`: Suppress weak encryption warnings

---

### compress_files

```python
def compress_files(
    input_paths: List[str],
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    prefixes: Optional[List[Optional[str]]] = None,
    suppress_warning: bool = False,
) -> None
```

Compress multiple files to a ZIP archive.

**Parameters:**

- `input_paths`: List of file paths to compress
- `output_path`: Path for the output ZIP file
- `password`: Optional password for encryption
- `encryption`: Encryption method (default: AES256)
- `compression_level`: Compression level (default: 6)
- `prefixes`: Optional archive path prefixes for each file
- `suppress_warning`: Suppress weak encryption warnings

---

### compress_directory

```python
def compress_directory(
    input_dir: str,
    output_path: str,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    suppress_warning: bool = False,
) -> None
```

Compress a directory to a ZIP archive.

**Parameters:**

- `input_dir`: Directory to compress
- `output_path`: Path for the output ZIP file
- `password`: Optional password for encryption
- `encryption`: Encryption method (default: AES256)
- `compression_level`: Compression level (default: 6)
- `include_patterns`: Glob patterns to include (e.g., `["*.py"]`)
- `exclude_patterns`: Glob patterns to exclude (e.g., `["__pycache__"]`)
- `suppress_warning`: Suppress weak encryption warnings

---

### decompress_file

```python
def decompress_file(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    *,
    policy: Optional[SecurityPolicy] = None,
) -> None
```

Decompress a ZIP archive with optional security policy.

**Parameters:**

- `input_path`: Path to the ZIP file
- `output_path`: Directory for extracted files
- `password`: Optional password for encrypted archives
- `policy`: Security policy (uses secure defaults if None)

---

## In-Memory Operations

### compress_bytes

```python
def compress_bytes(
    files: List[Tuple[str, bytes]],
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> bytes
```

Compress data to a ZIP archive in memory.

**Parameters:**

- `files`: List of `(filename, content)` tuples
- `password`: Optional password for encryption
- `encryption`: Encryption method (default: AES256)
- `compression_level`: Compression level (default: 6)
- `suppress_warning`: Suppress weak encryption warnings

**Returns:** ZIP archive as bytes

---

### decompress_bytes

```python
def decompress_bytes(
    data: bytes,
    password: Optional[str] = None,
    *,
    policy: Optional[SecurityPolicy] = None,
) -> List[Tuple[str, bytes]]
```

Decompress a ZIP archive from bytes.

**Parameters:**

- `data`: ZIP archive data
- `password`: Optional password for encrypted archives
- `policy`: Security policy (uses secure defaults if None)

**Returns:** List of `(filename, content)` tuples

---

## Streaming Operations

### compress_stream

```python
def compress_stream(
    files: List[Tuple[str, BinaryIO]],
    output: BinaryIO,
    password: Optional[str] = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: Union[CompressionLevel, int] = CompressionLevel.DEFAULT,
    suppress_warning: bool = False,
) -> None
```

Compress from file-like objects to an output stream.

**Parameters:**

- `files`: List of `(filename, file_object)` tuples
- `output`: Output file-like object with `write()` and `seek()`
- `password`: Optional password for encryption
- `encryption`: Encryption method (default: AES256)
- `compression_level`: Compression level (default: 6)
- `suppress_warning`: Suppress weak encryption warnings

---

### decompress_stream

```python
def decompress_stream(
    input: BinaryIO,
    password: Optional[str] = None,
    *,
    policy: Optional[SecurityPolicy] = None,
) -> List[Tuple[str, bytes]]
```

Decompress from a file-like object.

**Parameters:**

- `input`: Input file-like object with `read()` and `seek()`
- `password`: Optional password for encrypted archives
- `policy`: Security policy (uses secure defaults if None)

**Returns:** List of `(filename, content)` tuples

---

### open_zip_stream

```python
def open_zip_stream(
    data: bytes,
    password: Optional[str] = None,
) -> ZipStreamReader
```

Open a ZIP archive for per-file streaming iteration.

**Parameters:**

- `data`: ZIP archive data
- `password`: Optional password for encrypted archives

**Returns:** `ZipStreamReader` iterator

---

### open_zip_stream_from_file

```python
def open_zip_stream_from_file(
    input: BinaryIO,
    password: Optional[str] = None,
) -> ZipFileStreamReader
```

Open a ZIP archive from a file handle for true streaming.

**Parameters:**

- `input`: File-like object (must remain open during iteration)
- `password`: Optional password for encrypted archives

**Returns:** `ZipFileStreamReader` iterator

---

## Encryption Detection

### detect_encryption

```python
def detect_encryption(input_path: str) -> EncryptionMethod
```

Detect the encryption method used in a ZIP file.

**Parameters:**

- `input_path`: Path to the ZIP file

**Returns:** `EncryptionMethod` enum value

---

### detect_encryption_bytes

```python
def detect_encryption_bytes(data: bytes) -> EncryptionMethod
```

Detect the encryption method from ZIP data in memory.

**Parameters:**

- `data`: ZIP archive data

**Returns:** `EncryptionMethod` enum value

---

## Classes

### SecurityPolicy

```python
class SecurityPolicy:
    def __init__(
        self,
        max_size: Optional[Union[int, str]] = None,
        max_ratio: Optional[int] = None,
        allow_symlinks: bool = False,
    )

    @classmethod
    def unlimited(cls) -> SecurityPolicy

    @classmethod
    def strict(
        cls,
        max_size: Union[int, str] = "100MB",
        max_ratio: int = 100
    ) -> SecurityPolicy

    @property
    def max_size(self) -> Optional[int]

    @property
    def max_ratio(self) -> Optional[int]

    @property
    def allow_symlinks(self) -> bool
```

Security policy for decompression operations.

**Constructor Parameters:**

- `max_size`: Maximum decompressed size (bytes or string like "2GB")
- `max_ratio`: Maximum compression ratio (e.g., 500 for 500:1)
- `allow_symlinks`: Allow symlink extraction (default: False)

**Class Methods:**

- `unlimited()`: Create policy with no limits (use with caution)
- `strict(max_size, max_ratio)`: Create strict policy for untrusted content

---

### EncryptionMethod

```python
class EncryptionMethod(Enum):
    AES256 = "aes256"      # Strong AES-256 encryption
    ZIPCRYPTO = "zipcrypto"  # Legacy weak encryption
    NONE = "none"          # No encryption
```

---

### CompressionLevel

```python
class CompressionLevel(Enum):
    STORE = 0    # No compression
    FAST = 1     # Fast compression
    DEFAULT = 6  # Balanced (default)
    BEST = 9     # Maximum compression
```

---

### ZipStreamReader

Iterator for per-file streaming from bytes.

**Properties:**

- `file_count`: Number of files (excluding directories)
- `total_entries`: Total entries including directories

**Methods:**

- `__len__()`: Number of files
- `__iter__()`: Iterate over `(filename, content)` tuples
- `namelist()`: List all filenames
- `read(name: str)`: Extract a specific file

---

### ZipFileStreamReader

Iterator for true streaming from a file handle.

Same interface as `ZipStreamReader`, but reads directly from the file handle without loading ZIP data into memory.

---

## Exceptions

All exceptions are in `rustyzipper.exceptions`:

```python
from rustyzipper.exceptions import (
    RustyZipError,           # Base exception
    CompressionError,        # Compression failures
    DecompressionError,      # Decompression failures
    InvalidPasswordError,    # Wrong password (also ValueError)
    FileNotFoundError,       # File not found (also IOError)
    UnsupportedEncryptionError,  # Invalid encryption method
)
```
