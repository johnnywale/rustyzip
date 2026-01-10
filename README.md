# rustyzipper

[![CI](https://github.com/johnnywale/rustyzipper/actions/workflows/ci.yml/badge.svg)](https://github.com/johnnywale/rustyzipper/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rustyzipper.svg)](https://pypi.org/project/rustyzipper/)
[![Python](https://img.shields.io/pypi/pyversions/rustyzipper.svg)](https://pypi.org/project/rustyzipper/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A high-performance, secure file compression library with password protection, written in Rust with Python bindings.

**rustyzipper** is a modern, actively maintained replacement for [pyminizip](https://github.com/smihica/pyminizip), addressing critical security vulnerabilities while more encryption options.

## Why rustyzipper?

### Problems with pyminizip:
- Abandoned (last update years ago)
- Security vulnerabilities (CVE-2022-37434)
- Outdated zlib version
- No AES-256 support

### rustyzipper advantages:
- **Actively maintained** with regular updates
- **No known security vulnerabilities**
- **Modern zlib** (latest version)
- **AES-256 encryption** for sensitive data
- **Drop-in pyminizip replacement**
- **Windows Explorer compatible** (ZipCrypto option)
- **Zero Python dependencies** (fully self-contained)

## Installation

```bash
pip install rustyzipper
```

## Quick Start

### Modern API (Recommended)

```python
from rustyzipper import compress_file, decompress_file, EncryptionMethod

# Secure compression with AES-256 (recommended for sensitive data)
compress_file("document.pdf", "secure.zip", password="MySecureP@ssw0rd")

# Windows Explorer compatible (weak security, use only for non-sensitive files)
compress_file(
    "public.pdf",
    "compatible.zip",
    password="simple123",
    encryption=EncryptionMethod.ZIPCRYPTO,
    suppress_warning=True
)

# Decompress
decompress_file("secure.zip", "extracted/", password="MySecureP@ssw0rd")
```

### pyminizip Compatibility (No Code Changes Required)

```python
# Change this line:
# import pyminizip

# To this:
from rustyzipper.compat import pyminizip

# Rest of your code works as-is!
pyminizip.compress("file.txt", None, "output.zip", "password", 5)
pyminizip.uncompress("output.zip", "password", "extracted/", False)
```

## Features

### Encryption Methods

| Method | Security | Compatibility | Use Case |
|--------|----------|---------------|----------|
| **AES-256** | Strong | 7-Zip, WinRAR, WinZip | Sensitive data |
| **ZipCrypto** | Weak | Windows Explorer, All tools | Maximum compatibility |
| **None** | None | All tools | Non-sensitive data |

### Compression Levels

```python
from rustyzipper import CompressionLevel

CompressionLevel.STORE    # No compression (fastest)
CompressionLevel.FAST     # Fast compression
CompressionLevel.DEFAULT  # Balanced (recommended)
CompressionLevel.BEST     # Maximum compression (slowest)
```

## API Reference

### compress_file

```python
compress_file(
    input_path: str,
    output_path: str,
    password: str | None = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    suppress_warning: bool = False
) -> None
```

### compress_files

```python
compress_files(
    input_paths: list[str],
    output_path: str,
    password: str | None = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    prefixes: list[str | None] | None = None
) -> None
```

### compress_directory

```python
compress_directory(
    input_dir: str,
    output_path: str,
    password: str | None = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None
) -> None
```

### decompress_file

```python
decompress_file(
    input_path: str,
    output_path: str,
    password: str | None = None
) -> None
```

## Examples

### Compress a Directory with Filters

```python
from rustyzipper import compress_directory, EncryptionMethod

compress_directory(
    "my_project/",
    "backup.zip",
    password="BackupP@ss",
    encryption=EncryptionMethod.AES256,
    include_patterns=["*.py", "*.md", "*.json"],
    exclude_patterns=["__pycache__", "*.pyc", ".git", "node_modules"]
)
```

### Compress Multiple Files

```python
from rustyzipper import compress_files

compress_files(
    ["report.pdf", "data.csv", "summary.txt"],
    "documents.zip",
    password="secret",
    prefixes=["reports", "data", "reports"]  # Archive paths
)
```

## In-Memory and Streaming Compression

rustyzipper provides multiple APIs for different use cases, from simple in-memory operations to memory-efficient streaming for large files.

### In-Memory Compression (`compress_bytes` / `decompress_bytes`)

Compress and decompress data directly in memory without filesystem I/O. Ideal for web applications, APIs, and processing data in memory.

```python
from rustyzipper import compress_bytes, decompress_bytes, EncryptionMethod

# Compress multiple files to bytes
files = [
    ("hello.txt", b"Hello, World!"),
    ("data/config.json", b'{"key": "value"}'),
    ("binary.bin", bytes(range(256))),
]
zip_data = compress_bytes(files, password="secret")

# Send over network, store in database, etc.
# ...

# Decompress back to list of (filename, content) tuples
extracted = decompress_bytes(zip_data, password="secret")
for filename, content in extracted:
    print(f"{filename}: {len(content)} bytes")
```

**Note:** These functions load all data into memory. For large files, use streaming APIs below.

### Streaming Compression (`compress_stream` / `decompress_stream`)

Stream data through file-like objects. Compresses in 64KB chunks to reduce memory usage.

```python
import io
from rustyzipper import compress_stream, decompress_stream, EncryptionMethod

# Compress from file handles to BytesIO
output = io.BytesIO()
with open("large_file.bin", "rb") as f1, open("another.txt", "rb") as f2:
    compress_stream(
        [("large_file.bin", f1), ("another.txt", f2)],
        output,
        password="secret"
    )

zip_data = output.getvalue()

# Decompress from BytesIO
output.seek(0)
files = decompress_stream(output, password="secret")

# Or stream directly to/from files
with open("output.zip", "wb") as out:
    with open("input.txt", "rb") as inp:
        compress_stream([("input.txt", inp)], out, encryption=EncryptionMethod.NONE)
```

### Per-File Streaming Iterator (`open_zip_stream`)

For processing large ZIP archives with many files, use the streaming iterator to decompress one file at a time. This keeps only one decompressed file in memory at any moment.

```python
from rustyzipper import open_zip_stream, open_zip_stream_from_file

# From bytes
zip_data = open("archive.zip", "rb").read()
for filename, content in open_zip_stream(zip_data, password="secret"):
    print(f"Processing {filename}: {len(content)} bytes")
    process_file(content)
    # Previous file's content is garbage collected

# From file handle
with open("archive.zip", "rb") as f:
    for filename, content in open_zip_stream_from_file(f):
        process_file(content)

# Random access and inspection
reader = open_zip_stream(zip_data)
print(f"Files: {reader.namelist()}")        # List all files
print(f"Count: {len(reader)}")              # Number of files
content = reader.read("specific_file.txt")  # Extract by name
```

### Memory Comparison

| Function | ZIP Data | Decompressed Files | Best For |
|----------|----------|-------------------|----------|
| `decompress_bytes()` | All in memory | All at once | Small archives |
| `decompress_stream()` | Streamed | All at once | Large ZIP, small files |
| `open_zip_stream()` | All in memory | One at a time | Many files, ZIP fits in RAM |
| `open_zip_stream_from_file()` | **Streamed** | One at a time | Huge ZIP files |

### Choosing the Right Function

```
Is your ZIP file small (< 100MB)?
├── Yes → Use decompress_bytes() or open_zip_stream()
└── No → Is the ZIP itself too large for memory?
    ├── Yes → Use open_zip_stream_from_file() (true streaming)
    └── No → Use open_zip_stream() (ZIP in memory, files streamed)
```

**Example: 10GB ZIP with 100 files (100MB each when decompressed)**

| Function | Peak Memory |
|----------|-------------|
| `decompress_bytes()` | ~10GB (all decompressed at once) |
| `open_zip_stream()` | ~compressed size + 100MB (one file at a time) |
| `open_zip_stream_from_file()` | ~100MB only (true streaming) |

### API Reference

#### compress_bytes

```python
compress_bytes(
    files: list[tuple[str, bytes]],
    password: str | None = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    suppress_warning: bool = False
) -> bytes
```

#### decompress_bytes

```python
decompress_bytes(
    data: bytes,
    password: str | None = None
) -> list[tuple[str, bytes]]
```

#### compress_stream

```python
compress_stream(
    files: list[tuple[str, BinaryIO]],
    output: BinaryIO,
    password: str | None = None,
    encryption: EncryptionMethod = EncryptionMethod.AES256,
    compression_level: CompressionLevel = CompressionLevel.DEFAULT,
    suppress_warning: bool = False
) -> None
```

#### decompress_stream

```python
decompress_stream(
    input: BinaryIO,
    password: str | None = None
) -> list[tuple[str, bytes]]
```

#### open_zip_stream

```python
open_zip_stream(
    data: bytes,
    password: str | None = None
) -> ZipStreamReader

# ZipStreamReader supports:
# - Iteration: for filename, content in reader
# - len(reader): Number of files
# - reader.namelist(): List of filenames
# - reader.read(name): Extract specific file
# - reader.file_count: Number of files (property)
# - reader.total_entries: Total entries including directories (property)
```

#### open_zip_stream_from_file

```python
open_zip_stream_from_file(
    input: BinaryIO,
    password: str | None = None
) -> ZipFileStreamReader

# ZipFileStreamReader supports the same interface as ZipStreamReader
# but reads directly from the file handle (true streaming).
# NOTE: File handle must remain open during iteration!
```

**Usage example:**

```python
from rustyzipper import open_zip_stream_from_file

# True streaming - even 100GB ZIP files work with minimal memory
with open("huge_archive.zip", "rb") as f:
    for filename, content in open_zip_stream_from_file(f):
        process_file(content)  # Only one file in memory at a time
```

## Security Guidelines

### DO:
- Use **AES-256** for sensitive data
- Use strong passwords (12+ characters, mixed case, numbers, symbols)
- Store passwords in a password manager
- Use unique passwords for each archive

### DON'T:
- Use ZipCrypto for sensitive data (it's weak!)
- Use weak or common passwords
- Share passwords via insecure channels
- Reuse passwords across archives

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows 10+ | x64, x86, ARM64 | Supported |
| Linux (glibc) | x64, ARM64 | Supported |
| macOS 11+ | x64, ARM64 (Apple Silicon) | Supported |

### Python Version Support
- Python 3.8+

## Building from Source

### Prerequisites
- Rust 1.70+
- Python 3.8+
- maturin (`pip install maturin`)

### Build

```bash
git clone https://github.com/johnnywale/rustyzipper.git
cd rustyzipper

# Development build
maturin develop

# Release build
maturin build --release
```

### Run Tests

```bash
# Rust tests
cargo test

# Python tests
pip install pytest
pytest python/tests/
```

## Comparison with pyminizip

| Feature | pyminizip | rustyzipper |
|---------|-----------|----------|
| Maintenance Status | Abandoned | Active |
| Security Vulnerabilities | Multiple CVEs | None known |
| zlib Version | Outdated | Latest |
| AES-256 Support | No | Yes |
| Memory Safety | C/C++ risks | Rust guarantees |
| Windows Explorer Support | Yes (ZipCrypto) | Yes (ZipCrypto) |
| API Compatibility | N/A | Drop-in replacement |
| Installation | Requires compiler | Prebuilt wheels |
| Type Hints | No | Yes |

## License

Dual-licensed under MIT or Apache 2.0 at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/johnnywale/rustyzipper.git
cd rustyzipper

# Install development dependencies
pip install maturin pytest

# Build and install in development mode
maturin develop

# Run tests
cargo test                    # Rust tests
pytest python/tests/ -v       # Python tests
```

### Supported Platforms

| Platform | Architectures |
|----------|--------------|
| Linux (glibc/musl) | x86_64, aarch64, armv7, i686 |
| Windows | x86_64, i686 |
| macOS | x86_64, aarch64 (Apple Silicon) |

## Links

- [PyPI Package](https://pypi.org/project/rustyzipper/)
- [GitHub Repository](https://github.com/johnnywale/rustyzip)
- [Issue Tracker](https://github.com/johnnywale/rustyzip/issues)
