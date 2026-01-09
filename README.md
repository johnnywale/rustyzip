# RustyZip

[![CI](https://github.com/johnnywalee/rustyzip/actions/workflows/ci.yml/badge.svg)](https://github.com/johnnywalee/rustyzip/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rustyzip.svg)](https://pypi.org/project/rustyzip/)
[![Python](https://img.shields.io/pypi/pyversions/rustyzip.svg)](https://pypi.org/project/rustyzip/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A high-performance, secure file compression library with password protection, written in Rust with Python bindings.

**RustyZip** is a modern, actively maintained replacement for [pyminizip](https://github.com/smihica/pyminizip), addressing critical security vulnerabilities while providing better performance and more encryption options.

## Why RustyZip?

### Problems with pyminizip:
- Abandoned (last update years ago)
- Security vulnerabilities (CVE-2018-25032, CVE-2022-37434)
- Outdated zlib version
- No AES-256 support
- Slower performance

### RustyZip advantages:
- **Actively maintained** with regular updates
- **No known security vulnerabilities**
- **Modern zlib** (latest version)
- **AES-256 encryption** for sensitive data
- **2-5x faster** (Rust performance)
- **Drop-in pyminizip replacement**
- **Windows Explorer compatible** (ZipCrypto option)
- **Zero Python dependencies** (fully self-contained)

## Installation

```bash
pip install rustyzip
```

### Upgrading from pyminizip

```bash
pip uninstall pyminizip
pip install rustyzip
```

## Quick Start

### Modern API (Recommended)

```python
from rustyzip import compress_file, decompress_file, EncryptionMethod

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
from rustyzip.compat import pyminizip

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
from rustyzip import CompressionLevel

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
from rustyzip import compress_directory, EncryptionMethod

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
from rustyzip import compress_files

compress_files(
    ["report.pdf", "data.csv", "summary.txt"],
    "documents.zip",
    password="secret",
    prefixes=["reports", "data", "reports"]  # Archive paths
)
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
git clone https://github.com/johnnywalee/rustyzip.git
cd rustyzip

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

| Feature | pyminizip | RustyZip |
|---------|-----------|----------|
| Maintenance Status | Abandoned | Active |
| Security Vulnerabilities | Multiple CVEs | None known |
| zlib Version | Outdated | Latest |
| AES-256 Support | No | Yes |
| Performance | Baseline | 2-5x faster |
| Memory Safety | C/C++ risks | Rust guarantees |
| Windows Explorer Support | Yes (ZipCrypto) | Yes (ZipCrypto) |
| API Compatibility | N/A | Drop-in replacement |
| Python 3.12 Support | Limited | Full |
| Type Hints | No | Yes |

## License

Dual-licensed under MIT or Apache 2.0 at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/johnnywalee/rustyzip.git
cd rustyzip

# Install development dependencies
pip install maturin pytest

# Build and install in development mode
maturin develop

# Run tests
cargo test                    # Rust tests
pytest python/tests/ -v       # Python tests
```

### Release Process

Releases are automated via GitHub Actions:

1. Update version in `Cargo.toml` and `pyproject.toml`
2. Commit and push to main
3. Create a new GitHub Release with a tag (e.g., `v1.0.0`)
4. GitHub Actions will automatically:
   - Build wheels for all platforms (Linux, Windows, macOS)
   - Build for multiple architectures (x86_64, aarch64, i686, armv7)
   - Publish to PyPI

### Supported Platforms

| Platform | Architectures |
|----------|--------------|
| Linux (glibc/musl) | x86_64, aarch64, armv7, i686 |
| Windows | x86_64, i686 |
| macOS | x86_64, aarch64 (Apple Silicon) |

## Links

- [Documentation](https://rustyzip.readthedocs.io)
- [PyPI Package](https://pypi.org/project/rustyzip/)
- [GitHub Repository](https://github.com/johnnywalee/rustyzip)
- [Issue Tracker](https://github.com/johnnywalee/rustyzip/issues)
