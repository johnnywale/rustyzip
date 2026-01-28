# Quick Start

This guide will get you compressing and decompressing files in minutes.

## Basic File Compression

```python
from rustyzipper import compress_file, decompress_file

# Compress a single file with AES-256 encryption
compress_file("report.pdf", "report.zip", password="secret123")

# Decompress
decompress_file("report.zip", "output/", password="secret123")
```

## Multiple Files

```python
from rustyzipper import compress_files

# Compress multiple files
compress_files(
    ["file1.txt", "file2.txt", "image.png"],
    "archive.zip",
    password="secret123"
)
```

## Directory Compression

```python
from rustyzipper import compress_directory

# Compress an entire directory
compress_directory(
    "my_project/",
    "backup.zip",
    password="secret123",
    exclude_patterns=["__pycache__", "*.pyc", ".git"]
)
```

## In-Memory Operations

Perfect for web applications or when you don't want to touch the filesystem:

```python
from rustyzipper import compress_bytes, decompress_bytes

# Create files in memory
files = [
    ("hello.txt", b"Hello, World!"),
    ("data.json", b'{"key": "value"}'),
]

# Compress to bytes
zip_data = compress_bytes(files, password="secret")

# Decompress from bytes
extracted = decompress_bytes(zip_data, password="secret")
for filename, content in extracted:
    print(f"{filename}: {content}")
```

## Encryption Options

RustyZip supports multiple encryption methods:

```python
from rustyzipper import compress_file, EncryptionMethod

# AES-256 (default, recommended)
compress_file("doc.pdf", "secure.zip", password="secret")

# ZipCrypto (legacy, for Windows Explorer compatibility)
compress_file(
    "doc.pdf",
    "compatible.zip",
    password="secret",
    encryption=EncryptionMethod.ZIPCRYPTO,
    suppress_warning=True  # Acknowledge weak encryption
)

# No encryption
compress_file("doc.pdf", "plain.zip", encryption=EncryptionMethod.NONE)
```

!!! warning "ZipCrypto Security"
    ZipCrypto is a weak encryption method. Only use it when you need
    compatibility with Windows Explorer's built-in ZIP support.

## Compression Levels

Trade off between speed and file size:

```python
from rustyzipper import compress_file, CompressionLevel

# Store only (fastest, no compression)
compress_file("video.mp4", "video.zip", compression_level=CompressionLevel.STORE)

# Fast compression
compress_file("data.csv", "data.zip", compression_level=CompressionLevel.FAST)

# Default (balanced)
compress_file("doc.pdf", "doc.zip", compression_level=CompressionLevel.DEFAULT)

# Maximum compression (slowest, smallest)
compress_file("logs.txt", "logs.zip", compression_level=CompressionLevel.BEST)
```

## Security Policies

Control decompression limits to protect against ZIP bombs:

```python
from rustyzipper import decompress_file, SecurityPolicy

# Default security (2GB max, 500:1 ratio)
decompress_file("archive.zip", "output/")

# Custom limits for large archives
policy = SecurityPolicy(max_size="10GB", max_ratio=1000)
decompress_file("large.zip", "output/", policy=policy)

# Strict policy for untrusted files
strict = SecurityPolicy.strict(max_size="100MB", max_ratio=100)
decompress_file("user_upload.zip", "sandbox/", policy=strict)

# Unlimited (only for fully trusted archives!)
decompress_file("backup.zip", "restore/", policy=SecurityPolicy.unlimited())
```

## Next Steps

- [File Operations Guide](guide/file-operations.md) - Detailed file operations
- [Streaming Guide](guide/streaming.md) - Process large files efficiently
- [Security Guide](guide/security.md) - Understanding security features
- [API Reference](api-reference.md) - Complete API documentation
