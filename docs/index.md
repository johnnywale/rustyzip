# RustyZip

A high-performance, secure file compression library with password protection. Built with Rust, with Python bindings via PyO3.

## Features

- **High Performance**: Built with Rust for maximum speed
- **Strong Encryption**: AES-256 encryption by default
- **ZIP Bomb Protection**: Built-in security against malicious archives
- **Streaming Support**: Process large files without loading them entirely into memory
- **Archive Inspection**: List files, get metadata, check encryption without extracting
- **Archive Modification**: Add, remove, rename, and update files in existing archives
- **pyminizip Compatible**: Drop-in replacement for pyminizip with enhanced security

## Quick Example

```python
from rustyzipper import compress_file, decompress_file

# Compress with AES-256 encryption (recommended)
compress_file("document.pdf", "secure.zip", password="MyP@ssw0rd")

# Decompress with automatic security protection
decompress_file("secure.zip", "extracted/", password="MyP@ssw0rd")
```

## Installation

```bash
pip install rustyzipper
```

## Why RustyZip?

| Feature | RustyZip | pyminizip |
|---------|----------|-----------|
| AES-256 Encryption | Yes | No |
| ZIP Bomb Protection | Yes | No |
| Streaming Support | Yes | No |
| Archive Inspection | Yes | No |
| Archive Modification | Yes | No |
| Memory Safety | Rust | C |
| Active Maintenance | Yes | Limited |

## Security First

RustyZip follows the principle: **"Secure by Default, Explicitly Overridable"**

- All decompression operations are protected against ZIP bombs
- Path traversal attacks are always blocked
- Passwords are automatically wiped from memory after use
- Weak encryption methods require explicit opt-in

```python
from rustyzipper import decompress_file, SecurityPolicy

# Default: 2GB max, 500:1 compression ratio limit
decompress_file("archive.zip", "output/")

# Custom policy for large trusted archives
policy = SecurityPolicy(max_size="10GB", max_ratio=1000)
decompress_file("large.zip", "output/", policy=policy)
```

## Archive Inspection

Inspect archive contents without extracting - get file lists, metadata, compression ratios, and encryption status.

```python
from rustyzipper import list_archive, get_archive_info, get_file_info

# List all files in an archive
files = list_archive("archive.zip")
for name in files:
    print(name)

# Get archive-level statistics
info = get_archive_info("archive.zip")
print(f"Files: {info.file_count}")
print(f"Total size: {info.total_size} bytes")
print(f"Compression ratio: {info.compression_ratio:.1f}:1")
print(f"Encrypted: {info.has_encrypted_files}")

# Get details for a specific file
file_info = get_file_info("archive.zip", "document.txt")
print(f"Size: {file_info.size} bytes")
print(f"CRC32: {file_info.crc32:08x}")
```

## Archive Modification

Modify existing archives - add new files, remove unwanted entries, rename files, or update content.

```python
from rustyzipper import (
    add_to_archive,
    add_bytes_to_archive,
    remove_from_archive,
    rename_in_archive,
    update_in_archive,
)

# Add files to an existing archive
add_to_archive(
    "archive.zip",
    ["new_file.txt", "another.txt"],
    ["docs/new_file.txt", "docs/another.txt"],
    password="secret"
)

# Add in-memory data directly
config = b'{"version": 2, "updated": true}'
add_bytes_to_archive("archive.zip", config, "config.json")

# Remove files from archive
removed = remove_from_archive("archive.zip", ["old_file.txt", "temp.log"])
print(f"Removed {removed} files")

# Rename a file within the archive
rename_in_archive("archive.zip", "old_name.txt", "new_name.txt")

# Update a file's content
new_content = b"Updated content here"
update_in_archive("archive.zip", "readme.txt", new_content)
```

All modification functions also have `_bytes` variants for working with in-memory archives.

## Getting Started

- [Installation Guide](installation.md) - How to install RustyZip
- [Quick Start](quickstart.md) - Get up and running in minutes
- [API Reference](api-reference.md) - Complete API documentation
- [Migration from pyminizip](migration/pyminizip.md) - Upgrade your existing code
