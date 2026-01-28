# RustyZip

A high-performance, secure file compression library with password protection. Built with Rust, with Python bindings via PyO3.

## Features

- **High Performance**: Built with Rust for maximum speed
- **Strong Encryption**: AES-256 encryption by default
- **ZIP Bomb Protection**: Built-in security against malicious archives
- **Streaming Support**: Process large files without loading them entirely into memory
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

## Getting Started

- [Installation Guide](installation.md) - How to install RustyZip
- [Quick Start](quickstart.md) - Get up and running in minutes
- [Migration from pyminizip](migration/pyminizip.md) - Upgrade your existing code
