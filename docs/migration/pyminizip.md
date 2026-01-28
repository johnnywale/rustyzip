# Migration from pyminizip

RustyZip provides a drop-in compatibility layer for pyminizip, making migration simple while adding security features.

## Quick Migration

### Option 1: Drop-in Replacement

Simply change your import:

```python
# Before
import pyminizip

# After
from rustyzipper.compat import pyminizip
```

Your existing code will work unchanged, with added security protections.

### Option 2: Use the Modern API

For new code or gradual migration, use the native RustyZip API:

```python
# Before (pyminizip)
import pyminizip
pyminizip.compress("input.txt", None, "output.zip", "password", 5)

# After (RustyZip)
from rustyzipper import compress_file, EncryptionMethod
compress_file(
    "input.txt",
    "output.zip",
    password="password",
    encryption=EncryptionMethod.ZIPCRYPTO,  # For pyminizip compatibility
    suppress_warning=True
)
```

## API Mapping

### compress()

```python
# pyminizip
pyminizip.compress(
    src_path,        # Source file
    prefix,          # Archive prefix (can be None)
    dst_path,        # Destination ZIP
    password,        # Password
    compress_level   # 1-9
)

# RustyZip compat (identical)
from rustyzipper.compat import pyminizip
pyminizip.compress(src_path, prefix, dst_path, password, compress_level)

# RustyZip native
from rustyzipper import compress_file, CompressionLevel, EncryptionMethod
compress_file(
    src_path,
    dst_path,
    password=password,
    compression_level=compress_level,
    encryption=EncryptionMethod.ZIPCRYPTO,  # For pyminizip compatibility
    suppress_warning=True
)
```

### compress_multiple()

```python
# pyminizip
pyminizip.compress_multiple(
    src_paths,       # List of source files
    prefixes,        # List of prefixes
    dst_path,        # Destination ZIP
    password,        # Password
    compress_level   # 1-9
)

# RustyZip compat (identical)
from rustyzipper.compat import pyminizip
pyminizip.compress_multiple(src_paths, prefixes, dst_path, password, compress_level)

# RustyZip native
from rustyzipper import compress_files, EncryptionMethod
compress_files(
    src_paths,
    dst_path,
    password=password,
    prefixes=prefixes,
    encryption=EncryptionMethod.ZIPCRYPTO,
    suppress_warning=True
)
```

### uncompress()

```python
# pyminizip
pyminizip.uncompress(
    src_path,        # Source ZIP
    password,        # Password
    dst_path,        # Destination directory
    withoutpath      # Extract without directory structure
)

# RustyZip compat (with security extensions!)
from rustyzipper.compat import pyminizip
pyminizip.uncompress(
    src_path,
    password,
    dst_path,
    withoutpath,
    max_size=2 * 1024**3,    # NEW: 2GB limit (default)
    max_ratio=500,            # NEW: 500:1 ratio limit (default)
    allow_symlinks=False      # NEW: Block symlinks (default)
)

# RustyZip native
from rustyzipper import decompress_file, SecurityPolicy
policy = SecurityPolicy(max_size="2GB", max_ratio=500)
decompress_file(src_path, dst_path, password=password, policy=policy)
```

## Security Improvements

The compat layer adds security features not available in pyminizip:

### ZIP Bomb Protection

```python
from rustyzipper.compat import pyminizip

# Default: Protected with 2GB max, 500:1 ratio
pyminizip.uncompress("archive.zip", "password", "output/", False)

# Custom limits
pyminizip.uncompress(
    "archive.zip", "password", "output/", False,
    max_size=1024 * 1024 * 100,  # 100MB
    max_ratio=100                 # 100:1
)

# Disable limits (not recommended)
pyminizip.uncompress(
    "trusted.zip", "password", "output/", False,
    max_size=0,     # 0 = unlimited
    max_ratio=0     # 0 = unlimited
)
```

### Symlink Protection

```python
from rustyzipper.compat import pyminizip

# Default: Symlinks blocked
pyminizip.uncompress("archive.zip", "password", "output/", False)

# Allow symlinks (only for trusted archives)
pyminizip.uncompress(
    "trusted.zip", "password", "output/", False,
    allow_symlinks=True
)
```

## Encryption Compatibility

pyminizip uses ZipCrypto encryption. RustyZip defaults to AES-256 for better security.

### Reading pyminizip Archives

RustyZip can read ZipCrypto archives created by pyminizip:

```python
from rustyzipper import decompress_file

# Works with pyminizip-created archives
decompress_file("pyminizip_archive.zip", "output/", password="password")
```

### Creating pyminizip-Compatible Archives

To create archives readable by tools expecting ZipCrypto:

```python
from rustyzipper import compress_file, EncryptionMethod

compress_file(
    "file.txt",
    "compatible.zip",
    password="password",
    encryption=EncryptionMethod.ZIPCRYPTO,
    suppress_warning=True  # Acknowledge weak encryption
)
```

Or use the compat layer (automatically uses ZipCrypto):

```python
from rustyzipper.compat import pyminizip

pyminizip.compress("file.txt", None, "compatible.zip", "password", 5)
```

## Feature Comparison

| Feature | pyminizip | RustyZip |
|---------|-----------|----------|
| ZipCrypto encryption | Yes | Yes |
| AES-256 encryption | No | Yes (default) |
| ZIP bomb protection | No | Yes (default) |
| Path traversal protection | No | Yes (always) |
| Symlink protection | No | Yes (default) |
| In-memory operations | No | Yes |
| Streaming | No | Yes |
| Memory-safe | No (C) | Yes (Rust) |
| Active maintenance | Limited | Yes |

## Gradual Migration Example

Migrate incrementally while keeping code working:

```python
# Step 1: Start with compat layer
from rustyzipper.compat import pyminizip

# Existing code works unchanged
pyminizip.compress("file.txt", None, "archive.zip", "pass", 5)
pyminizip.uncompress("archive.zip", "pass", "out/", False)

# Step 2: Add security parameters to uncompress
pyminizip.uncompress(
    "archive.zip", "pass", "out/", False,
    max_size="1GB",
    max_ratio=500
)

# Step 3: Migrate to native API for new code
from rustyzipper import compress_file, decompress_file, SecurityPolicy

compress_file("file.txt", "archive.zip", password="pass")
decompress_file("archive.zip", "out/", password="pass")

# Step 4: Use AES-256 for new archives (recommended)
compress_file("sensitive.txt", "secure.zip", password="strong_pass")
# Default encryption is AES-256
```

## Verifying Migration

Test that your migration works correctly:

```python
import os
import tempfile
from rustyzipper.compat import pyminizip
from rustyzipper import decompress_file

# Create test file
with tempfile.TemporaryDirectory() as tmpdir:
    test_file = os.path.join(tmpdir, "test.txt")
    zip_file = os.path.join(tmpdir, "test.zip")
    out_dir = os.path.join(tmpdir, "output")

    # Write test data
    with open(test_file, "w") as f:
        f.write("Hello, World!")

    # Compress with compat layer
    pyminizip.compress(test_file, None, zip_file, "password", 5)

    # Decompress with native API
    os.makedirs(out_dir)
    decompress_file(zip_file, out_dir, password="password")

    # Verify
    with open(os.path.join(out_dir, "test.txt")) as f:
        assert f.read() == "Hello, World!"

    print("Migration test passed!")
```
