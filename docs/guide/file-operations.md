# File Operations

This guide covers all file-based compression and decompression operations.

## Single File Compression

Use `compress_file()` to compress a single file:

```python
from rustyzipper import compress_file, EncryptionMethod, CompressionLevel

compress_file(
    input_path="document.pdf",
    output_path="document.zip",
    password="optional_password",
    encryption=EncryptionMethod.AES256,  # Default
    compression_level=CompressionLevel.DEFAULT,  # Level 6
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | str | required | Path to the file to compress |
| `output_path` | str | required | Path for the output ZIP file |
| `password` | str | None | Password for encryption |
| `encryption` | EncryptionMethod | AES256 | Encryption method |
| `compression_level` | CompressionLevel | DEFAULT | Compression level (0-9) |
| `suppress_warning` | bool | False | Suppress weak encryption warnings |

## Multiple File Compression

Use `compress_files()` to compress multiple files into one archive:

```python
from rustyzipper import compress_files

# Basic usage
compress_files(
    input_paths=["file1.txt", "file2.txt", "file3.txt"],
    output_path="archive.zip",
    password="secret"
)

# With custom archive paths (prefixes)
compress_files(
    input_paths=["src/main.py", "src/utils.py", "README.md"],
    output_path="release.zip",
    prefixes=["app", "app", None],  # Results in: app/main.py, app/utils.py, README.md
    password="secret"
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_paths` | List[str] | required | List of file paths to compress |
| `output_path` | str | required | Path for the output ZIP file |
| `password` | str | None | Password for encryption |
| `prefixes` | List[str] | None | Archive path prefixes for each file |
| `encryption` | EncryptionMethod | AES256 | Encryption method |
| `compression_level` | CompressionLevel | DEFAULT | Compression level |

## Directory Compression

Use `compress_directory()` to compress an entire directory:

```python
from rustyzipper import compress_directory

# Basic usage
compress_directory(
    input_dir="my_project/",
    output_path="project.zip",
    password="secret"
)

# With include/exclude patterns
compress_directory(
    input_dir="my_project/",
    output_path="source.zip",
    password="secret",
    include_patterns=["*.py", "*.md"],  # Only Python and Markdown files
    exclude_patterns=["__pycache__", "*.pyc", ".git", "node_modules"]
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_dir` | str | required | Directory to compress |
| `output_path` | str | required | Path for the output ZIP file |
| `password` | str | None | Password for encryption |
| `include_patterns` | List[str] | None | Glob patterns to include |
| `exclude_patterns` | List[str] | None | Glob patterns to exclude |
| `encryption` | EncryptionMethod | AES256 | Encryption method |
| `compression_level` | CompressionLevel | DEFAULT | Compression level |

## Decompression

Use `decompress_file()` to extract a ZIP archive:

```python
from rustyzipper import decompress_file, SecurityPolicy

# Basic decompression with default security
decompress_file(
    input_path="archive.zip",
    output_path="extracted/",
    password="secret"
)

# With custom security policy
policy = SecurityPolicy(max_size="5GB", max_ratio=1000)
decompress_file(
    input_path="large.zip",
    output_path="extracted/",
    password="secret",
    policy=policy
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | str | required | Path to the ZIP file |
| `output_path` | str | required | Directory for extracted files |
| `password` | str | None | Password for encrypted archives |
| `policy` | SecurityPolicy | None | Security policy (uses secure defaults if None) |

## Detecting Encryption

Check what encryption method an archive uses:

```python
from rustyzipper import detect_encryption, EncryptionMethod

method = detect_encryption("archive.zip")

if method == EncryptionMethod.AES256:
    print("Strong AES-256 encryption")
elif method == EncryptionMethod.ZIPCRYPTO:
    print("Weak ZipCrypto encryption")
else:
    print("No encryption")
```

## Error Handling

```python
from rustyzipper import compress_file, decompress_file
from rustyzipper.exceptions import (
    RustyZipError,
    InvalidPasswordError,
    CompressionError,
    DecompressionError
)

try:
    decompress_file("archive.zip", "output/", password="wrong")
except InvalidPasswordError:
    print("Wrong password!")
except DecompressionError as e:
    print(f"Decompression failed: {e}")
except RustyZipError as e:
    print(f"General error: {e}")
```
