# Streaming Operations

RustyZip provides streaming APIs for memory-efficient processing of large files and archives.

## When to Use Streaming

Use streaming when:

- Processing large files that shouldn't be loaded entirely into memory
- Working with archives containing many files
- Building pipelines that process files one at a time
- Memory is constrained

## Streaming Compression

Use `compress_stream()` to compress from file-like objects:

```python
from rustyzipper import compress_stream
import io

# Compress to a BytesIO buffer
output = io.BytesIO()

with open("large_file.bin", "rb") as f1, open("another.dat", "rb") as f2:
    compress_stream(
        files=[
            ("large_file.bin", f1),
            ("another.dat", f2),
        ],
        output=output,
        password="secret"
    )

zip_data = output.getvalue()

# Or compress directly to a file
with open("output.zip", "wb") as out:
    with open("data.txt", "rb") as f:
        compress_stream([("data.txt", f)], out)
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `files` | List[Tuple[str, BinaryIO]] | List of (archive_name, file_object) tuples |
| `output` | BinaryIO | Output file-like object with write() and seek() |
| `password` | str | Optional password |
| `encryption` | EncryptionMethod | Encryption method (default: AES256) |
| `compression_level` | CompressionLevel | Compression level (default: 6) |

## Streaming Decompression

Use `decompress_stream()` to decompress from a file-like object:

```python
from rustyzipper import decompress_stream, SecurityPolicy

# Stream from a file
with open("archive.zip", "rb") as f:
    files = decompress_stream(f, password="secret")

for filename, content in files:
    print(f"{filename}: {len(content)} bytes")

# With security policy
policy = SecurityPolicy(max_size="5GB")
with open("large.zip", "rb") as f:
    files = decompress_stream(f, password="secret", policy=policy)
```

!!! note "Seekable Streams Required"
    The input stream must support seeking because ZIP files store their
    directory at the end. For non-seekable streams, read into a BytesIO first.

## Per-File Streaming with ZipStreamReader

For maximum memory efficiency, use `open_zip_stream()` to process files one at a time:

```python
from rustyzipper import open_zip_stream, compress_bytes

# Create a test archive
zip_data = compress_bytes([
    ("file1.txt", b"Content 1"),
    ("file2.txt", b"Content 2"),
    ("file3.txt", b"Content 3"),
])

# Process files one at a time
reader = open_zip_stream(zip_data, password=None)

print(f"Archive contains {len(reader)} files")
print(f"Files: {reader.namelist()}")

# Iterate - only one file's content in memory at a time
for filename, content in reader:
    process_file(filename, content)
    # Previous file's content can be garbage collected

# Random access to specific files
specific_content = reader.read("file2.txt")
```

### ZipStreamReader Properties and Methods

| Property/Method | Description |
|----------------|-------------|
| `len(reader)` | Number of files in the archive |
| `reader.namelist()` | List of all filenames |
| `reader.read(name)` | Extract a specific file by name |
| `reader.file_count` | Number of files (excluding directories) |
| `reader.total_entries` | Total entries including directories |
| `for name, content in reader` | Iterate over all files |

## True Streaming with ZipFileStreamReader

For the most memory-efficient approach, use `open_zip_stream_from_file()`:

```python
from rustyzipper import open_zip_stream_from_file

# True streaming - ZIP data NOT loaded into memory
with open("huge_archive.zip", "rb") as f:
    reader = open_zip_stream_from_file(f)

    print(f"Archive contains {len(reader)} files")

    for filename, content in reader:
        # Only this file's decompressed content is in memory
        process_file(filename, content)

    # Random access still works
    specific = reader.read("important.txt")
# File handle closes here
```

!!! warning "Keep File Handle Open"
    The file handle MUST remain open during iteration. The reader
    reads directly from the file, so closing it will cause errors.

### Memory Comparison

| Method | ZIP Data in Memory | Files in Memory |
|--------|-------------------|-----------------|
| `decompress_bytes()` | Yes | All at once |
| `decompress_stream()` | No (reads from stream) | All at once |
| `open_zip_stream()` | Yes | One at a time |
| `open_zip_stream_from_file()` | No | One at a time |

## Processing Large Archives

Example: Process a large archive with many files:

```python
from rustyzipper import open_zip_stream_from_file
import hashlib

def process_large_archive(zip_path: str) -> dict:
    """Process files from a large archive without loading it all into memory."""
    results = {}

    with open(zip_path, "rb") as f:
        reader = open_zip_stream_from_file(f)

        for filename, content in reader:
            # Skip directories
            if filename.endswith("/"):
                continue

            # Process each file
            results[filename] = {
                "size": len(content),
                "hash": hashlib.sha256(content).hexdigest(),
            }

            # content is eligible for garbage collection now

    return results
```

## Network Streaming

Stream from a network response:

```python
import requests
import io
from rustyzipper import open_zip_stream

def process_remote_zip(url: str, password: str = None):
    """Download and process a ZIP file."""
    response = requests.get(url)
    response.raise_for_status()

    # For open_zip_stream, we need bytes
    zip_data = response.content

    for filename, content in open_zip_stream(zip_data, password):
        yield filename, content
```

For true streaming without loading the full response:

```python
import requests
import io
from rustyzipper import decompress_stream

def stream_remote_zip(url: str, password: str = None):
    """Stream a remote ZIP (requires seekable response)."""
    response = requests.get(url)
    response.raise_for_status()

    # Wrap in BytesIO for seeking capability
    buffer = io.BytesIO(response.content)

    return decompress_stream(buffer, password)
```
