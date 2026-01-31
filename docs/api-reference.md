# API Reference

Complete API reference for the RustyZip Python library. This documentation is auto-generated from docstrings.

## File Operations

::: rustyzipper.compress_file
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.compress_files
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.compress_directory
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.decompress_file
    options:
      show_root_heading: true
      heading_level: 3

---

## In-Memory Operations

::: rustyzipper.compress_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.decompress_bytes
    options:
      show_root_heading: true
      heading_level: 3

---

## Streaming Operations

::: rustyzipper.compress_stream
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.decompress_stream
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.open_zip_stream
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.open_zip_stream_from_file
    options:
      show_root_heading: true
      heading_level: 3

---

## Archive Inspection

::: rustyzipper.list_archive
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.list_archive_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_archive_info
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_archive_info_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_file_info
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_file_info_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_all_file_info
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.get_all_file_info_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.has_file
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.has_file_bytes
    options:
      show_root_heading: true
      heading_level: 3

---

## Archive Modification

::: rustyzipper.add_to_archive
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.add_bytes_to_archive
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.remove_from_archive
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.rename_in_archive
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.update_in_archive
    options:
      show_root_heading: true
      heading_level: 3

---

## Archive Modification (Bytes)

::: rustyzipper.add_to_archive_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.remove_from_archive_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.rename_in_archive_bytes
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.update_in_archive_bytes
    options:
      show_root_heading: true
      heading_level: 3

---

## Encryption Detection

::: rustyzipper.detect_encryption
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.detect_encryption_bytes
    options:
      show_root_heading: true
      heading_level: 3

---

## Classes

::: rustyzipper.SecurityPolicy
    options:
      show_root_heading: true
      heading_level: 3
      members:
        - __init__
        - unlimited
        - strict
        - max_size
        - max_ratio
        - allow_symlinks

::: rustyzipper.EncryptionMethod
    options:
      show_root_heading: true
      heading_level: 3

::: rustyzipper.CompressionLevel
    options:
      show_root_heading: true
      heading_level: 3

---

## Exceptions

All exceptions are in `rustyzipper`:

| Exception | Description |
|-----------|-------------|
| `RustyZipException` | Base exception for all RustyZip errors |
| `InvalidPasswordException` | Wrong password provided |
| `FileNotFoundException` | File not found |
| `UnsupportedEncryptionException` | Invalid encryption method |
| `PathTraversalException` | Path traversal attack detected |
| `ZipBombException` | ZIP bomb limits exceeded |
| `SecurityException` | General security violation |
| `CompressionException` | Compression operation failed |
| `DecompressionException` | Decompression operation failed |
