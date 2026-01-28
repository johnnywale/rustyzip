# Security

RustyZip follows the principle: **"Secure by Default, Explicitly Overridable"**

## Built-in Protections

| Protection | Default | Description |
|------------|---------|-------------|
| ZIP Bomb (Size) | 2 GB max | Maximum total decompressed size |
| ZIP Bomb (Ratio) | 500:1 max | Maximum compression ratio |
| Path Traversal | Always blocked | Cannot be disabled |
| Symlinks | Blocked | Symlink extraction disabled by default |
| Password Zeroization | Automatic | Passwords wiped from memory after use |

## Security Policy

The `SecurityPolicy` class provides a clean way to configure security limits:

```python
from rustyzipper import SecurityPolicy, decompress_file

# Use secure defaults
decompress_file("archive.zip", "output/")

# Custom policy
policy = SecurityPolicy(
    max_size="10GB",      # Maximum decompressed size
    max_ratio=1000,       # Maximum compression ratio
    allow_symlinks=False  # Block symlinks (default)
)
decompress_file("large.zip", "output/", policy=policy)
```

### Creating Policies

```python
from rustyzipper import SecurityPolicy

# Default secure policy
policy = SecurityPolicy()  # 2GB max, 500:1 ratio

# Custom size limits
policy = SecurityPolicy(max_size="5GB", max_ratio=1000)

# Using bytes for size
policy = SecurityPolicy(max_size=10 * 1024 * 1024 * 1024)  # 10GB

# Strict policy for untrusted content
policy = SecurityPolicy.strict(max_size="100MB", max_ratio=100)

# Unlimited policy (use with caution!)
policy = SecurityPolicy.unlimited()
```

### Size Format

The `max_size` parameter accepts:

- Integers (bytes): `1073741824`
- Human-readable strings: `"1GB"`, `"500MB"`, `"100 KB"`

Supported units: B, KB, MB, GB, TB (case-insensitive)

## ZIP Bomb Protection

ZIP bombs are malicious archives designed to crash or overwhelm systems:

- **Compression bombs**: Small archives that expand to huge sizes
- **Recursive bombs**: Archives containing archives containing archives...

RustyZip protects against these by checking:

1. **Total decompressed size** against `max_size`
2. **Compression ratio** against `max_ratio`

```python
from rustyzipper import decompress_bytes, SecurityPolicy
from rustyzipper.exceptions import RustyZipError

zip_data = get_untrusted_archive()

try:
    # Strict limits for untrusted content
    policy = SecurityPolicy.strict(max_size="50MB", max_ratio=100)
    files = decompress_bytes(zip_data, policy=policy)
except RustyZipError as e:
    if "size limit" in str(e).lower():
        print("Archive too large - possible ZIP bomb")
    elif "ratio" in str(e).lower():
        print("Suspicious compression ratio - possible ZIP bomb")
    else:
        print(f"Decompression failed: {e}")
```

## Path Traversal Protection

Path traversal attacks use filenames like `../../../etc/passwd` to write files outside the intended directory. RustyZip **always blocks these** - this cannot be disabled.

```python
from rustyzipper import decompress_file

# Safe - path traversal attempts are blocked
decompress_file("malicious.zip", "sandbox/")
# Files with ".." in their paths are rejected
```

## Symlink Protection

Symlinks in archives can be used to:

- Point to sensitive files outside the extraction directory
- Create circular references
- Bypass file permissions

By default, RustyZip blocks symlink extraction:

```python
from rustyzipper import SecurityPolicy, decompress_file

# Default: symlinks blocked
decompress_file("archive.zip", "output/")

# Explicitly allow symlinks (only if you trust the archive)
policy = SecurityPolicy(allow_symlinks=True)
decompress_file("trusted.zip", "output/", policy=policy)
```

## Password Security

RustyZip uses the `zeroize` crate to securely erase passwords from memory after use. This happens automatically - you don't need to do anything special.

```python
from rustyzipper import compress_file

# Password is automatically wiped from memory after compression
compress_file("secret.txt", "secret.zip", password="sensitive_password")
# Password memory has been zeroed
```

## Encryption Methods

### AES-256 (Recommended)

- Strong, modern encryption
- Resistant to known attacks
- Requires 7-Zip, WinRAR, or WinZip to open
- **Default for all operations**

```python
from rustyzipper import compress_file, EncryptionMethod

compress_file("doc.pdf", "secure.zip",
              password="strong_password",
              encryption=EncryptionMethod.AES256)
```

### ZipCrypto (Legacy)

- Weak encryption with known vulnerabilities
- Compatible with Windows Explorer
- Only use for non-sensitive files
- **Requires explicit opt-in and warning suppression**

```python
from rustyzipper import compress_file, EncryptionMethod

compress_file("public.pdf", "compatible.zip",
              password="password",
              encryption=EncryptionMethod.ZIPCRYPTO,
              suppress_warning=True)  # Acknowledge weak encryption
```

!!! danger "ZipCrypto Vulnerabilities"
    ZipCrypto has known cryptographic weaknesses:

    - Susceptible to known-plaintext attacks
    - Short passwords can be brute-forced quickly
    - File sizes and names are not encrypted

    Only use for compatibility with tools that don't support AES.

### Detecting Archive Encryption

```python
from rustyzipper import detect_encryption, EncryptionMethod

method = detect_encryption("archive.zip")

if method == EncryptionMethod.NONE:
    print("Archive is not encrypted")
elif method == EncryptionMethod.AES256:
    print("Strong AES-256 encryption")
elif method == EncryptionMethod.ZIPCRYPTO:
    print("Warning: Weak ZipCrypto encryption")
```

## Best Practices

### For User Uploads

```python
from rustyzipper import decompress_bytes, SecurityPolicy

def handle_upload(zip_data: bytes) -> list:
    """Process user-uploaded ZIP with strict security."""
    policy = SecurityPolicy.strict(
        max_size="50MB",   # Limit total size
        max_ratio=100      # Strict ratio limit
    )

    try:
        return decompress_bytes(zip_data, policy=policy)
    except Exception as e:
        log_security_event(f"Suspicious upload: {e}")
        raise
```

### For Internal Archives

```python
from rustyzipper import decompress_file, SecurityPolicy

def restore_backup(backup_path: str, restore_dir: str):
    """Restore from trusted internal backup."""
    # More permissive but still protected
    policy = SecurityPolicy(
        max_size="100GB",
        max_ratio=1000,
        allow_symlinks=False  # Still block symlinks
    )

    decompress_file(backup_path, restore_dir, policy=policy)
```

### Never Do This in Production

```python
# DON'T: Disable all limits for untrusted data
policy = SecurityPolicy.unlimited()
decompress_bytes(user_upload, policy=policy)  # Dangerous!

# DON'T: Allow symlinks for untrusted archives
policy = SecurityPolicy(allow_symlinks=True)
decompress_file(user_file, "output/", policy=policy)  # Dangerous!
```
