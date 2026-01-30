# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in RustyZip, please report it responsibly.

### How to Report

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use GitHub's private vulnerability reporting feature
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Updates**: We will provide updates on our progress within 7 days
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days
- **Credit**: We will credit reporters in our release notes (unless you prefer to remain anonymous)

## Security Features

RustyZip includes several built-in security protections:

### ZIP Bomb Protection
- **Size limit**: Default 2 GB maximum decompressed size
- **Ratio limit**: Default 500:1 maximum compression ratio
- Both limits are configurable via the `SecurityPolicy` API

### Path Traversal Protection
- All paths are validated to prevent directory traversal attacks
- Paths containing `..` or absolute paths outside the target directory are rejected
- This protection is **always enabled** and cannot be disabled

### Symlink Protection
- Symlink extraction is blocked by default
- Can be explicitly enabled via `allow_symlinks` parameter when needed

### Password Security
- Passwords are wrapped in a `Password` type that implements `Zeroize`
- Passwords are securely erased from memory when no longer needed

### Encryption Options
- **AES-256**: Strong encryption (recommended, requires 7-Zip/WinRAR to open)
- **ZipCrypto**: Legacy encryption for compatibility (weaker security)
- **None**: No encryption

## Best Practices

When using RustyZip in your applications:

1. **Use AES-256 encryption** for sensitive data
2. **Use strong passwords** when encrypting archives
3. **Keep default security limits** unless you have a specific need to change them
4. **Validate input paths** before compression
5. **Keep RustyZip updated** to get the latest security patches

## Security Audits

This project has not undergone a formal security audit. If you're using RustyZip in a security-critical application, consider conducting your own security review.
