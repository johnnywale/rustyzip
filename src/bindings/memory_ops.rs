//! In-memory compression/decompression Python functions.

use crate::compression::{CompressionLevel, EncryptionMethod};
use log::warn;
use pyo3::prelude::*;

/// Compress bytes directly to a ZIP archive in memory.
///
/// # Arguments
/// * `files` - List of (archive_name, data) tuples to compress
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method: "aes256", "zipcrypto", or "none"
/// * `compression_level` - Compression level (0-9, default 6)
/// * `suppress_warning` - Suppress security warnings for weak encryption
///
/// # Returns
/// * `bytes` - The compressed ZIP archive
///
/// # Raises
/// * `IOError` - If compression fails
/// * `ValueError` - If parameters are invalid
///
/// # Example
/// ```python
/// import rustyzipper
/// files = [("hello.txt", b"Hello World"), ("subdir/data.bin", b"\x00\x01\x02")]
/// zip_data = rustyzipper.compress_bytes(files, password="secret")
/// ```
#[pyfunction]
#[pyo3(signature = (files, password=None, encryption="aes256", compression_level=6, suppress_warning=false))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn compress_bytes(
    py: Python<'_>,
    files: Vec<(String, Vec<u8>)>,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    suppress_warning: bool,
) -> PyResult<Vec<u8>> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    // Warn about weak encryption
    if enc_method == EncryptionMethod::ZipCrypto && password.is_some() && !suppress_warning {
        warn!(
            "ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    // Convert to owned data for use in allow_threads closure
    let pwd = password.map(|s| s.to_string());
    let level = CompressionLevel::new(compression_level);

    // Release GIL during CPU-intensive compression
    let result = py.allow_threads(|| {
        let file_refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect();

        crate::compression::compress_bytes(&file_refs, pwd.as_deref(), enc_method, level)
    })?;

    Ok(result)
}

/// Decompress a ZIP archive from bytes in memory.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
/// * `password` - Optional password for encrypted archives
/// * `max_size` - Maximum total decompressed size in bytes. Default is 2GB. Set to 0 to disable.
/// * `max_ratio` - Maximum compression ratio allowed. Default is 500. Set to 0 to disable.
///
/// # Returns
/// * `list[tuple[str, bytes]]` - List of (filename, content) tuples
///
/// # Raises
/// * `IOError` - If decompression fails
/// * `ValueError` - If password is incorrect
/// * `RustyZipError` - If ZIP bomb limits are exceeded
///
/// # Example
/// ```python
/// import rustyzipper
/// files = rustyzipper.decompress_bytes(zip_data, password="secret")
/// for filename, content in files:
///     print(f"{filename}: {len(content)} bytes")
/// ```
#[pyfunction]
#[pyo3(signature = (data, password=None, max_size=None, max_ratio=None))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn decompress_bytes(
    py: Python<'_>,
    data: Vec<u8>,
    password: Option<&str>,
    max_size: Option<u64>,
    max_ratio: Option<u64>,
) -> PyResult<Vec<(String, Vec<u8>)>> {
    use crate::compression::{DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE};

    // Convert to owned data for use in allow_threads closure
    let pwd = password.map(|s| s.to_string());

    // Use provided limits or defaults (0 means u64::MAX for unlimited)
    let effective_max_size = match max_size {
        Some(0) => u64::MAX,
        Some(size) => size,
        None => DEFAULT_MAX_DECOMPRESSED_SIZE,
    };
    let effective_max_ratio = match max_ratio {
        Some(0) => u64::MAX,
        Some(ratio) => ratio,
        None => DEFAULT_MAX_COMPRESSION_RATIO,
    };

    // Release GIL during CPU-intensive decompression
    let result = py.allow_threads(|| {
        crate::compression::decompress_bytes_with_limits(
            &data,
            pwd.as_deref(),
            effective_max_size,
            effective_max_ratio,
        )
    })?;
    Ok(result)
}
