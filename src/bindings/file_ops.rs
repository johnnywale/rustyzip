//! File-based compression/decompression Python functions.

use crate::compression::{CompressionLevel, EncryptionMethod};
use log::warn;
use pyo3::prelude::*;
use std::path::Path;

/// Detect the encryption method used in a ZIP file.
///
/// This function examines the ZIP archive and returns the encryption method
/// used. Returns "aes256", "zipcrypto", or "none".
///
/// # Arguments
/// * `input_path` - Path to the ZIP file
///
/// # Returns
/// * A string representing the encryption method: "aes256", "zipcrypto", or "none"
///
/// # Raises
/// * `IOError` - If file operations fail
#[pyfunction]
#[pyo3(signature = (input_path,))]
pub fn detect_encryption(input_path: &str) -> PyResult<String> {
    let path = Path::new(input_path);
    let method = crate::compression::detect_encryption(path)?;

    Ok(match method {
        EncryptionMethod::Aes256 => "aes256".to_string(),
        EncryptionMethod::ZipCrypto => "zipcrypto".to_string(),
        EncryptionMethod::None => "none".to_string(),
    })
}

/// Detect the encryption method from ZIP data in memory.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Returns
/// * A string representing the encryption method: "aes256", "zipcrypto", or "none"
///
/// # Raises
/// * `IOError` - If decompression fails
#[pyfunction]
#[pyo3(signature = (data,))]
pub fn detect_encryption_bytes(data: &[u8]) -> PyResult<String> {
    let method = crate::compression::detect_encryption_bytes(data)?;

    Ok(match method {
        EncryptionMethod::Aes256 => "aes256".to_string(),
        EncryptionMethod::ZipCrypto => "zipcrypto".to_string(),
        EncryptionMethod::None => "none".to_string(),
    })
}

/// Compress a single file to a ZIP archive.
///
/// # Arguments
/// * `input_path` - Path to the file to compress
/// * `output_path` - Path for the output ZIP file
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method: "aes256", "zipcrypto", or "none"
/// * `compression_level` - Compression level (0-9, default 6)
/// * `suppress_warning` - Suppress security warnings for weak encryption
///
/// # Returns
/// * `None` on success
///
/// # Raises
/// * `IOError` - If file operations fail
/// * `ValueError` - If parameters are invalid
#[pyfunction]
#[pyo3(signature = (input_path, output_path, password=None, encryption="aes256", compression_level=6, suppress_warning=false))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly; detach has different semantics
pub fn compress_file(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    suppress_warning: bool,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    // Warn about weak encryption
    if enc_method == EncryptionMethod::ZipCrypto && password.is_some() && !suppress_warning {
        warn!(
            "ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    // Convert to owned strings for use in allow_threads closure
    let input = input_path.to_string();
    let output = output_path.to_string();
    let pwd = password.map(|s| s.to_string());
    let level = CompressionLevel::new(compression_level);

    // Release GIL during CPU-intensive compression
    py.allow_threads(|| {
        crate::compression::compress_file(
            Path::new(&input),
            Path::new(&output),
            pwd.as_deref(),
            enc_method,
            level,
        )
    })?;

    Ok(())
}

/// Compress multiple files to a ZIP archive.
///
/// # Arguments
/// * `input_paths` - List of paths to files to compress
/// * `prefixes` - Optional list of archive prefixes for each file
/// * `output_path` - Path for the output ZIP file
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method: "aes256", "zipcrypto", or "none"
/// * `compression_level` - Compression level (0-9, default 6)
/// * `suppress_warning` - Suppress security warnings for weak encryption
#[pyfunction]
#[pyo3(signature = (input_paths, prefixes, output_path, password=None, encryption="aes256", compression_level=6, suppress_warning=false))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn compress_files(
    py: Python<'_>,
    input_paths: Vec<String>,
    prefixes: Vec<Option<String>>,
    output_path: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    suppress_warning: bool,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    // Warn about weak encryption
    if enc_method == EncryptionMethod::ZipCrypto && password.is_some() && !suppress_warning {
        warn!(
            "ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    // Convert to owned data for use in allow_threads closure
    let output = output_path.to_string();
    let pwd = password.map(|s| s.to_string());
    let level = CompressionLevel::new(compression_level);

    // Release GIL during CPU-intensive compression
    py.allow_threads(|| {
        let paths: Vec<std::path::PathBuf> =
            input_paths.iter().map(std::path::PathBuf::from).collect();
        let path_refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
        let prefix_refs: Vec<Option<&str>> = prefixes
            .iter()
            .map(|p| p.as_ref().map(|s| s.as_str()))
            .collect();

        crate::compression::compress_files(
            &path_refs,
            &prefix_refs,
            Path::new(&output),
            pwd.as_deref(),
            enc_method,
            level,
        )
    })?;

    Ok(())
}

/// Compress a directory to a ZIP archive.
///
/// # Arguments
/// * `input_dir` - Path to the directory to compress
/// * `output_path` - Path for the output ZIP file
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method: "aes256", "zipcrypto", or "none"
/// * `compression_level` - Compression level (0-9, default 6)
/// * `include_patterns` - Optional list of glob patterns to include
/// * `exclude_patterns` - Optional list of glob patterns to exclude
/// * `suppress_warning` - Suppress security warnings for weak encryption
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (input_dir, output_path, password=None, encryption="aes256", compression_level=6, include_patterns=None, exclude_patterns=None, suppress_warning=false))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn compress_directory(
    py: Python<'_>,
    input_dir: &str,
    output_path: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    include_patterns: Option<Vec<String>>,
    exclude_patterns: Option<Vec<String>>,
    suppress_warning: bool,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    // Warn about weak encryption
    if enc_method == EncryptionMethod::ZipCrypto && password.is_some() && !suppress_warning {
        warn!(
            "ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    // Convert to owned data for use in allow_threads closure
    let input = input_dir.to_string();
    let output = output_path.to_string();
    let pwd = password.map(|s| s.to_string());
    let level = CompressionLevel::new(compression_level);

    // Release GIL during CPU-intensive compression
    py.allow_threads(|| {
        crate::compression::compress_directory(
            Path::new(&input),
            Path::new(&output),
            pwd.as_deref(),
            enc_method,
            level,
            include_patterns.as_deref(),
            exclude_patterns.as_deref(),
        )
    })?;

    Ok(())
}

/// Decompress a ZIP archive.
///
/// # Arguments
/// * `input_path` - Path to the ZIP file to decompress
/// * `output_path` - Path for the output directory
/// * `password` - Optional password for encrypted archives
/// * `withoutpath` - If true, extract files without their directory paths (flatten).
///                   Defaults to false.
/// * `max_size` - Maximum total decompressed size in bytes. Default is 2GB. Set to 0 to disable.
/// * `max_ratio` - Maximum compression ratio allowed. Default is 500. Set to 0 to disable.
///
/// # Returns
/// * `None` on success
///
/// # Raises
/// * `IOError` - If file operations fail
/// * `ValueError` - If password is incorrect
/// * `RustyZipError` - If ZIP bomb limits are exceeded
#[pyfunction]
#[pyo3(signature = (input_path, output_path, password=None, withoutpath=false, max_size=None, max_ratio=None))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn decompress_file(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    password: Option<&str>,
    withoutpath: bool,
    max_size: Option<u64>,
    max_ratio: Option<u64>,
) -> PyResult<()> {
    use crate::compression::{DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE};

    // Convert to owned data for use in allow_threads closure
    let input = input_path.to_string();
    let output = output_path.to_string();
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
    py.allow_threads(|| {
        crate::compression::decompress_file_with_limits(
            Path::new(&input),
            Path::new(&output),
            pwd.as_deref(),
            withoutpath,
            effective_max_size,
            effective_max_ratio,
        )
    })?;

    Ok(())
}
