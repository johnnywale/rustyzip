//! pyminizip compatibility layer.
//!
//! This module provides API-compatible functions that match pyminizip's interface,
//! with optional security extensions for ZIP bomb protection and resource limits.

use crate::compression::{
    CompressionLevel, EncryptionMethod, DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_DECOMPRESSED_SIZE,
};
use pyo3::prelude::*;
use std::path::Path;

/// pyminizip-compatible compress function.
///
/// This function provides API compatibility with pyminizip.compress().
/// For new code, prefer using compress_file() or compress_files().
///
/// # Arguments
/// * `src` - Source file path (single file) or list of file paths
/// * `src_prefix` - Prefix path in archive (single) or list of prefixes
/// * `dst` - Destination ZIP file path
/// * `password` - Password for encryption (uses ZipCrypto for compatibility)
/// * `compress_level` - Compression level (1-9)
///
/// # Note
/// For pyminizip compatibility, this uses ZipCrypto encryption by default
/// when a password is provided, matching pyminizip's behavior.
#[pyfunction]
#[pyo3(signature = (src, src_prefix, dst, password, compress_level))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn compress(
    py: Python<'_>,
    src: &Bound<'_, PyAny>,
    src_prefix: &Bound<'_, PyAny>,
    dst: &str,
    password: Option<&str>,
    compress_level: u32,
) -> PyResult<()> {
    // Handle both single file and list of files
    let (paths, prefixes): (Vec<String>, Vec<Option<String>>) =
        if src.is_instance_of::<pyo3::types::PyList>() {
            let paths: Vec<String> = src.extract()?;
            let prefixes: Vec<Option<String>> = if src_prefix.is_none() {
                vec![None; paths.len()]
            } else if src_prefix.is_instance_of::<pyo3::types::PyList>() {
                src_prefix.extract()?
            } else {
                let prefix: Option<String> = src_prefix.extract()?;
                vec![prefix; paths.len()]
            };
            (paths, prefixes)
        } else {
            let path: String = src.extract()?;
            let prefix: Option<String> = if src_prefix.is_none() {
                None
            } else {
                src_prefix.extract()?
            };
            (vec![path], vec![prefix])
        };

    // Use ZipCrypto for pyminizip compatibility
    let enc_method = if password.is_some() {
        EncryptionMethod::ZipCrypto
    } else {
        EncryptionMethod::None
    };

    // Convert to owned data for use in allow_threads closure
    let output = dst.to_string();
    let pwd = password.map(|s| s.to_string());
    let level = CompressionLevel::new(compress_level);

    // Release GIL during CPU-intensive compression
    py.allow_threads(|| {
        let path_bufs: Vec<std::path::PathBuf> =
            paths.iter().map(std::path::PathBuf::from).collect();
        let path_refs: Vec<&Path> = path_bufs.iter().map(|p| p.as_path()).collect();
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

/// pyminizip-compatible uncompress function with optional security settings.
///
/// This function provides API compatibility with pyminizip.uncompress().
/// For new code, prefer using decompress_file().
///
/// # Arguments
/// * `src` - Source ZIP file path
/// * `password` - Password for encrypted archives
/// * `dst` - Destination directory path
/// * `withoutpath` - If non-zero, extract files without their directory paths (flatten)
/// * `max_size` - Maximum total decompressed size in bytes (default: 2GB, 0 to disable)
/// * `max_ratio` - Maximum compression ratio (default: 500, 0 to disable)
/// * `allow_symlinks` - Whether to allow extracting symlinks (default: false)
///
/// # Security
/// By default, this function protects against:
/// - ZIP bomb attacks (via max_size and max_ratio limits)
/// - Path traversal attacks (hardcoded protection)
/// - Symlink attacks (disabled by default)
///
/// Legacy code calling `uncompress(src, pw, dst, 0)` works immediately but is
/// protected by 2GB/500:1 limits. Advanced users can pass `max_size=0` to disable
/// size checking or set higher values as needed.
///
/// # Example
/// ```python
/// # Basic usage (protected by defaults)
/// rustyzip.uncompress("archive.zip", "password", "/output", 0)
///
/// # Disable size limit for large archives
/// rustyzip.uncompress("archive.zip", "password", "/output", 0, max_size=0)
///
/// # Custom limits
/// rustyzip.uncompress("archive.zip", "password", "/output", 0,
///                     max_size=10*1024*1024*1024,  # 10GB
///                     max_ratio=1000)              # Allow 1000:1 ratio
/// ```
#[pyfunction]
#[pyo3(signature = (src, password, dst, withoutpath, max_size=None, max_ratio=None, allow_symlinks=false))]
#[allow(deprecated)] // allow_threads is deprecated but works correctly
pub fn uncompress(
    py: Python<'_>,
    src: &str,
    password: Option<&str>,
    dst: &str,
    withoutpath: i32,
    max_size: Option<u64>,
    max_ratio: Option<u64>,
    allow_symlinks: bool,
) -> PyResult<()> {
    // Convert to owned data for use in allow_threads closure
    let input = src.to_string();
    let output = dst.to_string();
    let pwd = password.map(|s| s.to_string());
    let without = withoutpath != 0;

    // Use provided limits or secure defaults
    // A value of 0 means "disabled" (unlimited) for both limits
    let size_limit = match max_size {
        Some(0) => u64::MAX, // 0 means disabled/unlimited
        Some(size) => size,
        None => DEFAULT_MAX_DECOMPRESSED_SIZE,
    };
    let ratio_limit = match max_ratio {
        Some(0) => u64::MAX, // 0 means disabled/unlimited
        Some(ratio) => ratio,
        None => DEFAULT_MAX_COMPRESSION_RATIO,
    };

    // Note: allow_symlinks is currently passed through but symlink handling
    // is enforced at the path validation level. This parameter is reserved
    // for future use when symlink extraction is supported.
    let _ = allow_symlinks;

    // Release GIL during CPU-intensive decompression
    py.allow_threads(|| {
        crate::compression::decompress_file_with_limits(
            Path::new(&input),
            Path::new(&output),
            pwd.as_deref(),
            without,
            size_limit,
            ratio_limit,
        )
    })?;

    Ok(())
}
