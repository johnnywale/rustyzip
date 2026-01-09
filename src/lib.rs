//! RustyZip - A high-performance, secure file compression library
//!
//! RustyZip provides fast ZIP compression with multiple encryption methods,
//! serving as a modern replacement for pyminizip.

mod compression;
mod error;

use compression::{CompressionLevel, EncryptionMethod};
use pyo3::prelude::*;
use std::path::Path;

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
fn compress_file(
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
        eprintln!(
            "WARNING: ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    compression::compress_file(
        Path::new(input_path),
        Path::new(output_path),
        password,
        enc_method,
        CompressionLevel::new(compression_level),
    )?;

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
#[pyfunction]
#[pyo3(signature = (input_paths, prefixes, output_path, password=None, encryption="aes256", compression_level=6))]
fn compress_files(
    input_paths: Vec<String>,
    prefixes: Vec<Option<String>>,
    output_path: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    let paths: Vec<&Path> = input_paths.iter().map(|p| Path::new(p.as_str())).collect();
    let prefix_refs: Vec<Option<&str>> = prefixes
        .iter()
        .map(|p| p.as_ref().map(|s| s.as_str()))
        .collect();

    compression::compress_files(
        &paths,
        &prefix_refs,
        Path::new(output_path),
        password,
        enc_method,
        CompressionLevel::new(compression_level),
    )?;

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
#[pyfunction]
#[pyo3(signature = (input_dir, output_path, password=None, encryption="aes256", compression_level=6, include_patterns=None, exclude_patterns=None))]
fn compress_directory(
    input_dir: &str,
    output_path: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    include_patterns: Option<Vec<String>>,
    exclude_patterns: Option<Vec<String>>,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    compression::compress_directory(
        Path::new(input_dir),
        Path::new(output_path),
        password,
        enc_method,
        CompressionLevel::new(compression_level),
        include_patterns.as_ref().map(|v| v.as_slice()),
        exclude_patterns.as_ref().map(|v| v.as_slice()),
    )?;

    Ok(())
}

/// Decompress a ZIP archive.
///
/// # Arguments
/// * `input_path` - Path to the ZIP file to decompress
/// * `output_path` - Path for the output directory
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// * `None` on success
///
/// # Raises
/// * `IOError` - If file operations fail
/// * `ValueError` - If password is incorrect
#[pyfunction]
#[pyo3(signature = (input_path, output_path, password=None))]
fn decompress_file(input_path: &str, output_path: &str, password: Option<&str>) -> PyResult<()> {
    compression::decompress_file(Path::new(input_path), Path::new(output_path), password)?;

    Ok(())
}

// ============================================================================
// pyminizip Compatibility Functions
// ============================================================================

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
fn compress(
    src: &Bound<'_, PyAny>,
    src_prefix: &Bound<'_, PyAny>,
    dst: &str,
    password: Option<&str>,
    compress_level: u32,
) -> PyResult<()> {
    let _py = src.py();

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
    let encryption = if password.is_some() {
        "zipcrypto"
    } else {
        "none"
    };

    let path_refs: Vec<&Path> = paths.iter().map(|p| Path::new(p.as_str())).collect();
    let prefix_refs: Vec<Option<&str>> = prefixes
        .iter()
        .map(|p| p.as_ref().map(|s| s.as_str()))
        .collect();

    let enc_method = EncryptionMethod::from_str(encryption)?;

    compression::compress_files(
        &path_refs,
        &prefix_refs,
        Path::new(dst),
        password,
        enc_method,
        CompressionLevel::new(compress_level),
    )?;

    Ok(())
}

/// pyminizip-compatible uncompress function.
///
/// This function provides API compatibility with pyminizip.uncompress().
/// For new code, prefer using decompress_file().
///
/// # Arguments
/// * `src` - Source ZIP file path
/// * `password` - Password for encrypted archives
/// * `dst` - Destination directory path
/// * `delete_zip` - Whether to delete the ZIP file after extraction
#[pyfunction]
#[pyo3(signature = (src, password, dst, delete_zip))]
fn uncompress(src: &str, password: Option<&str>, dst: &str, delete_zip: bool) -> PyResult<()> {
    compression::decompress_file(Path::new(src), Path::new(dst), password)?;

    if delete_zip {
        compression::delete_file(Path::new(src))?;
    }

    Ok(())
}

/// RustyZip Python module
#[pymodule]
fn rustyzip(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compress_file, m)?)?;
    m.add_function(wrap_pyfunction!(compress_files, m)?)?;
    m.add_function(wrap_pyfunction!(compress_directory, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_file, m)?)?;

    // pyminizip compatibility functions
    m.add_function(wrap_pyfunction!(compress, m)?)?;
    m.add_function(wrap_pyfunction!(uncompress, m)?)?;

    // Add version
    m.add("__version__", "1.0.0")?;

    Ok(())
}
