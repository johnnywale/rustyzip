//! Python bindings for archive modification functions.

use crate::compression::{self, CompressionLevel, EncryptionMethod};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::Path;

/// Add files to an existing ZIP archive.
///
/// Args:
///     archive_path: Path to the existing ZIP archive.
///     files: List of file paths to add.
///     archive_names: Names for the files in the archive (must match files length).
///     password: Optional password for encryption.
///     encryption: Encryption method ("aes256", "zipcrypto", or "none").
///     compression_level: Compression level (0-9, default 6).
///
/// Raises:
///     FileNotFoundError: If the archive or any input file doesn't exist.
///     ValueError: If the number of files doesn't match archive_names.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> add_to_archive("archive.zip", ["new_file.txt"], ["docs/new_file.txt"])
#[pyfunction]
#[pyo3(signature = (archive_path, files, archive_names, password=None, encryption="aes256", compression_level=6))]
pub fn add_to_archive(
    archive_path: &str,
    files: Vec<String>,
    archive_names: Vec<String>,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;
    let level = CompressionLevel::new(compression_level);

    let file_paths: Vec<&Path> = files.iter().map(|s| Path::new(s.as_str())).collect();
    let names: Vec<&str> = archive_names.iter().map(|s| s.as_str()).collect();

    compression::add_to_archive(
        Path::new(archive_path),
        &file_paths,
        &names,
        password,
        enc_method,
        level,
    )?;

    Ok(())
}

/// Add bytes data to an existing ZIP archive.
///
/// Args:
///     archive_path: Path to the existing ZIP archive.
///     data: Data to add as a file.
///     archive_name: Name for the data in the archive.
///     password: Optional password for encryption.
///     encryption: Encryption method ("aes256", "zipcrypto", or "none").
///     compression_level: Compression level (0-9, default 6).
///
/// Raises:
///     FileNotFoundError: If the archive doesn't exist.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> add_bytes_to_archive("archive.zip", b"Hello!", "greeting.txt")
#[pyfunction]
#[pyo3(signature = (archive_path, data, archive_name, password=None, encryption="aes256", compression_level=6))]
pub fn add_bytes_to_archive(
    archive_path: &str,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;
    let level = CompressionLevel::new(compression_level);

    compression::add_bytes_to_archive(
        Path::new(archive_path),
        data,
        archive_name,
        password,
        enc_method,
        level,
    )?;

    Ok(())
}

/// Remove files from a ZIP archive.
///
/// Args:
///     archive_path: Path to the ZIP archive.
///     file_names: Names of files to remove from the archive.
///
/// Returns:
///     The number of files that were actually removed.
///
/// Raises:
///     FileNotFoundError: If the archive doesn't exist.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> count = remove_from_archive("archive.zip", ["old_file.txt", "temp.txt"])
///     >>> print(f"Removed {count} files")
#[pyfunction]
#[pyo3(signature = (archive_path, file_names))]
pub fn remove_from_archive(archive_path: &str, file_names: Vec<String>) -> PyResult<usize> {
    let names: Vec<&str> = file_names.iter().map(|s| s.as_str()).collect();
    let count = compression::remove_from_archive(Path::new(archive_path), &names)?;
    Ok(count)
}

/// Rename a file within a ZIP archive.
///
/// Args:
///     archive_path: Path to the ZIP archive.
///     old_name: Current name of the file in the archive.
///     new_name: New name for the file.
///
/// Raises:
///     FileNotFoundError: If the archive doesn't exist or the file isn't found.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> rename_in_archive("archive.zip", "old_name.txt", "new_name.txt")
#[pyfunction]
#[pyo3(signature = (archive_path, old_name, new_name))]
pub fn rename_in_archive(archive_path: &str, old_name: &str, new_name: &str) -> PyResult<()> {
    compression::rename_in_archive(Path::new(archive_path), old_name, new_name)?;
    Ok(())
}

/// Update (replace) a file's content within a ZIP archive.
///
/// Args:
///     archive_path: Path to the ZIP archive.
///     file_name: Name of the file to update in the archive.
///     new_data: New content for the file.
///     password: Optional password for encryption.
///     encryption: Encryption method ("aes256", "zipcrypto", or "none").
///     compression_level: Compression level (0-9, default 6).
///
/// Raises:
///     FileNotFoundError: If the archive doesn't exist or the file isn't found.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> update_in_archive("archive.zip", "config.json", b'{"version": 2}')
#[pyfunction]
#[pyo3(signature = (archive_path, file_name, new_data, password=None, encryption="aes256", compression_level=6))]
pub fn update_in_archive(
    archive_path: &str,
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<()> {
    let enc_method = EncryptionMethod::from_str(encryption)?;
    let level = CompressionLevel::new(compression_level);

    compression::update_in_archive(
        Path::new(archive_path),
        file_name,
        new_data,
        password,
        enc_method,
        level,
    )?;

    Ok(())
}

// Bytes variants for working with in-memory archives

/// Add files to a ZIP archive in memory.
///
/// Args:
///     archive_data: Existing archive data as bytes.
///     files_data: List of (data, name) tuples to add.
///     password: Optional password for encryption.
///     encryption: Encryption method ("aes256", "zipcrypto", or "none").
///     compression_level: Compression level (0-9, default 6).
///
/// Returns:
///     The modified archive data.
///
/// Example:
///     >>> new_data = add_to_archive_bytes(archive_data, [(b"content", "file.txt")])
#[pyfunction]
#[pyo3(signature = (archive_data, files_data, password=None, encryption="aes256", compression_level=6))]
pub fn add_to_archive_bytes<'py>(
    py: Python<'py>,
    archive_data: &[u8],
    files_data: Vec<(Vec<u8>, String)>,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let enc_method = EncryptionMethod::from_str(encryption)?;
    let level = CompressionLevel::new(compression_level);

    // Convert to the format expected by the Rust function
    let files: Vec<(&[u8], &str)> = files_data
        .iter()
        .map(|(data, name)| (data.as_slice(), name.as_str()))
        .collect();

    let result =
        compression::add_to_archive_bytes(archive_data, &files, password, enc_method, level)?;

    Ok(PyBytes::new(py, &result))
}

/// Remove files from a ZIP archive in memory.
///
/// Args:
///     archive_data: Existing archive data as bytes.
///     file_names: Names of files to remove.
///
/// Returns:
///     A tuple of (modified archive data, number of files removed).
///
/// Example:
///     >>> new_data, count = remove_from_archive_bytes(archive_data, ["old.txt"])
#[pyfunction]
#[pyo3(signature = (archive_data, file_names))]
pub fn remove_from_archive_bytes<'py>(
    py: Python<'py>,
    archive_data: &[u8],
    file_names: Vec<String>,
) -> PyResult<(Bound<'py, PyBytes>, usize)> {
    let names: Vec<&str> = file_names.iter().map(|s| s.as_str()).collect();
    let (result, count) = compression::remove_from_archive_bytes(archive_data, &names)?;
    Ok((PyBytes::new(py, &result), count))
}

/// Rename a file within a ZIP archive in memory.
///
/// Args:
///     archive_data: Existing archive data as bytes.
///     old_name: Current name of the file.
///     new_name: New name for the file.
///
/// Returns:
///     The modified archive data.
///
/// Example:
///     >>> new_data = rename_in_archive_bytes(archive_data, "old.txt", "new.txt")
#[pyfunction]
#[pyo3(signature = (archive_data, old_name, new_name))]
pub fn rename_in_archive_bytes<'py>(
    py: Python<'py>,
    archive_data: &[u8],
    old_name: &str,
    new_name: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = compression::rename_in_archive_bytes(archive_data, old_name, new_name)?;
    Ok(PyBytes::new(py, &result))
}

/// Update (replace) a file's content within a ZIP archive in memory.
///
/// Args:
///     archive_data: Existing archive data as bytes.
///     file_name: Name of the file to update.
///     new_data: New content for the file.
///     password: Optional password for encryption.
///     encryption: Encryption method ("aes256", "zipcrypto", or "none").
///     compression_level: Compression level (0-9, default 6).
///
/// Returns:
///     The modified archive data.
///
/// Example:
///     >>> new_data = update_in_archive_bytes(archive_data, "config.json", b"{}")
#[pyfunction]
#[pyo3(signature = (archive_data, file_name, new_data, password=None, encryption="aes256", compression_level=6))]
pub fn update_in_archive_bytes<'py>(
    py: Python<'py>,
    archive_data: &[u8],
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let enc_method = EncryptionMethod::from_str(encryption)?;
    let level = CompressionLevel::new(compression_level);

    let result = compression::update_in_archive_bytes(
        archive_data,
        file_name,
        new_data,
        password,
        enc_method,
        level,
    )?;

    Ok(PyBytes::new(py, &result))
}

/// Register modification functions with the Python module.
pub fn register_modification_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(add_to_archive, m)?)?;
    m.add_function(wrap_pyfunction!(add_bytes_to_archive, m)?)?;
    m.add_function(wrap_pyfunction!(remove_from_archive, m)?)?;
    m.add_function(wrap_pyfunction!(rename_in_archive, m)?)?;
    m.add_function(wrap_pyfunction!(update_in_archive, m)?)?;
    m.add_function(wrap_pyfunction!(add_to_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(remove_from_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(rename_in_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(update_in_archive_bytes, m)?)?;
    Ok(())
}
