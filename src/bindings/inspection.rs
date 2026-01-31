//! Python bindings for archive inspection functions.

use crate::compression::{self, ArchiveInfo, FileInfo};
use pyo3::prelude::*;
use pyo3::types::PyList;
use std::path::Path;

/// Information about a single file in a ZIP archive.
///
/// This class provides read-only access to file metadata without extracting the file.
///
/// Attributes:
///     name (str): File name including path within archive
///     size (int): Uncompressed size in bytes
///     compressed_size (int): Compressed size in bytes
///     is_dir (bool): Whether this entry is a directory
///     is_encrypted (bool): Whether this file is encrypted
///     crc32 (int): CRC32 checksum
///     compression_method (str): Compression method name (e.g., "Deflated", "Stored")
///     last_modified (int | None): Last modified time as Unix timestamp
///     compression_ratio (float): Ratio of uncompressed to compressed size
///
/// Example:
///     >>> info = get_file_info("archive.zip", "document.txt")
///     >>> print(f"{info.name}: {info.size} bytes")
///     >>> if info.is_encrypted:
///     ...     print("File is encrypted")
#[pyclass(name = "FileInfo", frozen)]
#[derive(Clone)]
pub struct PyFileInfo {
    inner: FileInfo,
}

#[pymethods]
impl PyFileInfo {
    /// File name including path within archive.
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    /// Uncompressed size in bytes.
    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    /// Compressed size in bytes.
    #[getter]
    fn compressed_size(&self) -> u64 {
        self.inner.compressed_size
    }

    /// Whether this entry is a directory.
    #[getter]
    fn is_dir(&self) -> bool {
        self.inner.is_dir
    }

    /// Whether this file is encrypted.
    #[getter]
    fn is_encrypted(&self) -> bool {
        self.inner.is_encrypted
    }

    /// CRC32 checksum.
    #[getter]
    fn crc32(&self) -> u32 {
        self.inner.crc32
    }

    /// Compression method name.
    #[getter]
    fn compression_method(&self) -> &str {
        &self.inner.compression_method
    }

    /// Last modified time as Unix timestamp, or None if not available.
    #[getter]
    fn last_modified(&self) -> Option<i64> {
        self.inner.last_modified
    }

    /// Compression ratio (uncompressed size / compressed size).
    #[getter]
    fn compression_ratio(&self) -> f64 {
        self.inner.compression_ratio()
    }

    fn __repr__(&self) -> String {
        format!(
            "FileInfo(name={:?}, size={}, compressed_size={}, is_dir={}, is_encrypted={})",
            self.inner.name,
            self.inner.size,
            self.inner.compressed_size,
            self.inner.is_dir,
            self.inner.is_encrypted
        )
    }

    fn __str__(&self) -> String {
        if self.inner.is_dir {
            format!("{} (directory)", self.inner.name)
        } else {
            format!(
                "{}: {} bytes ({:.1}:1 compression)",
                self.inner.name,
                self.inner.size,
                self.inner.compression_ratio()
            )
        }
    }
}

impl From<FileInfo> for PyFileInfo {
    fn from(info: FileInfo) -> Self {
        Self { inner: info }
    }
}

/// Summary information about a ZIP archive.
///
/// This class provides read-only access to archive metadata without extracting files.
///
/// Attributes:
///     total_entries (int): Total number of entries (files and directories)
///     file_count (int): Number of files (excluding directories)
///     dir_count (int): Number of directories
///     total_size (int): Total uncompressed size in bytes
///     total_compressed_size (int): Total compressed size in bytes
///     compression_ratio (float): Overall compression ratio
///     encryption (str): Encryption method ("aes256", "zipcrypto", or "none")
///     has_encrypted_files (bool): Whether archive contains encrypted files
///     comment (str): Archive comment (empty string if none)
///
/// Example:
///     >>> info = get_archive_info("archive.zip")
///     >>> print(f"Files: {info.file_count}, Total: {info.total_size} bytes")
///     >>> if info.has_encrypted_files:
///     ...     print(f"Encryption: {info.encryption}")
#[pyclass(name = "ArchiveInfo", frozen)]
#[derive(Clone)]
pub struct PyArchiveInfo {
    inner: ArchiveInfo,
}

#[pymethods]
impl PyArchiveInfo {
    /// Total number of entries (files and directories).
    #[getter]
    fn total_entries(&self) -> usize {
        self.inner.total_entries
    }

    /// Number of files (excluding directories).
    #[getter]
    fn file_count(&self) -> usize {
        self.inner.file_count
    }

    /// Number of directories.
    #[getter]
    fn dir_count(&self) -> usize {
        self.inner.dir_count
    }

    /// Total uncompressed size in bytes.
    #[getter]
    fn total_size(&self) -> u64 {
        self.inner.total_size
    }

    /// Total compressed size in bytes.
    #[getter]
    fn total_compressed_size(&self) -> u64 {
        self.inner.total_compressed_size
    }

    /// Overall compression ratio.
    #[getter]
    fn compression_ratio(&self) -> f64 {
        self.inner.compression_ratio()
    }

    /// Encryption method ("aes256", "zipcrypto", "none", or "mixed").
    #[getter]
    fn encryption(&self) -> &'static str {
        match self.inner.encryption {
            crate::compression::EncryptionMethod::Aes256 => "aes256",
            crate::compression::EncryptionMethod::ZipCrypto => "zipcrypto",
            crate::compression::EncryptionMethod::None => "none",
            crate::compression::EncryptionMethod::Mixed => "mixed",
        }
    }

    /// Whether archive contains encrypted files.
    #[getter]
    fn has_encrypted_files(&self) -> bool {
        self.inner.has_encrypted_files
    }

    /// Archive comment (empty string if none).
    #[getter]
    fn comment(&self) -> &str {
        &self.inner.comment
    }

    fn __repr__(&self) -> String {
        format!(
            "ArchiveInfo(file_count={}, dir_count={}, total_size={}, encryption={:?})",
            self.inner.file_count,
            self.inner.dir_count,
            self.inner.total_size,
            self.encryption()
        )
    }

    fn __str__(&self) -> String {
        let enc_info = if self.inner.has_encrypted_files {
            format!(", encryption={}", self.encryption())
        } else {
            String::new()
        };
        format!(
            "{} files, {} dirs, {} bytes total ({:.1}:1 compression){}",
            self.inner.file_count,
            self.inner.dir_count,
            self.inner.total_size,
            self.inner.compression_ratio(),
            enc_info
        )
    }
}

impl From<ArchiveInfo> for PyArchiveInfo {
    fn from(info: ArchiveInfo) -> Self {
        Self { inner: info }
    }
}

/// List all files in a ZIP archive.
///
/// Returns a list of file names (including paths within the archive).
/// This function does not extract any files.
///
/// Args:
///     path: Path to the ZIP file.
///
/// Returns:
///     A list of file names in the archive.
///
/// Raises:
///     FileNotFoundError: If the ZIP file does not exist.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> files = list_archive("archive.zip")
///     >>> for name in files:
///     ...     print(name)
#[pyfunction]
pub fn list_archive(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let names = compression::list_archive(Path::new(path))?;
    let list = PyList::new(py, names)?;
    Ok(list.into())
}

/// List all files in a ZIP archive from bytes.
///
/// Args:
///     data: The ZIP archive data as bytes.
///
/// Returns:
///     A list of file names in the archive.
#[pyfunction]
pub fn list_archive_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyList>> {
    let names = compression::list_archive_bytes(data)?;
    let list = PyList::new(py, names)?;
    Ok(list.into())
}

/// Get detailed information about a ZIP archive.
///
/// Returns an ArchiveInfo object with archive metadata.
///
/// Args:
///     path: Path to the ZIP file.
///
/// Returns:
///     ArchiveInfo object with archive metadata.
///
/// Raises:
///     FileNotFoundError: If the ZIP file does not exist.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> info = get_archive_info("archive.zip")
///     >>> print(f"Files: {info.file_count}, Size: {info.total_size} bytes")
#[pyfunction]
pub fn get_archive_info(path: &str) -> PyResult<PyArchiveInfo> {
    let info = compression::get_archive_info(Path::new(path))?;
    Ok(info.into())
}

/// Get detailed information about a ZIP archive from bytes.
///
/// Args:
///     data: The ZIP archive data as bytes.
///
/// Returns:
///     ArchiveInfo object with archive metadata.
#[pyfunction]
pub fn get_archive_info_bytes(data: &[u8]) -> PyResult<PyArchiveInfo> {
    let info = compression::get_archive_info_bytes(data)?;
    Ok(info.into())
}

/// Get detailed information about a specific file in a ZIP archive.
///
/// Args:
///     path: Path to the ZIP file.
///     file_name: Name of the file within the archive (must match exactly).
///
/// Returns:
///     FileInfo object with file metadata.
///
/// Raises:
///     FileNotFoundError: If the ZIP file or specified file doesn't exist.
///     IOError: If the file is not a valid ZIP archive.
///
/// Example:
///     >>> info = get_file_info("archive.zip", "document.txt")
///     >>> print(f"Size: {info.size}, Encrypted: {info.is_encrypted}")
#[pyfunction]
pub fn get_file_info(path: &str, file_name: &str) -> PyResult<PyFileInfo> {
    let info = compression::get_file_info(Path::new(path), file_name)?;
    Ok(info.into())
}

/// Get detailed information about a specific file in a ZIP archive from bytes.
///
/// Args:
///     data: The ZIP archive data as bytes.
///     file_name: Name of the file within the archive.
///
/// Returns:
///     FileInfo object with file metadata.
#[pyfunction]
pub fn get_file_info_bytes(data: &[u8], file_name: &str) -> PyResult<PyFileInfo> {
    let info = compression::get_file_info_bytes(data, file_name)?;
    Ok(info.into())
}

/// Get information about all files in a ZIP archive.
///
/// Returns a list of FileInfo objects for all entries.
///
/// Args:
///     path: Path to the ZIP file.
///
/// Returns:
///     A list of FileInfo objects.
///
/// Example:
///     >>> files = get_all_file_info("archive.zip")
///     >>> for f in files:
///     ...     print(f"{f.name}: {f.size} bytes")
#[pyfunction]
pub fn get_all_file_info(path: &str) -> PyResult<Vec<PyFileInfo>> {
    let infos = compression::get_all_file_info(Path::new(path))?;
    Ok(infos.into_iter().map(PyFileInfo::from).collect())
}

/// Get information about all files in a ZIP archive from bytes.
///
/// Args:
///     data: The ZIP archive data as bytes.
///
/// Returns:
///     A list of FileInfo objects.
#[pyfunction]
pub fn get_all_file_info_bytes(data: &[u8]) -> PyResult<Vec<PyFileInfo>> {
    let infos = compression::get_all_file_info_bytes(data)?;
    Ok(infos.into_iter().map(PyFileInfo::from).collect())
}

/// Check if a file exists in a ZIP archive.
///
/// This is more efficient than list_archive when you only need to check
/// for a specific file, as it can return early once the file is found.
///
/// Args:
///     path: Path to the ZIP file.
///     file_name: Name of the file to check for.
///
/// Returns:
///     True if the file exists, False otherwise.
///
/// Example:
///     >>> if has_file("archive.zip", "config.json"):
///     ...     print("Config file found!")
#[pyfunction]
pub fn has_file(path: &str, file_name: &str) -> PyResult<bool> {
    Ok(compression::has_file(Path::new(path), file_name)?)
}

/// Check if a file exists in a ZIP archive from bytes.
///
/// Args:
///     data: The ZIP archive data as bytes.
///     file_name: Name of the file to check for.
///
/// Returns:
///     True if the file exists, False otherwise.
#[pyfunction]
pub fn has_file_bytes(data: &[u8], file_name: &str) -> PyResult<bool> {
    Ok(compression::has_file_bytes(data, file_name)?)
}

/// Register inspection functions and classes with the Python module.
pub fn register_inspection_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register classes
    m.add_class::<PyFileInfo>()?;
    m.add_class::<PyArchiveInfo>()?;

    // Register functions
    m.add_function(wrap_pyfunction!(list_archive, m)?)?;
    m.add_function(wrap_pyfunction!(list_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(get_archive_info, m)?)?;
    m.add_function(wrap_pyfunction!(get_archive_info_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(get_file_info, m)?)?;
    m.add_function(wrap_pyfunction!(get_file_info_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(get_all_file_info, m)?)?;
    m.add_function(wrap_pyfunction!(get_all_file_info_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(has_file, m)?)?;
    m.add_function(wrap_pyfunction!(has_file_bytes, m)?)?;
    Ok(())
}
