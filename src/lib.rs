//! RustyZip - A high-performance, secure file compression library
//!
//! RustyZip provides fast ZIP compression with multiple encryption methods,
//! serving as a modern replacement for pyminizip.

mod compression;
mod error;
mod stream;

use compression::{CompressionLevel, EncryptionMethod};
use pyo3::prelude::*;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

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
/// * `suppress_warning` - Suppress security warnings for weak encryption
#[pyfunction]
#[pyo3(signature = (input_paths, prefixes, output_path, password=None, encryption="aes256", compression_level=6, suppress_warning=false))]
fn compress_files(
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
        eprintln!(
            "WARNING: ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

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
/// * `suppress_warning` - Suppress security warnings for weak encryption
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (input_dir, output_path, password=None, encryption="aes256", compression_level=6, include_patterns=None, exclude_patterns=None, suppress_warning=false))]
fn compress_directory(
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
        eprintln!(
            "WARNING: ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    compression::compress_directory(
        Path::new(input_dir),
        Path::new(output_path),
        password,
        enc_method,
        CompressionLevel::new(compression_level),
        include_patterns.as_deref(),
        exclude_patterns.as_deref(),
    )?;

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
///
/// # Returns
/// * `None` on success
///
/// # Raises
/// * `IOError` - If file operations fail
/// * `ValueError` - If password is incorrect
#[pyfunction]
#[pyo3(signature = (input_path, output_path, password=None, withoutpath=false))]
fn decompress_file(input_path: &str, output_path: &str, password: Option<&str>, withoutpath: bool) -> PyResult<()> {
    compression::decompress_file(Path::new(input_path), Path::new(output_path), password, withoutpath)?;

    Ok(())
}

// ============================================================================
// In-Memory Compression Functions
// ============================================================================

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
fn compress_bytes(
    files: Vec<(String, Vec<u8>)>,
    password: Option<&str>,
    encryption: &str,
    compression_level: u32,
    suppress_warning: bool,
) -> PyResult<Vec<u8>> {
    let enc_method = EncryptionMethod::from_str(encryption)?;

    // Warn about weak encryption
    if enc_method == EncryptionMethod::ZipCrypto && password.is_some() && !suppress_warning {
        eprintln!(
            "WARNING: ZipCrypto encryption is weak and can be cracked. \
            Use AES256 for sensitive data or set suppress_warning=True to acknowledge this risk."
        );
    }

    // Convert to the format expected by compression module
    let file_refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, data)| (name.as_str(), data.as_slice()))
        .collect();

    let result = compression::compress_bytes(
        &file_refs,
        password,
        enc_method,
        CompressionLevel::new(compression_level),
    )?;

    Ok(result)
}

/// Decompress a ZIP archive from bytes in memory.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// * `list[tuple[str, bytes]]` - List of (filename, content) tuples
///
/// # Raises
/// * `IOError` - If decompression fails
/// * `ValueError` - If password is incorrect
///
/// # Example
/// ```python
/// import rustyzipper
/// files = rustyzipper.decompress_bytes(zip_data, password="secret")
/// for filename, content in files:
///     print(f"{filename}: {len(content)} bytes")
/// ```
#[pyfunction]
#[pyo3(signature = (data, password=None))]
fn decompress_bytes(data: Vec<u8>, password: Option<&str>) -> PyResult<Vec<(String, Vec<u8>)>> {
    let result = compression::decompress_bytes(&data, password)?;
    Ok(result)
}

// ============================================================================
// Streaming Compression Functions
// ============================================================================

/// Compress files from file-like objects to an output file-like object (streaming).
///
/// This function reads data in chunks and writes compressed output without
/// loading entire files into memory. Ideal for large files.
///
/// # Arguments
/// * `files` - List of (archive_name, file_object) tuples. Each file_object must have a read() method.
/// * `output` - Output file-like object with write() and seek() methods (e.g., open file or BytesIO)
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method: "aes256", "zipcrypto", or "none"
/// * `compression_level` - Compression level (0-9, default 6)
/// * `suppress_warning` - Suppress security warnings for weak encryption
///
/// # Example
/// ```python
/// import rustyzipper
/// import io
///
/// # Stream from files to BytesIO
/// output = io.BytesIO()
/// with open("large_file.bin", "rb") as f1, open("data.txt", "rb") as f2:
///     rustyzipper.compress_stream(
///         [("large_file.bin", f1), ("data.txt", f2)],
///         output,
///         password="secret"
///     )
/// zip_data = output.getvalue()
/// ```
#[pyfunction]
#[pyo3(signature = (files, output, password=None, encryption="aes256", compression_level=6, suppress_warning=false))]
fn compress_stream(
    _py: Python<'_>,
    files: Vec<(String, Bound<'_, pyo3::PyAny>)>,
    output: Bound<'_, pyo3::PyAny>,
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

    // Create the output writer wrapper
    let writer = stream::PyWriteSeeker::new(output);

    // Create readers for each file
    let file_readers: Vec<(String, stream::PyReader)> = files
        .into_iter()
        .map(|(name, file_obj)| (name, stream::PyReader::new(file_obj, None)))
        .collect();

    // Use py.allow_threads to release GIL during compression
    // Note: We can't easily do this with the current design since PyReader holds Python references
    // For now, keep the GIL held but process in chunks
    compression::compress_stream(
        writer,
        file_readers,
        password,
        enc_method,
        CompressionLevel::new(compression_level),
    )?;

    Ok(())
}

/// Decompress a ZIP archive from a file-like object (streaming).
///
/// This function reads the ZIP archive from a seekable file-like object,
/// allowing streaming decompression from files, network streams, etc.
///
/// # Arguments
/// * `input` - Input file-like object with read() and seek() methods
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// * `list[tuple[str, bytes]]` - List of (filename, content) tuples
///
/// # Example
/// ```python
/// import rustyzipper
///
/// # Stream from file
/// with open("archive.zip", "rb") as f:
///     files = rustyzipper.decompress_stream(f, password="secret")
///     for filename, content in files:
///         print(f"{filename}: {len(content)} bytes")
///
/// # Stream from BytesIO
/// import io
/// zip_data = get_zip_from_network()
/// buf = io.BytesIO(zip_data)
/// files = rustyzipper.decompress_stream(buf)
/// ```
#[pyfunction]
#[pyo3(signature = (input, password=None))]
fn decompress_stream(
    _py: Python<'_>,
    input: Bound<'_, pyo3::PyAny>,
    password: Option<&str>,
) -> PyResult<Vec<(String, Vec<u8>)>> {
    let reader = stream::PyReadSeeker::new(input, None);

    let result = compression::decompress_stream_to_vec(reader, password)?;
    Ok(result)
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

    let path_refs: Vec<&Path> = paths.iter().map(|p| Path::new(p.as_str())).collect();
    let prefix_refs: Vec<Option<&str>> = prefixes
        .iter()
        .map(|p| p.as_ref().map(|s| s.as_str()))
        .collect();

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
/// * `withoutpath` - If non-zero, extract files without their directory paths (flatten)
#[pyfunction]
#[pyo3(signature = (src, password, dst, withoutpath))]
fn uncompress(src: &str, password: Option<&str>, dst: &str, withoutpath: i32) -> PyResult<()> {
    compression::decompress_file(Path::new(src), Path::new(dst), password, withoutpath != 0)?;

    Ok(())
}

// ============================================================================
// Streaming Iterator Class
// ============================================================================

/// A streaming iterator for decompressing ZIP archives one file at a time.
///
/// This class implements Python's iterator protocol, allowing you to iterate
/// over files in a ZIP archive without loading all decompressed content into
/// memory at once. Each iteration yields a (filename, content) tuple.
///
/// # Example
/// ```python
/// from rustyzipper import open_zip_stream
///
/// # Iterate over files one at a time
/// for filename, content in open_zip_stream(zip_data, password="secret"):
///     print(f"Processing {filename}: {len(content)} bytes")
///     # Process content here - only one file in memory at a time
///     process_file(content)
/// ```
#[pyclass]
struct ZipStreamReader {
    /// The raw ZIP data
    data: Vec<u8>,
    /// Optional password for encrypted archives
    password: Option<String>,
    /// Current file index
    index: usize,
    /// Total number of files in the archive
    total: usize,
    /// List of file indices that are not directories
    file_indices: Vec<usize>,
}

#[pymethods]
impl ZipStreamReader {
    /// Returns self as the iterator
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Returns the next (filename, content) tuple or None if exhausted
    fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<Option<(String, Vec<u8>)>> {
        if slf.index >= slf.file_indices.len() {
            return Ok(None);
        }

        let file_idx = slf.file_indices[slf.index];
        slf.index += 1;

        // Create a new archive view for this read
        let cursor = Cursor::new(&slf.data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let mut file = match &slf.password {
            Some(pwd) => {
                match archive.by_index_decrypt(file_idx, pwd.as_bytes()) {
                    Ok(f) => f,
                    Err(zip::result::ZipError::InvalidPassword) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "Invalid password",
                        ));
                    }
                    Err(e) => {
                        return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                    }
                }
            }
            None => archive
                .by_index(file_idx)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        };

        let name = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok(Some((name, content)))
    }

    /// Returns the number of files in the archive (excluding directories)
    fn __len__(&self) -> usize {
        self.file_indices.len()
    }

    /// Returns the total number of entries (including directories)
    #[getter]
    fn total_entries(&self) -> usize {
        self.total
    }

    /// Returns the number of files (excluding directories)
    #[getter]
    fn file_count(&self) -> usize {
        self.file_indices.len()
    }

    /// Returns a list of all filenames in the archive
    fn namelist(&self) -> PyResult<Vec<String>> {
        let cursor = Cursor::new(&self.data);
        let archive = ZipArchive::new(cursor)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| {
                archive.name_for_index(i).map(|s| s.to_string())
            })
            .collect();

        Ok(names)
    }

    /// Extract a specific file by name
    fn read(&self, name: &str) -> PyResult<Vec<u8>> {
        let cursor = Cursor::new(&self.data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let mut file = match &self.password {
            Some(pwd) => {
                match archive.by_name_decrypt(name, pwd.as_bytes()) {
                    Ok(f) => f,
                    Err(zip::result::ZipError::InvalidPassword) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "Invalid password",
                        ));
                    }
                    Err(e) => {
                        return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                    }
                }
            }
            None => archive
                .by_name(name)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        };

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok(content)
    }
}

/// Open a ZIP archive for streaming iteration.
///
/// This function returns a ZipStreamReader that yields files one at a time,
/// avoiding loading all decompressed content into memory at once.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// * `ZipStreamReader` - An iterator yielding (filename, content) tuples
///
/// # Example
/// ```python
/// import rustyzipper
///
/// # Process large ZIP without loading all files into memory
/// with open("large_archive.zip", "rb") as f:
///     zip_data = f.read()
///
/// for filename, content in rustyzipper.open_zip_stream(zip_data):
///     # Only one file's content in memory at a time
///     process_file(filename, content)
///
/// # Or use it like a file object
/// reader = rustyzipper.open_zip_stream(zip_data, password="secret")
/// print(f"Archive contains {len(reader)} files")
/// print(f"Files: {reader.namelist()}")
///
/// # Read a specific file
/// content = reader.read("specific_file.txt")
/// ```
#[pyfunction]
#[pyo3(signature = (data, password=None))]
fn open_zip_stream(data: Vec<u8>, password: Option<String>) -> PyResult<ZipStreamReader> {
    // Pre-scan the archive to get file indices (excluding directories)
    let cursor = Cursor::new(&data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let total = archive.len();
    let mut file_indices = Vec::new();

    for i in 0..total {
        if let Ok(file) = archive.by_index_raw(i) {
            if !file.is_dir() {
                file_indices.push(i);
            }
        }
    }

    Ok(ZipStreamReader {
        data,
        password,
        index: 0,
        total,
        file_indices,
    })
}

/// A streaming iterator that reads from a file handle without loading ZIP into memory.
///
/// This class keeps the file handle open and seeks as needed, providing true
/// streaming for very large ZIP files where even the compressed data shouldn't
/// be loaded into memory.
#[pyclass]
struct ZipFileStreamReader {
    /// The Python file object (kept alive)
    file: Py<pyo3::PyAny>,
    /// Optional password for encrypted archives
    password: Option<String>,
    /// Current file index
    index: usize,
    /// List of file indices that are not directories
    file_indices: Vec<usize>,
    /// Total number of entries in the archive
    total: usize,
}

#[pymethods]
impl ZipFileStreamReader {
    /// Returns self as the iterator
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Returns the next (filename, content) tuple or None if exhausted
    fn __next__(mut slf: PyRefMut<'_, Self>, py: Python<'_>) -> PyResult<Option<(String, Vec<u8>)>> {
        if slf.index >= slf.file_indices.len() {
            return Ok(None);
        }

        let file_idx = slf.file_indices[slf.index];
        slf.index += 1;

        let file_bound = slf.file.bind(py);

        // Seek to beginning before creating archive
        file_bound.call_method1("seek", (0i64, 0i32))?;

        let reader = stream::PyReadSeeker::new(file_bound.clone(), None);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let mut file = match &slf.password {
            Some(pwd) => {
                match archive.by_index_decrypt(file_idx, pwd.as_bytes()) {
                    Ok(f) => f,
                    Err(zip::result::ZipError::InvalidPassword) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "Invalid password",
                        ));
                    }
                    Err(e) => {
                        return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                    }
                }
            }
            None => archive
                .by_index(file_idx)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        };

        let name = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok(Some((name, content)))
    }

    /// Returns the number of files in the archive (excluding directories)
    fn __len__(&self) -> usize {
        self.file_indices.len()
    }

    /// Returns the total number of entries (including directories)
    #[getter]
    fn total_entries(&self) -> usize {
        self.total
    }

    /// Returns the number of files (excluding directories)
    #[getter]
    fn file_count(&self) -> usize {
        self.file_indices.len()
    }

    /// Returns a list of all filenames in the archive
    fn namelist(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        let file_bound = self.file.bind(py);

        // Seek to beginning
        file_bound.call_method1("seek", (0i64, 0i32))?;

        let reader = stream::PyReadSeeker::new(file_bound.clone(), None);
        let archive = ZipArchive::new(reader)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();

        Ok(names)
    }

    /// Extract a specific file by name
    fn read(&self, py: Python<'_>, name: &str) -> PyResult<Vec<u8>> {
        let file_bound = self.file.bind(py);

        // Seek to beginning
        file_bound.call_method1("seek", (0i64, 0i32))?;

        let reader = stream::PyReadSeeker::new(file_bound.clone(), None);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let mut file = match &self.password {
            Some(pwd) => {
                match archive.by_name_decrypt(name, pwd.as_bytes()) {
                    Ok(f) => f,
                    Err(zip::result::ZipError::InvalidPassword) => {
                        return Err(pyo3::exceptions::PyValueError::new_err(
                            "Invalid password",
                        ));
                    }
                    Err(e) => {
                        return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                    }
                }
            }
            None => archive
                .by_name(name)
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        };

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        Ok(content)
    }
}

/// Open a ZIP archive from a file-like object for true streaming iteration.
///
/// This function returns a ZipFileStreamReader that reads directly from the
/// file handle without loading the entire ZIP into memory. The file handle
/// must remain open during iteration.
///
/// Memory behavior:
/// - ZIP data is NOT loaded into memory (only central directory metadata)
/// - Decompressed files are yielded one at a time
/// - File handle must remain open during iteration
///
/// # Arguments
/// * `input` - A file-like object with read() and seek() methods
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// * `ZipFileStreamReader` - An iterator yielding (filename, content) tuples
///
/// # Example
/// ```python
/// from rustyzipper import open_zip_stream_from_file
///
/// # True streaming - ZIP data is NOT loaded into memory
/// with open("huge_archive.zip", "rb") as f:
///     reader = open_zip_stream_from_file(f)
///     print(f"Files: {len(reader)}")
///
///     for filename, content in reader:
///         # Only one file's decompressed content in memory
///         process_file(content)
///
/// # Note: File handle must stay open during iteration!
/// ```
#[pyfunction]
#[pyo3(signature = (input, password=None))]
fn open_zip_stream_from_file(
    _py: Python<'_>,
    input: Bound<'_, pyo3::PyAny>,
    password: Option<String>,
) -> PyResult<ZipFileStreamReader> {
    // Seek to beginning
    input.call_method1("seek", (0i64, 0i32))?;

    // Pre-scan the archive to get file indices (excluding directories)
    let reader = stream::PyReadSeeker::new(input.clone(), None);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let total = archive.len();
    let mut file_indices = Vec::new();

    for i in 0..total {
        if let Ok(file) = archive.by_index_raw(i) {
            if !file.is_dir() {
                file_indices.push(i);
            }
        }
    }

    // Store the file handle as Py<PyAny> to keep it alive
    let file: Py<pyo3::PyAny> = input.unbind();

    Ok(ZipFileStreamReader {
        file,
        password,
        index: 0,
        file_indices,
        total,
    })
}

/// RustyZip Python module
#[pymodule]
fn rustyzip(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compress_file, m)?)?;
    m.add_function(wrap_pyfunction!(compress_files, m)?)?;
    m.add_function(wrap_pyfunction!(compress_directory, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_file, m)?)?;

    // In-memory compression functions
    m.add_function(wrap_pyfunction!(compress_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_bytes, m)?)?;

    // Streaming compression functions
    m.add_function(wrap_pyfunction!(compress_stream, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_stream, m)?)?;

    // Streaming iterator functions
    m.add_class::<ZipStreamReader>()?;
    m.add_class::<ZipFileStreamReader>()?;
    m.add_function(wrap_pyfunction!(open_zip_stream, m)?)?;
    m.add_function(wrap_pyfunction!(open_zip_stream_from_file, m)?)?;

    // pyminizip compatibility functions
    m.add_function(wrap_pyfunction!(compress, m)?)?;
    m.add_function(wrap_pyfunction!(uncompress, m)?)?;

    // Add version
    m.add("__version__", "1.0.0")?;

    Ok(())
}
