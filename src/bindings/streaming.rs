//! Streaming compression/decompression Python functions and classes.

use crate::compression::{CompressionLevel, EncryptionMethod};
use crate::stream;
use log::warn;
use pyo3::prelude::*;
use std::io::{Cursor, Read};
use zip::ZipArchive;

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
pub fn compress_stream(
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
        warn!(
            "ZipCrypto encryption is weak and can be cracked. \
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
    crate::compression::compress_stream(
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
/// * `max_size` - Maximum total decompressed size in bytes. Default is 2GB. Set to 0 to disable.
/// * `max_ratio` - Maximum compression ratio allowed. Default is 500. Set to 0 to disable.
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
#[pyo3(signature = (input, password=None, max_size=None, max_ratio=None))]
pub fn decompress_stream(
    _py: Python<'_>,
    input: Bound<'_, pyo3::PyAny>,
    password: Option<&str>,
    max_size: Option<u64>,
    max_ratio: Option<u64>,
) -> PyResult<Vec<(String, Vec<u8>)>> {
    use crate::compression::{DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE};

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

    let reader = stream::PyReadSeeker::new(input, None);

    let result = crate::compression::decompress_stream_to_vec_with_limits(
        reader,
        password,
        effective_max_size,
        effective_max_ratio,
    )?;
    Ok(result)
}

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
pub struct ZipStreamReader {
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
            Some(pwd) => match archive.by_index_decrypt(file_idx, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(pyo3::exceptions::PyValueError::new_err("Invalid password"));
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                }
            },
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
            .filter_map(|i| archive.name_for_index(i).map(|s| s.to_string()))
            .collect();

        Ok(names)
    }

    /// Extract a specific file by name
    fn read(&self, name: &str) -> PyResult<Vec<u8>> {
        let cursor = Cursor::new(&self.data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

        let mut file = match &self.password {
            Some(pwd) => match archive.by_name_decrypt(name, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(pyo3::exceptions::PyValueError::new_err("Invalid password"));
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                }
            },
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
pub fn open_zip_stream(data: Vec<u8>, password: Option<String>) -> PyResult<ZipStreamReader> {
    // Pre-scan the archive to get file indices (excluding directories)
    let cursor = Cursor::new(&data);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

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
pub struct ZipFileStreamReader {
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
    fn __next__(
        mut slf: PyRefMut<'_, Self>,
        py: Python<'_>,
    ) -> PyResult<Option<(String, Vec<u8>)>> {
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
            Some(pwd) => match archive.by_index_decrypt(file_idx, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(pyo3::exceptions::PyValueError::new_err("Invalid password"));
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                }
            },
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
            Some(pwd) => match archive.by_name_decrypt(name, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(pyo3::exceptions::PyValueError::new_err("Invalid password"));
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyIOError::new_err(e.to_string()));
                }
            },
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
pub fn open_zip_stream_from_file(
    _py: Python<'_>,
    input: Bound<'_, pyo3::PyAny>,
    password: Option<String>,
) -> PyResult<ZipFileStreamReader> {
    // Seek to beginning
    input.call_method1("seek", (0i64, 0i32))?;

    // Pre-scan the archive to get file indices (excluding directories)
    let reader = stream::PyReadSeeker::new(input.clone(), None);
    let mut archive =
        ZipArchive::new(reader).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

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
