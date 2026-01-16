//! Python reader adapters for Rust's Read trait.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::io::{self, Read, Seek, SeekFrom};

/// A wrapper that implements Rust's Read trait for Python file-like objects.
///
/// This allows any Python object with a `read(size)` method to be used
/// as a Rust reader, enabling streaming reads without loading all data into memory.
pub struct PyReader<'py> {
    pub(super) file: Bound<'py, PyAny>,
    buffer_size: usize,
}

impl<'py> PyReader<'py> {
    /// Create a new PyReader wrapping a Python file-like object.
    ///
    /// # Arguments
    /// * `file` - A Python object with a `read(size)` method
    /// * `buffer_size` - The chunk size for reading (default 64KB)
    pub fn new(file: Bound<'py, PyAny>, buffer_size: Option<usize>) -> Self {
        Self {
            file,
            buffer_size: buffer_size.unwrap_or(64 * 1024), // 64KB default
        }
    }
}

impl Read for PyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read_size = buf.len().min(self.buffer_size);

        // Call Python's read(size) method
        let result = self
            .file
            .call_method1("read", (read_size,))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Try to cast to PyBytes first for zero-copy access
        #[allow(deprecated)] // downcast is deprecated but cast() has different semantics
        if let Ok(py_bytes) = result.downcast::<PyBytes>() {
            let bytes = py_bytes.as_bytes();
            let bytes_read = bytes.len();

            if bytes_read > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Python read returned more bytes than requested",
                ));
            }

            buf[..bytes_read].copy_from_slice(bytes);
            return Ok(bytes_read);
        }

        // Fallback: extract as Vec<u8> (for memoryview or other types)
        let bytes: Vec<u8> = result
            .extract()
            .map_err(|e: pyo3::PyErr| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let bytes_read = bytes.len();
        if bytes_read > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Python read returned more bytes than requested",
            ));
        }

        buf[..bytes_read].copy_from_slice(&bytes);
        Ok(bytes_read)
    }
}

/// A wrapper that implements Rust's Read + Seek traits for Python file-like objects.
///
/// This is needed for ZIP reading which requires seeking.
pub struct PyReadSeeker<'py> {
    reader: PyReader<'py>,
}

impl<'py> PyReadSeeker<'py> {
    /// Create a new PyReadSeeker wrapping a Python file-like object.
    ///
    /// # Arguments
    /// * `file` - A Python object with `read(size)` and `seek(pos, whence)` methods
    /// * `buffer_size` - The chunk size for reading (default 64KB)
    pub fn new(file: Bound<'py, PyAny>, buffer_size: Option<usize>) -> Self {
        Self {
            reader: PyReader::new(file, buffer_size),
        }
    }
}

impl Read for PyReadSeeker<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Seek for PyReadSeeker<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (n as i64, 0),
            SeekFrom::Current(n) => (n, 1),
            SeekFrom::End(n) => (n, 2),
        };

        let result = self
            .reader
            .file
            .call_method1("seek", (offset, whence))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let new_pos: u64 = result
            .extract()
            .map_err(|e: pyo3::PyErr| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(new_pos)
    }
}
