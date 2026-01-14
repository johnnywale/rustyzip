//! Stream wrappers for Python file-like objects
//!
//! This module provides adapters that allow Python file-like objects
//! (objects with read/write/seek methods) to be used with Rust's
//! std::io::Read, Write, and Seek traits.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::io::{self, Read, Seek, SeekFrom, Write};

// Note: PyBytes is still used in PyWriter::write()

/// A wrapper that implements Rust's Read trait for Python file-like objects.
///
/// This allows any Python object with a `read(size)` method to be used
/// as a Rust reader, enabling streaming reads without loading all data into memory.
pub struct PyReader<'py> {
    file: Bound<'py, PyAny>,
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

/// A wrapper that implements Rust's Write trait for Python file-like objects.
///
/// This allows any Python object with a `write(data)` method to be used
/// as a Rust writer, enabling streaming writes without buffering all data in memory.
pub struct PyWriter<'py> {
    file: Bound<'py, PyAny>,
}

impl<'py> PyWriter<'py> {
    /// Create a new PyWriter wrapping a Python file-like object.
    ///
    /// # Arguments
    /// * `file` - A Python object with a `write(data)` method
    pub fn new(file: Bound<'py, PyAny>) -> Self {
        Self { file }
    }
}

impl Write for PyWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Create Python bytes from the buffer
        let py = self.file.py();
        let py_bytes = PyBytes::new(py, buf);

        // Call Python's write(data) method
        let result = self
            .file
            .call_method1("write", (py_bytes,))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Get number of bytes written (Python's write returns the count)
        let bytes_written: usize = result
            .extract()
            .map_err(|e: pyo3::PyErr| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Call Python's flush() method if it exists
        if self.file.hasattr("flush").unwrap_or(false) {
            self.file
                .call_method0("flush")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        Ok(())
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

/// A wrapper that implements Rust's Write + Seek traits for Python file-like objects.
///
/// This is needed for ZIP writing which requires seeking.
pub struct PyWriteSeeker<'py> {
    writer: PyWriter<'py>,
}

impl<'py> PyWriteSeeker<'py> {
    /// Create a new PyWriteSeeker wrapping a Python file-like object.
    ///
    /// # Arguments
    /// * `file` - A Python object with `write(data)` and `seek(pos, whence)` methods
    pub fn new(file: Bound<'py, PyAny>) -> Self {
        Self {
            writer: PyWriter::new(file),
        }
    }
}

impl Write for PyWriteSeeker<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Seek for PyWriteSeeker<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (n as i64, 0),
            SeekFrom::Current(n) => (n, 1),
            SeekFrom::End(n) => (n, 2),
        };

        let result = self
            .writer
            .file
            .call_method1("seek", (offset, whence))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let new_pos: u64 = result
            .extract()
            .map_err(|e: pyo3::PyErr| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(new_pos)
    }
}
