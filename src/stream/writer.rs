//! Python writer adapters for Rust's Write trait.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::io::{self, Seek, SeekFrom, Write};

/// A wrapper that implements Rust's Write trait for Python file-like objects.
///
/// This allows any Python object with a `write(data)` method to be used
/// as a Rust writer, enabling streaming writes without buffering all data in memory.
pub struct PyWriter<'py> {
    pub(super) file: Bound<'py, PyAny>,
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
