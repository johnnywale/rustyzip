//! RustyZip - A high-performance, secure file compression library
//!
//! RustyZip provides fast ZIP compression with multiple encryption methods,
//! serving as a modern replacement for pyminizip.

mod bindings;
pub mod compression;
pub mod error;
mod stream;

// Re-export for internal use
pub use compression::{CompressionLevel, EncryptionMethod};
pub use error::{Result, RustyZipError};

use pyo3::prelude::*;

/// RustyZip Python module
#[pymodule]
fn rustyzip(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // File operations
    m.add_function(wrap_pyfunction!(bindings::compress_file, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::compress_files, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::compress_directory, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::decompress_file, m)?)?;

    // Encryption detection
    m.add_function(wrap_pyfunction!(bindings::detect_encryption, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::detect_encryption_bytes, m)?)?;

    // In-memory compression functions
    m.add_function(wrap_pyfunction!(bindings::compress_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::decompress_bytes, m)?)?;

    // Streaming compression functions
    m.add_function(wrap_pyfunction!(bindings::compress_stream, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::decompress_stream, m)?)?;

    // Streaming iterator functions
    m.add_class::<bindings::ZipStreamReader>()?;
    m.add_class::<bindings::ZipFileStreamReader>()?;
    m.add_function(wrap_pyfunction!(bindings::open_zip_stream, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::open_zip_stream_from_file, m)?)?;

    // pyminizip compatibility functions
    m.add_function(wrap_pyfunction!(bindings::compress, m)?)?;
    m.add_function(wrap_pyfunction!(bindings::uncompress, m)?)?;

    // Add version
    m.add("__version__", "1.0.0")?;

    Ok(())
}
