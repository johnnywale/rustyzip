//! Python bindings for RustyZip.
//!
//! This module contains all the Python-facing functions and classes.

mod compat;
mod file_ops;
mod memory_ops;
mod streaming;

// Re-export all Python bindings
pub use compat::{compress, uncompress};
pub use file_ops::{compress_directory, compress_file, compress_files, decompress_file};
pub use memory_ops::{compress_bytes, decompress_bytes};
pub use streaming::{
    compress_stream, decompress_stream, open_zip_stream, open_zip_stream_from_file,
    ZipFileStreamReader, ZipStreamReader,
};
