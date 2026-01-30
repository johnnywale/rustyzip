//! Python bindings for `RustyZip`.
//!
//! This module contains all the Python-facing functions and classes.

mod compat;
pub mod exceptions;
mod file_ops;
mod inspection;
mod memory_ops;
mod modification;
mod streaming;

// Re-export all Python bindings
pub use compat::{compress, uncompress};
pub use exceptions::register_exceptions;
pub use file_ops::{
    compress_directory, compress_file, compress_files, decompress_file, detect_encryption,
    detect_encryption_bytes,
};
pub use inspection::register_inspection_functions;
pub use memory_ops::{compress_bytes, decompress_bytes};
pub use modification::register_modification_functions;
pub use streaming::{
    compress_stream, decompress_stream, open_zip_stream, open_zip_stream_from_file,
    ZipFileStreamReader, ZipStreamReader,
};
