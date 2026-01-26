//! Compression module for RustyZip
//!
//! This module provides all compression and decompression functionality.

mod decompression;
mod security;
mod sequential;
mod streaming;
mod types;
mod utils;

#[cfg(feature = "parallel")]
mod parallel;

#[cfg(test)]
mod tests;

// Re-export public types
pub use types::{CompressionLevel, EncryptionMethod};

// Re-export security types, constants and functions
pub use security::{
    should_include_file, validate_output_path, Password, SecurityPolicy,
    DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX_THREADS,
};

// Re-export compression functions
pub use sequential::{compress_bytes, compress_file};

#[cfg(feature = "parallel")]
pub use parallel::PARALLEL_FILE_SIZE_THRESHOLD;

// Re-export decompression functions
pub use decompression::{
    decompress_bytes, decompress_bytes_with_limits, decompress_file, decompress_file_with_limits,
    delete_file, detect_encryption, detect_encryption_bytes,
};

// Re-export streaming functions
pub use streaming::{
    compress_stream, decompress_stream_to_vec, decompress_stream_to_vec_with_limits,
};

// Re-export utility functions needed by other modules
pub(crate) use utils::system_time_to_zip_datetime;

/// Compress multiple files to a ZIP archive
///
/// When compiled with the `parallel` feature (default), this function
/// automatically uses parallel processing for improved performance.
pub fn compress_files(
    input_paths: &[&std::path::Path],
    prefixes: &[Option<&str>],
    output_path: &std::path::Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> crate::error::Result<()> {
    // Use parallel implementation when feature is enabled
    #[cfg(feature = "parallel")]
    {
        parallel::compress_files_parallel(
            input_paths,
            prefixes,
            output_path,
            password,
            encryption,
            compression_level,
        )
    }

    #[cfg(not(feature = "parallel"))]
    {
        sequential::compress_files_sequential(
            input_paths,
            prefixes,
            output_path,
            password,
            encryption,
            compression_level,
        )
    }
}

/// Compress a directory to a ZIP archive
///
/// When compiled with the `parallel` feature (default), this function
/// automatically uses parallel processing for improved performance.
pub fn compress_directory(
    input_dir: &std::path::Path,
    output_path: &std::path::Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    include_patterns: Option<&[String]>,
    exclude_patterns: Option<&[String]>,
) -> crate::error::Result<()> {
    // Use parallel implementation when feature is enabled
    #[cfg(feature = "parallel")]
    {
        parallel::compress_directory_parallel(
            input_dir,
            output_path,
            password,
            encryption,
            compression_level,
            include_patterns,
            exclude_patterns,
        )
    }

    #[cfg(not(feature = "parallel"))]
    {
        sequential::compress_directory_sequential(
            input_dir,
            output_path,
            password,
            encryption,
            compression_level,
            include_patterns,
            exclude_patterns,
        )
    }
}
