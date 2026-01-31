use pyo3::prelude::*;
use thiserror::Error;

use crate::bindings::exceptions::to_py_err;

/// Custom error types for RustyZip operations
#[derive(Debug, Error)]
pub enum RustyZipError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Unsupported encryption method: {0}")]
    UnsupportedEncryption(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Invalid path error with descriptive context
    /// Error messages should include:
    /// - The problematic path
    /// - The reason (UTF-8 encoding, illegal characters, missing filename, etc.)
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Pattern error: {0}")]
    PatternError(String),

    #[error("Walk directory error: {0}")]
    WalkDirError(#[from] walkdir::Error),

    #[error("Path traversal attempt detected: {0}")]
    PathTraversal(String),

    #[error("ZIP bomb detected: decompressed size ({0} bytes) exceeds limit ({1} bytes)")]
    ZipBomb(u64, u64),

    #[error("Suspicious compression ratio detected: {0}x (limit: {1}x)")]
    SuspiciousCompressionRatio(u64, u64),

    #[error("Symlink not allowed: {0}")]
    SymlinkNotAllowed(String),
}

impl From<RustyZipError> for PyErr {
    fn from(err: RustyZipError) -> PyErr {
        to_py_err(err)
    }
}

impl From<glob::PatternError> for RustyZipError {
    fn from(err: glob::PatternError) -> Self {
        RustyZipError::PatternError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RustyZipError>;
