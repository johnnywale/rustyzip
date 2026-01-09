use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use thiserror::Error;

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

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("Pattern error: {0}")]
    PatternError(String),

    #[error("Walk directory error: {0}")]
    WalkDirError(#[from] walkdir::Error),
}

impl From<RustyZipError> for PyErr {
    fn from(err: RustyZipError) -> PyErr {
        match &err {
            RustyZipError::Io(_) => PyIOError::new_err(err.to_string()),
            RustyZipError::Zip(_) => PyIOError::new_err(err.to_string()),
            RustyZipError::FileNotFound(_) => PyIOError::new_err(err.to_string()),
            RustyZipError::InvalidPassword => PyValueError::new_err(err.to_string()),
            RustyZipError::UnsupportedEncryption(_) => PyValueError::new_err(err.to_string()),
            RustyZipError::InvalidPath(_) => PyValueError::new_err(err.to_string()),
            RustyZipError::CompressionFailed(_) => PyIOError::new_err(err.to_string()),
            RustyZipError::DecompressionFailed(_) => PyIOError::new_err(err.to_string()),
            RustyZipError::PatternError(_) => PyValueError::new_err(err.to_string()),
            RustyZipError::WalkDirError(_) => PyIOError::new_err(err.to_string()),
        }
    }
}

impl From<glob::PatternError> for RustyZipError {
    fn from(err: glob::PatternError) -> Self {
        RustyZipError::PatternError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RustyZipError>;
