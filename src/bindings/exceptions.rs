//! Custom Python exceptions for RustyZip.
//!
//! This module defines custom exception classes that are exposed to Python,
//! allowing Python code to catch specific error types.

use pyo3::prelude::*;
use pyo3::{create_exception, exceptions::PyException};

use crate::error::RustyZipError;

// =============================================================================
// Error Code Enum
// =============================================================================

/// Error codes that identify the type of error that occurred.
///
/// Python code can check this enum to understand what went wrong:
/// ```python
/// from rustyzipper import ErrorCode
/// try:
///     decompress_file("archive.zip", "output/")
/// except RustyZipError as e:
///     if e.code == ErrorCode.INVALID_PASSWORD:
///         print("Wrong password!")
///     elif e.code == ErrorCode.ZIP_BOMB_DETECTED:
///         print("ZIP bomb detected!")
/// ```
#[pyclass(module = "rustyzip", eq, eq_int)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Generic IO error
    IoError = 1,
    /// ZIP format error
    ZipError = 2,
    /// Invalid or wrong password
    InvalidPassword = 3,
    /// Unsupported encryption method
    UnsupportedEncryption = 4,
    /// File not found
    FileNotFound = 5,
    /// Invalid file path
    InvalidPath = 6,
    /// Glob pattern error
    PatternError = 7,
    /// Directory traversal error
    WalkDirError = 8,
    /// Path traversal attack detected
    PathTraversal = 9,
    /// ZIP bomb detected (size limit exceeded)
    ZipBombDetected = 10,
    /// Suspicious compression ratio
    SuspiciousRatio = 11,
    /// Compression failed
    CompressionFailed = 12,
    /// Decompression failed
    DecompressionFailed = 13,
    /// Symlink not allowed
    SymlinkNotAllowed = 14,
    /// Unknown error
    Unknown = 99,
}

#[pymethods]
impl ErrorCode {
    /// Get a human-readable description of the error code.
    fn description(&self) -> &'static str {
        match self {
            ErrorCode::IoError => "IO operation failed",
            ErrorCode::ZipError => "ZIP format error",
            ErrorCode::InvalidPassword => "Invalid or incorrect password",
            ErrorCode::UnsupportedEncryption => "Unsupported encryption method",
            ErrorCode::FileNotFound => "File not found",
            ErrorCode::InvalidPath => "Invalid file path",
            ErrorCode::PatternError => "Invalid glob pattern",
            ErrorCode::WalkDirError => "Directory traversal failed",
            ErrorCode::PathTraversal => "Path traversal attack detected",
            ErrorCode::ZipBombDetected => "ZIP bomb detected - size limit exceeded",
            ErrorCode::SuspiciousRatio => "Suspicious compression ratio detected",
            ErrorCode::CompressionFailed => "Compression operation failed",
            ErrorCode::DecompressionFailed => "Decompression operation failed",
            ErrorCode::SymlinkNotAllowed => "Symlink extraction not allowed",
            ErrorCode::Unknown => "Unknown error",
        }
    }

    fn __repr__(&self) -> String {
        format!("ErrorCode.{:?}", self)
    }

    fn __str__(&self) -> &'static str {
        self.description()
    }
}

impl From<&RustyZipError> for ErrorCode {
    fn from(err: &RustyZipError) -> Self {
        match err {
            RustyZipError::Io(_) => ErrorCode::IoError,
            RustyZipError::Zip(_) => ErrorCode::ZipError,
            RustyZipError::InvalidPassword => ErrorCode::InvalidPassword,
            RustyZipError::UnsupportedEncryption(_) => ErrorCode::UnsupportedEncryption,
            RustyZipError::FileNotFound(_) => ErrorCode::FileNotFound,
            RustyZipError::InvalidPath(_) => ErrorCode::InvalidPath,
            RustyZipError::PatternError(_) => ErrorCode::PatternError,
            RustyZipError::WalkDirError(_) => ErrorCode::WalkDirError,
            RustyZipError::PathTraversal(_) => ErrorCode::PathTraversal,
            RustyZipError::ZipBomb(_, _) => ErrorCode::ZipBombDetected,
            RustyZipError::SuspiciousCompressionRatio(_, _) => ErrorCode::SuspiciousRatio,
        }
    }
}

// =============================================================================
// Custom Exception Classes
// =============================================================================

// Base exception for all RustyZip errors
create_exception!(rustyzip, RustyZipException, PyException);

// Specific exception types
create_exception!(rustyzip, CompressionException, RustyZipException);
create_exception!(rustyzip, DecompressionException, RustyZipException);
create_exception!(rustyzip, InvalidPasswordException, RustyZipException);
create_exception!(rustyzip, FileNotFoundException, RustyZipException);
create_exception!(rustyzip, UnsupportedEncryptionException, RustyZipException);
create_exception!(rustyzip, PathTraversalException, RustyZipException);
create_exception!(rustyzip, ZipBombException, RustyZipException);
create_exception!(rustyzip, SecurityException, RustyZipException);

// =============================================================================
// Error Conversion
// =============================================================================

/// Convert RustyZipError to a PyErr with the appropriate exception type.
///
/// This creates exceptions with additional attributes:
/// - `code`: ErrorCode enum value
/// - `message`: Human-readable error message
pub fn to_py_err(err: RustyZipError) -> PyErr {
    let code = ErrorCode::from(&err);
    let message = err.to_string();

    match err {
        RustyZipError::InvalidPassword => {
            InvalidPasswordException::new_err((message, code as i32))
        }
        RustyZipError::FileNotFound(_) => {
            FileNotFoundException::new_err((message, code as i32))
        }
        RustyZipError::UnsupportedEncryption(_) => {
            UnsupportedEncryptionException::new_err((message, code as i32))
        }
        RustyZipError::PathTraversal(_) => {
            PathTraversalException::new_err((message, code as i32))
        }
        RustyZipError::ZipBomb(_, _) | RustyZipError::SuspiciousCompressionRatio(_, _) => {
            ZipBombException::new_err((message, code as i32))
        }
        RustyZipError::Io(_)
        | RustyZipError::Zip(_)
        | RustyZipError::InvalidPath(_)
        | RustyZipError::PatternError(_)
        | RustyZipError::WalkDirError(_) => RustyZipException::new_err((message, code as i32)),
    }
}

/// Register exception classes with the Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add ErrorCode enum
    m.add_class::<ErrorCode>()?;

    // Add exception classes
    m.add("RustyZipException", m.py().get_type::<RustyZipException>())?;
    m.add(
        "CompressionException",
        m.py().get_type::<CompressionException>(),
    )?;
    m.add(
        "DecompressionException",
        m.py().get_type::<DecompressionException>(),
    )?;
    m.add(
        "InvalidPasswordException",
        m.py().get_type::<InvalidPasswordException>(),
    )?;
    m.add(
        "FileNotFoundException",
        m.py().get_type::<FileNotFoundException>(),
    )?;
    m.add(
        "UnsupportedEncryptionException",
        m.py().get_type::<UnsupportedEncryptionException>(),
    )?;
    m.add(
        "PathTraversalException",
        m.py().get_type::<PathTraversalException>(),
    )?;
    m.add("ZipBombException", m.py().get_type::<ZipBombException>())?;
    m.add(
        "SecurityException",
        m.py().get_type::<SecurityException>(),
    )?;

    Ok(())
}
