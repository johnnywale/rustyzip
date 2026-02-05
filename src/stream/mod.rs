//! Stream wrappers for Python file-like objects
//!
//! This module provides adapters that allow Python file-like objects
//! (objects with read/write/seek methods) to be used with Rust's
//! std::io::Read, Write, and Seek traits.

pub mod reader;
pub mod writer;

pub use reader::{PyReadSeeker, PyReader};
pub use writer::{PyWriteSeeker, PyWriter};
