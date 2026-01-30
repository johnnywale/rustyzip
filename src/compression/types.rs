//! Core type definitions for compression settings.

use crate::error::{Result, RustyZipError};

/// Encryption method for password-protected archives
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum EncryptionMethod {
    /// AES-256 encryption (strong, requires 7-Zip/WinRAR to open)
    #[default]
    Aes256,
    /// ZipCrypto encryption (weak, Windows Explorer compatible)
    ZipCrypto,
    /// No encryption
    None,
}

impl EncryptionMethod {
    /// Parse encryption method from string.
    ///
    /// # Errors
    /// Returns an error if the string doesn't match a known encryption method.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes256" | "aes" | "aes-256" => Ok(EncryptionMethod::Aes256),
            "zipcrypto" | "zip_crypto" | "legacy" => Ok(EncryptionMethod::ZipCrypto),
            "none" | "" => Ok(EncryptionMethod::None),
            _ => Err(RustyZipError::UnsupportedEncryption(s.to_string())),
        }
    }
}

/// Compression level (0-9)
#[derive(Debug, Clone, Copy)]
pub struct CompressionLevel(pub u32);

impl Default for CompressionLevel {
    fn default() -> Self {
        CompressionLevel::DEFAULT
    }
}

impl CompressionLevel {
    #[allow(dead_code)]
    pub const STORE: CompressionLevel = CompressionLevel(0);
    #[allow(dead_code)]
    pub const FAST: CompressionLevel = CompressionLevel(1);
    #[allow(dead_code)]
    pub const DEFAULT: CompressionLevel = CompressionLevel(6);
    #[allow(dead_code)]
    pub const BEST: CompressionLevel = CompressionLevel(9);

    pub fn new(level: u32) -> Self {
        CompressionLevel(level.min(9))
    }

    #[allow(dead_code)]
    pub fn to_flate2_compression(self) -> flate2::Compression {
        flate2::Compression::new(self.0)
    }
}
