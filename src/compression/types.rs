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
    /// Indicates the archive contains files with different encryption methods.
    /// This variant is only returned by detection functions, not used for compression.
    Mixed,
}

impl EncryptionMethod {
    /// Parse encryption method from string.
    ///
    /// # Errors
    /// Returns an error if the string doesn't match a known encryption method.
    /// Note: `Mixed` cannot be parsed from a string as it's only used for detection results.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes256" | "aes" | "aes-256" => Ok(EncryptionMethod::Aes256),
            "zipcrypto" | "zip_crypto" | "legacy" => Ok(EncryptionMethod::ZipCrypto),
            "none" | "" => Ok(EncryptionMethod::None),
            _ => Err(RustyZipError::UnsupportedEncryption(s.to_string())),
        }
    }

    /// Returns true if this represents a single encryption method (not Mixed).
    /// Useful when you need to verify you can use this method for compression.
    pub fn is_single_method(&self) -> bool {
        !matches!(self, EncryptionMethod::Mixed)
    }
}

/// How to handle symbolic links during compression and decompression.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SymlinkHandling {
    /// Follow symlinks and store the target file's content (default).
    /// This is the safest option and most compatible across platforms.
    #[default]
    Follow,
    /// Preserve symlinks by storing them as symlinks in the archive.
    /// The symlink target path is stored as the file content.
    /// **Note**: Not all ZIP tools support extracting symlinks.
    Preserve,
    /// Skip symlinks entirely (don't include them in the archive).
    Skip,
}

impl SymlinkHandling {
    /// Check if symlinks should be preserved as symlinks.
    pub fn should_preserve(&self) -> bool {
        matches!(self, SymlinkHandling::Preserve)
    }

    /// Check if symlinks should be skipped.
    pub fn should_skip(&self) -> bool {
        matches!(self, SymlinkHandling::Skip)
    }

    /// Check if symlinks should be followed.
    pub fn should_follow(&self) -> bool {
        matches!(self, SymlinkHandling::Follow)
    }
}

/// Compression level (0-9)
#[derive(Debug, Clone, Copy)]
pub struct CompressionLevel(pub u32);

/// Options for directory compression operations.
///
/// This struct bundles all the parameters needed for directory compression,
/// reducing function argument count and providing a cleaner API.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::{DirectoryCompressionOptions, EncryptionMethod, CompressionLevel};
///
/// let options = DirectoryCompressionOptions::new()
///     .with_password("secret")
///     .with_encryption(EncryptionMethod::Aes256)
///     .with_compression_level(CompressionLevel::BEST)
///     .with_exclude_patterns(&["*.tmp".to_string(), "*.log".to_string()]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct DirectoryCompressionOptions<'a> {
    /// Optional password for encryption
    pub password: Option<&'a str>,
    /// Encryption method to use
    pub encryption: EncryptionMethod,
    /// Compression level (0-9)
    pub compression_level: CompressionLevel,
    /// Optional glob patterns to include
    pub include_patterns: Option<&'a [String]>,
    /// Optional glob patterns to exclude
    pub exclude_patterns: Option<&'a [String]>,
}

impl<'a> DirectoryCompressionOptions<'a> {
    /// Create new options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the password for encryption
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the encryption method
    pub fn with_encryption(mut self, encryption: EncryptionMethod) -> Self {
        self.encryption = encryption;
        self
    }

    /// Set the compression level
    pub fn with_compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Set glob patterns for files to include
    pub fn with_include_patterns(mut self, patterns: &'a [String]) -> Self {
        self.include_patterns = Some(patterns);
        self
    }

    /// Set glob patterns for files to exclude
    pub fn with_exclude_patterns(mut self, patterns: &'a [String]) -> Self {
        self.exclude_patterns = Some(patterns);
        self
    }
}

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
