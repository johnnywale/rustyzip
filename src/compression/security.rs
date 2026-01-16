//! Security-related validation and protection.
//!
//! This module provides path traversal protection, ZIP bomb detection,
//! and secure password handling.

use crate::error::{Result, RustyZipError};
use glob::Pattern;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default maximum decompressed size (2 GB)
/// This limit prevents ZIP bomb attacks that could exhaust disk/memory
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Default maximum compression ratio (500x)
/// Ratios above 500x are suspicious and may indicate a ZIP bomb
/// Note: Highly compressible data (e.g., repeated text) can legitimately reach 100-200x
pub const DEFAULT_MAX_COMPRESSION_RATIO: u64 = 500;

/// Default maximum number of threads for parallel operations
/// Set to 0 to use all available physical cores
pub const DEFAULT_MAX_THREADS: usize = 0;

/// Secure password wrapper that zeroes memory on drop.
///
/// This ensures that password data doesn't linger in memory after use,
/// reducing the risk of password exposure through memory dumps or side-channel attacks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Password(String);

impl Password {
    /// Create a new Password from a string
    pub fn new(password: impl Into<String>) -> Self {
        Password(password.into())
    }

    /// Get a reference to the password string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get password as bytes for encryption operations
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for Password {
    fn from(s: String) -> Self {
        Password::new(s)
    }
}

impl From<&str> for Password {
    fn from(s: &str) -> Self {
        Password::new(s)
    }
}

/// Security policy configuration for decompression operations.
///
/// This struct centralizes all security thresholds and settings,
/// allowing users to customize protection levels while maintaining
/// secure defaults.
///
/// # Example
/// ```rust
/// use rustyzip::compression::SecurityPolicy;
///
/// // Use secure defaults
/// let default_policy = SecurityPolicy::default();
///
/// // Or customize for specific needs
/// let custom_policy = SecurityPolicy::new()
///     .with_max_size(4 * 1024 * 1024 * 1024)  // 4 GB
///     .with_max_ratio(1000)                    // Allow higher compression
///     .with_allow_symlinks(false);             // Keep symlinks blocked
/// ```
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Maximum total decompressed size in bytes (default: 2 GB)
    /// Set to 0 to disable size checking
    pub max_decompressed_size: u64,

    /// Maximum allowed compression ratio (default: 500)
    /// Set to 0 to disable ratio checking
    pub max_compression_ratio: u64,

    /// Whether to allow extracting symbolic links (default: false)
    /// When false, symlinks in archives are skipped for safety
    pub allow_symlinks: bool,

    /// Optional extraction boundary directory
    /// When set, all extracted files must stay within this directory
    pub sandbox_root: Option<PathBuf>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
            allow_symlinks: false,
            sandbox_root: None,
        }
    }
}

impl SecurityPolicy {
    /// Create a new SecurityPolicy with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive policy with no limits (use with caution!)
    pub fn permissive() -> Self {
        Self {
            max_decompressed_size: 0, // Disabled
            max_compression_ratio: 0, // Disabled
            allow_symlinks: true,
            sandbox_root: None,
        }
    }

    /// Set the maximum decompressed size
    /// Set to 0 to disable size checking
    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_decompressed_size = size;
        self
    }

    /// Set the maximum compression ratio
    /// Set to 0 to disable ratio checking
    pub fn with_max_ratio(mut self, ratio: u64) -> Self {
        self.max_compression_ratio = ratio;
        self
    }

    /// Set whether to allow symlinks
    pub fn with_allow_symlinks(mut self, allow: bool) -> Self {
        self.allow_symlinks = allow;
        self
    }

    /// Set the sandbox root directory
    pub fn with_sandbox_root(mut self, root: Option<PathBuf>) -> Self {
        self.sandbox_root = root;
        self
    }

    /// Check if size limit is enabled
    pub fn size_limit_enabled(&self) -> bool {
        self.max_decompressed_size > 0
    }

    /// Check if ratio limit is enabled
    pub fn ratio_limit_enabled(&self) -> bool {
        self.max_compression_ratio > 0
    }
}

/// Check if a file should be included based on include/exclude patterns
pub fn should_include_file(
    path: &Path,
    relative_path: &str,
    include_patterns: Option<&Vec<Pattern>>,
    exclude_patterns: Option<&Vec<Pattern>>,
) -> bool {
    // Check include patterns - file must match at least one
    if let Some(patterns) = include_patterns {
        let matches_relative = patterns.iter().any(|p| p.matches(relative_path));
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let matches_filename = patterns.iter().any(|p| p.matches(file_name));
        if !matches_relative && !matches_filename {
            return false;
        }
    }

    // Check exclude patterns - file must not match any
    if let Some(patterns) = exclude_patterns {
        // Check relative path
        if patterns.iter().any(|p| p.matches(relative_path)) {
            return false;
        }
        // Check filename
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if patterns.iter().any(|p| p.matches(file_name)) {
            return false;
        }
        // Check if any parent directory matches exclude pattern
        let ancestor_matches = path.ancestors().any(|ancestor| {
            ancestor
                .file_name()
                .and_then(|n| n.to_str())
                .map(|name| patterns.iter().any(|p| p.matches(name)))
                .unwrap_or(false)
        });
        if ancestor_matches {
            return false;
        }
    }

    true
}

/// Validate that a path is safe and doesn't escape the output directory
///
/// This function implements multiple layers of path traversal protection:
/// 1. Rejects paths with ".." components
/// 2. Checks for null bytes and dangerous characters
/// 3. Normalizes and verifies the final path stays within bounds
/// 4. Uses canonicalize() when possible for symlink resolution
pub fn validate_output_path(output_base: &Path, target_path: &Path) -> Result<()> {
    // Canonicalize the output base (create if needed for canonicalization)
    let canonical_base = if output_base.exists() {
        output_base.canonicalize()?
    } else {
        // For non-existent paths, we need to find the existing ancestor
        let mut existing = output_base.to_path_buf();
        while !existing.exists() && existing.parent().is_some() {
            existing = existing.parent().unwrap().to_path_buf();
        }
        if existing.exists() {
            let canonical_existing = existing.canonicalize()?;
            let remaining = output_base.strip_prefix(&existing).unwrap_or(Path::new(""));
            canonical_existing.join(remaining)
        } else {
            output_base.to_path_buf()
        }
    };

    // Check if target path escapes the output directory
    // We need to check the target path components for any ".." that could escape
    for component in target_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(RustyZipError::PathTraversal(format!(
                    "Parent directory reference (..) in path: {}",
                    target_path.display()
                )));
            }
            std::path::Component::Normal(name) => {
                if let Some(name_str) = name.to_str() {
                    // Check for null bytes
                    if name_str.contains('\0') {
                        return Err(RustyZipError::PathTraversal(format!(
                            "Null byte in path: {}",
                            target_path.display()
                        )));
                    }
                    // Check for other dangerous patterns (Windows-specific)
                    #[cfg(windows)]
                    {
                        // Check for reserved device names on Windows
                        let upper = name_str.to_uppercase();
                        let reserved = [
                            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
                            "LPT6", "LPT7", "LPT8", "LPT9",
                        ];
                        let base_name = upper.split('.').next().unwrap_or("");
                        if reserved.contains(&base_name) {
                            return Err(RustyZipError::PathTraversal(format!(
                                "Reserved device name in path: {}",
                                target_path.display()
                            )));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Build and normalize the full path
    let full_path = canonical_base.join(target_path);

    // Normalize the path by resolving . and ..
    let mut normalized = std::path::PathBuf::new();
    for component in full_path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            c => normalized.push(c),
        }
    }

    // Primary security check: ensure normalized path starts with canonical base
    if !normalized.starts_with(&canonical_base) {
        return Err(RustyZipError::PathTraversal(format!(
            "Path escapes output directory: {}",
            target_path.display()
        )));
    }

    // Additional check: if the full path exists, canonicalize and verify again
    // This catches symlink attacks where a file could point outside the directory
    if full_path.exists() {
        if let Ok(canonical_full) = full_path.canonicalize() {
            if !canonical_full.starts_with(&canonical_base) {
                return Err(RustyZipError::PathTraversal(format!(
                    "Symlink escapes output directory: {}",
                    target_path.display()
                )));
            }
        }
    }

    Ok(())
}
