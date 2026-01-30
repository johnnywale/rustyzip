//! Security-related validation and protection.
//!
//! This module provides path traversal protection, ZIP bomb detection,
//! and secure password handling.

use crate::error::{Result, RustyZipError};
use glob::Pattern;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canonicalize a path, removing the Windows `\\?\` prefix if present.
/// This wrapper uses the `dunce` crate which handles cross-platform
/// path canonicalization correctly.
fn safe_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    dunce::canonicalize(path)
}

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

/// Default maximum archive size for modification operations (100 MB)
/// This limit prevents memory exhaustion when loading archives for modification
pub const DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION: u64 = 100 * 1024 * 1024;

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

/// Security policy configuration for compression and decompression operations.
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
///     .with_allow_symlinks(false)              // Keep symlinks blocked
///     .with_max_modification_size(200 * 1024 * 1024); // 200 MB for modification
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

    // === Modification-specific settings ===
    /// Maximum archive size that can be loaded for modification (default: 100 MB)
    /// This prevents memory exhaustion when modifying archives.
    /// Set to 0 to disable size checking (use with caution!)
    pub max_archive_size_for_modification: u64,

    /// Whether to allow adding symlinks to archives (default: false)
    /// When false, attempting to add a symlink will return an error.
    /// This prevents Arbitrary File Read attacks where an attacker creates
    /// a symlink pointing to sensitive files like /etc/passwd.
    pub allow_symlinks_in_input: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
            allow_symlinks: false,
            sandbox_root: None,
            max_archive_size_for_modification: DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION,
            allow_symlinks_in_input: false,
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
            max_archive_size_for_modification: 0, // Disabled
            allow_symlinks_in_input: true,
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

    // === Modification-specific methods ===

    /// Set the maximum archive size for modification operations
    /// Set to 0 to disable size checking (use with caution!)
    pub fn with_max_modification_size(mut self, size: u64) -> Self {
        self.max_archive_size_for_modification = size;
        self
    }

    /// Set whether to allow adding symlinks to archives
    pub fn with_allow_symlinks_in_input(mut self, allow: bool) -> Self {
        self.allow_symlinks_in_input = allow;
        self
    }

    /// Check if modification size limit is enabled
    pub fn modification_size_limit_enabled(&self) -> bool {
        self.max_archive_size_for_modification > 0
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

/// Characters that are reserved on Windows and cannot be used in filenames.
pub const WINDOWS_RESERVED_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Device names that are reserved on Windows and cannot be used as filenames.
pub const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate an archive entry name to prevent path traversal attacks and ensure
/// cross-platform compatibility.
///
/// This function rejects names that could be used for Zip Slip attacks or cause
/// issues on different operating systems:
/// - Empty names
/// - Names containing null bytes or control characters (ASCII 0-31)
/// - Names containing Windows reserved characters (`<>:"|?*`)
/// - Absolute paths (starting with "/" or "C:\")
/// - Names containing ".." path components
/// - Names containing Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
///
/// # Arguments
/// * `name` - The archive entry name to validate
///
/// # Returns
/// Ok(()) if the name is safe, or an error if it's potentially malicious or problematic
///
/// # Example
/// ```rust,ignore
/// use rustyzip::compression::security::validate_archive_entry_name;
///
/// // Safe names
/// assert!(validate_archive_entry_name("file.txt").is_ok());
/// assert!(validate_archive_entry_name("subdir/file.txt").is_ok());
///
/// // Rejected names
/// assert!(validate_archive_entry_name("../etc/passwd").is_err());  // Path traversal
/// assert!(validate_archive_entry_name("CON.txt").is_err());        // Windows reserved
/// assert!(validate_archive_entry_name("file\nname").is_err());     // Control char
/// ```
pub fn validate_archive_entry_name(name: &str) -> Result<()> {
    // Reject empty names
    if name.is_empty() {
        return Err(RustyZipError::PathTraversal(
            "Empty archive name".to_string(),
        ));
    }

    // Reject null bytes and control characters (ASCII 0-31)
    for c in name.chars() {
        if c == '\0' {
            return Err(RustyZipError::PathTraversal(format!(
                "Null byte in archive name: {}",
                name.replace('\0', "\\0")
            )));
        }
        if c.is_ascii_control() {
            return Err(RustyZipError::InvalidPath(format!(
                "Archive name contains control character (0x{:02X}): {}",
                c as u32,
                name.replace(c, &format!("\\x{:02X}", c as u32))
            )));
        }
    }

    // Reject Windows reserved characters for cross-platform compatibility
    if let Some(c) = name.chars().find(|c| WINDOWS_RESERVED_CHARS.contains(c)) {
        return Err(RustyZipError::InvalidPath(format!(
            "Archive name contains reserved character '{}': {}",
            c, name
        )));
    }

    // Reject absolute paths
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(RustyZipError::PathTraversal(format!(
            "Absolute path in archive name: {}",
            name
        )));
    }

    // Reject Windows absolute paths (e.g., "C:\...")
    if name.len() >= 2 && name.chars().nth(1) == Some(':') {
        return Err(RustyZipError::PathTraversal(format!(
            "Absolute path in archive name: {}",
            name
        )));
    }

    // Check each path component for ".." and Windows reserved device names
    // Handle both Unix and Windows path separators
    let normalized = name.replace('\\', "/");
    for component in normalized.split('/') {
        if component == ".." {
            return Err(RustyZipError::PathTraversal(format!(
                "Parent directory reference (..) in archive name: {}",
                name
            )));
        }

        // Check for Windows reserved device names (case-insensitive)
        // These can appear with or without extensions (e.g., "CON" or "CON.txt")
        let base_name = component.split('.').next().unwrap_or("");
        if WINDOWS_RESERVED_NAMES
            .iter()
            .any(|reserved| base_name.eq_ignore_ascii_case(reserved))
        {
            return Err(RustyZipError::InvalidPath(format!(
                "Archive name contains Windows reserved device name '{}': {}",
                component, name
            )));
        }
    }

    Ok(())
}

/// Validate that a path is safe and doesn't escape the output directory
///
/// This function implements multiple layers of path traversal protection:
/// 1. Rejects paths with ".." components
/// 2. Checks for null bytes and dangerous characters
/// 3. Normalizes and verifies the final path stays within bounds
/// 4. Uses canonicalize() when possible for symlink resolution
///
/// Note: Uses `dunce::canonicalize` to handle Windows extended-length paths
/// correctly (removes `\\?\` prefix that would break `strip_prefix`).
pub fn validate_output_path(output_base: &Path, target_path: &Path) -> Result<()> {
    // Canonicalize the output base (create if needed for canonicalization)
    // Using safe_canonicalize (dunce) to handle Windows \\?\ prefix
    let canonical_base = if output_base.exists() {
        safe_canonicalize(output_base)?
    } else {
        // For non-existent paths, we need to find the existing ancestor
        let mut existing = output_base.to_path_buf();
        while !existing.exists() && existing.parent().is_some() {
            existing = existing.parent().unwrap().to_path_buf();
        }
        if existing.exists() {
            let canonical_existing = safe_canonicalize(&existing)?;
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
        if let Ok(canonical_full) = safe_canonicalize(&full_path) {
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

// ============================================================================
// Dry-Run Validation (Archive Safety Check)
// ============================================================================

/// Severity level for validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    /// Informational message (not a problem)
    Info,
    /// Warning (potential issue, but extraction may proceed)
    Warning,
    /// Error (extraction should be blocked)
    Error,
}

/// A single validation issue found in an archive.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Severity of the issue
    pub severity: ValidationSeverity,
    /// Description of the issue
    pub message: String,
    /// Name of the affected file (if applicable)
    pub file_name: Option<String>,
}

impl ValidationIssue {
    /// Create a new validation issue.
    pub fn new(severity: ValidationSeverity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
            file_name: None,
        }
    }

    /// Create a validation issue for a specific file.
    pub fn for_file(
        severity: ValidationSeverity,
        message: impl Into<String>,
        file_name: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            message: message.into(),
            file_name: Some(file_name.into()),
        }
    }
}

/// Report from validating an archive without extracting.
///
/// Use this to check if an archive is safe before committing to extraction.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::{validate_archive, SecurityPolicy};
///
/// let report = validate_archive("suspicious.zip", &SecurityPolicy::default())?;
///
/// if report.is_safe() {
///     println!("Archive is safe to extract");
/// } else {
///     println!("Issues found:");
///     for issue in report.errors() {
///         println!("  - {}", issue.message);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// All issues found during validation
    pub issues: Vec<ValidationIssue>,
    /// Total number of files in the archive
    pub total_files: usize,
    /// Total uncompressed size of all files
    pub total_uncompressed_size: u64,
    /// Total compressed size of all files
    pub total_compressed_size: u64,
    /// Whether the archive contains encrypted files
    pub has_encrypted_files: bool,
    /// Whether the archive contains symlinks
    pub has_symlinks: bool,
    /// Maximum compression ratio found in the archive
    pub max_compression_ratio: f64,
}

impl ValidationReport {
    /// Create a new empty validation report.
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            total_files: 0,
            total_uncompressed_size: 0,
            total_compressed_size: 0,
            has_encrypted_files: false,
            has_symlinks: false,
            max_compression_ratio: 0.0,
        }
    }

    /// Check if the archive is safe to extract (no errors).
    pub fn is_safe(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error)
    }

    /// Check if the archive has any warnings.
    pub fn has_warnings(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Warning)
    }

    /// Get all error-level issues.
    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
    }

    /// Get all warning-level issues.
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
    }

    /// Get the overall compression ratio (total_uncompressed / total_compressed).
    pub fn overall_compression_ratio(&self) -> f64 {
        if self.total_compressed_size == 0 {
            1.0
        } else {
            self.total_uncompressed_size as f64 / self.total_compressed_size as f64
        }
    }

    /// Add an issue to the report.
    pub fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// Add an error to the report.
    pub fn add_error(&mut self, message: impl Into<String>) {
        self.issues
            .push(ValidationIssue::new(ValidationSeverity::Error, message));
    }

    /// Add a warning to the report.
    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.issues
            .push(ValidationIssue::new(ValidationSeverity::Warning, message));
    }

    /// Add an info message to the report.
    pub fn add_info(&mut self, message: impl Into<String>) {
        self.issues
            .push(ValidationIssue::new(ValidationSeverity::Info, message));
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate an archive without extracting it.
///
/// Scans the ZIP Central Directory and performs security checks according
/// to the provided policy. Returns a detailed report of any issues found.
///
/// This function is useful for:
/// - Checking if an untrusted archive is safe before extraction
/// - Pre-validating large archives to avoid wasted I/O
/// - Implementing security scanning in pipelines
///
/// # Arguments
/// * `path` - Path to the ZIP archive
/// * `policy` - Security policy to validate against
///
/// # Returns
/// A `ValidationReport` containing all issues found and archive statistics.
pub fn validate_archive(path: &Path, policy: &SecurityPolicy) -> Result<ValidationReport> {
    use std::fs::File;
    use zip::ZipArchive;

    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;

    validate_archive_from_reader(&mut archive, policy)
}

/// Validate an archive from bytes without extracting it.
pub fn validate_archive_bytes(data: &[u8], policy: &SecurityPolicy) -> Result<ValidationReport> {
    use std::io::Cursor;
    use zip::ZipArchive;

    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    validate_archive_from_reader(&mut archive, policy)
}

/// Internal function to validate archive from any reader.
fn validate_archive_from_reader<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    policy: &SecurityPolicy,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();
    report.total_files = archive.len();

    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;
        let name = file.name().to_string();
        let uncompressed_size = file.size();
        let compressed_size = file.compressed_size();

        report.total_uncompressed_size = report
            .total_uncompressed_size
            .saturating_add(uncompressed_size);
        report.total_compressed_size = report.total_compressed_size.saturating_add(compressed_size);

        // Track encryption
        if file.encrypted() {
            report.has_encrypted_files = true;
        }

        // Check for symlinks (Unix mode check)
        // NOTE: This check runs on ALL platforms. A ZIP created on Unix may contain
        // symlinks stored with unix_mode, and we need to detect them even on Windows.
        if let Some(mode) = file.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                // S_IFLNK
                report.has_symlinks = true;
                if !policy.allow_symlinks {
                    report.add_issue(ValidationIssue::for_file(
                        ValidationSeverity::Error,
                        "Archive contains symlink (blocked by policy)",
                        &name,
                    ));
                }
            }
        }

        // Check compression ratio per file
        if compressed_size > 0 {
            let ratio = uncompressed_size as f64 / compressed_size as f64;
            if ratio > report.max_compression_ratio {
                report.max_compression_ratio = ratio;
            }

            if policy.ratio_limit_enabled() && ratio > policy.max_compression_ratio as f64 {
                report.add_issue(ValidationIssue::for_file(
                    ValidationSeverity::Error,
                    format!(
                        "Suspicious compression ratio {:.1}x (limit: {}x) - possible ZIP bomb",
                        ratio, policy.max_compression_ratio
                    ),
                    &name,
                ));
            }
        }

        // Validate file name for path traversal
        if let Err(e) = validate_archive_entry_name(&name) {
            report.add_issue(ValidationIssue::for_file(
                ValidationSeverity::Error,
                format!("Invalid entry name: {}", e),
                &name,
            ));
        }
    }

    // Check total size against policy
    if policy.size_limit_enabled() && report.total_uncompressed_size > policy.max_decompressed_size
    {
        report.add_error(format!(
            "Total uncompressed size ({} bytes) exceeds limit ({} bytes)",
            report.total_uncompressed_size, policy.max_decompressed_size
        ));
    }

    // Check overall compression ratio
    let overall_ratio = report.overall_compression_ratio();
    if policy.ratio_limit_enabled() && overall_ratio > policy.max_compression_ratio as f64 {
        report.add_error(format!(
            "Overall compression ratio {:.1}x exceeds limit {}x",
            overall_ratio, policy.max_compression_ratio
        ));
    }

    // Add informational summary
    if report.has_encrypted_files {
        report.add_info("Archive contains encrypted files");
    }

    Ok(report)
}
