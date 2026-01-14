use crate::error::{Result, RustyZipError};
use filetime::FileTime;
use glob::Pattern;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Encryption method for password-protected archives
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionMethod {
    /// AES-256 encryption (strong, requires 7-Zip/WinRAR to open)
    Aes256,
    /// ZipCrypto encryption (weak, Windows Explorer compatible)
    ZipCrypto,
    /// No encryption
    None,
}

impl Default for EncryptionMethod {
    fn default() -> Self {
        EncryptionMethod::Aes256
    }
}

impl EncryptionMethod {
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

/// Compress a single file to a ZIP archive
pub fn compress_file(
    input_path: &Path,
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    if !input_path.exists() {
        return Err(RustyZipError::FileNotFound(
            input_path.display().to_string(),
        ));
    }

    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    let file_name = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| RustyZipError::InvalidPath(
            format!("'{}' - cannot extract filename (path may contain invalid UTF-8 or be empty)", input_path.display())
        ))?;

    add_file_to_zip(
        &mut zip,
        input_path,
        file_name,
        password,
        encryption,
        compression_level,
    )?;

    zip.finish()?;
    Ok(())
}

/// Compress multiple files to a ZIP archive
///
/// When compiled with the `parallel` feature (default), this function
/// automatically uses parallel processing for improved performance.
pub fn compress_files(
    input_paths: &[&Path],
    prefixes: &[Option<&str>],
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    // Use parallel implementation when feature is enabled
    #[cfg(feature = "parallel")]
    {
        compress_files_parallel(
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
        compress_files_sequential(
            input_paths,
            prefixes,
            output_path,
            password,
            encryption,
            compression_level,
        )
    }
}

/// Sequential implementation of multi-file compression
#[cfg(not(feature = "parallel"))]
fn compress_files_sequential(
    input_paths: &[&Path],
    prefixes: &[Option<&str>],
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    for (i, input_path) in input_paths.iter().enumerate() {
        if !input_path.exists() {
            return Err(RustyZipError::FileNotFound(
                input_path.display().to_string(),
            ));
        }

        let file_name = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RustyZipError::InvalidPath(
                format!("'{}' - cannot extract filename (path may contain invalid UTF-8 or be empty)", input_path.display())
            ))?;

        let prefix = prefixes.get(i).and_then(|p| *p);
        let archive_name = match prefix {
            Some(p) if !p.is_empty() => format!("{}/{}", p.trim_matches('/'), file_name),
            _ => file_name.to_string(),
        };

        add_file_to_zip(
            &mut zip,
            input_path,
            &archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Compress a directory to a ZIP archive
///
/// When compiled with the `parallel` feature (default), this function
/// automatically uses parallel processing for improved performance.
pub fn compress_directory(
    input_dir: &Path,
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    include_patterns: Option<&[String]>,
    exclude_patterns: Option<&[String]>,
) -> Result<()> {
    // Use parallel implementation when feature is enabled
    #[cfg(feature = "parallel")]
    {
        compress_directory_parallel(
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
        compress_directory_sequential(
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

/// Sequential implementation of directory compression
#[cfg(not(feature = "parallel"))]
fn compress_directory_sequential(
    input_dir: &Path,
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    include_patterns: Option<&[String]>,
    exclude_patterns: Option<&[String]>,
) -> Result<()> {
    if !input_dir.exists() {
        return Err(RustyZipError::FileNotFound(input_dir.display().to_string()));
    }

    if !input_dir.is_dir() {
        return Err(RustyZipError::InvalidPath(format!(
            "{} is not a directory",
            input_dir.display()
        )));
    }

    // Compile patterns - return error if any pattern is invalid
    let include_patterns: Option<Vec<Pattern>> = match include_patterns {
        Some(patterns) => {
            let compiled: std::result::Result<Vec<Pattern>, _> = patterns
                .iter()
                .map(|p| Pattern::new(p).map_err(RustyZipError::from))
                .collect();
            Some(compiled?)
        }
        None => None,
    };

    let exclude_patterns: Option<Vec<Pattern>> = match exclude_patterns {
        Some(patterns) => {
            let compiled: std::result::Result<Vec<Pattern>, _> = patterns
                .iter()
                .map(|p| Pattern::new(p).map_err(RustyZipError::from))
                .collect();
            Some(compiled?)
        }
        None => None,
    };

    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // Use the original input_dir for prefix stripping to avoid Windows canonicalize issues
    // (canonicalize on Windows adds \\?\ prefix which breaks strip_prefix)
    let base_path = input_dir;

    for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_dir() {
            continue;
        }

        // Get relative path for archive
        let relative_path = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        // Check if file should be included based on patterns
        if !should_include_file(
            path,
            &relative_path,
            include_patterns.as_ref(),
            exclude_patterns.as_ref(),
        ) {
            continue;
        }

        add_file_to_zip(
            &mut zip,
            path,
            &relative_path,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Maximum file size for parallel loading (10 MB)
/// Files larger than this will be processed sequentially to avoid OOM
#[cfg(feature = "parallel")]
const PARALLEL_FILE_SIZE_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Holds pre-compressed file data for parallel compression
#[cfg(feature = "parallel")]
struct CompressedFileData {
    archive_name: String,
    data: Vec<u8>,
    last_modified: Option<zip::DateTime>,
}

/// Represents a file that's too large for parallel memory loading
#[cfg(feature = "parallel")]
struct LargeFileInfo {
    path: std::path::PathBuf,
    archive_name: String,
}

/// Compress a directory to a ZIP archive using parallel processing
///
/// This function reads and compresses files in parallel using rayon,
/// then writes them sequentially to the ZIP archive. This provides
/// significant speedup for directories with many files.
///
/// # Arguments
/// * `input_dir` - Path to the directory to compress
/// * `output_path` - Path for the output ZIP file
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level (0-9)
/// * `include_patterns` - Optional list of glob patterns to include
/// * `exclude_patterns` - Optional list of glob patterns to exclude
#[cfg(feature = "parallel")]
pub fn compress_directory_parallel(
    input_dir: &Path,
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    include_patterns: Option<&[String]>,
    exclude_patterns: Option<&[String]>,
) -> Result<()> {
    if !input_dir.exists() {
        return Err(RustyZipError::FileNotFound(input_dir.display().to_string()));
    }

    if !input_dir.is_dir() {
        return Err(RustyZipError::InvalidPath(format!(
            "{} is not a directory",
            input_dir.display()
        )));
    }

    // Compile patterns
    let include_patterns: Option<Vec<Pattern>> = match include_patterns {
        Some(patterns) => {
            let compiled: std::result::Result<Vec<Pattern>, _> = patterns
                .iter()
                .map(|p| Pattern::new(p).map_err(RustyZipError::from))
                .collect();
            Some(compiled?)
        }
        None => None,
    };

    let exclude_patterns: Option<Vec<Pattern>> = match exclude_patterns {
        Some(patterns) => {
            let compiled: std::result::Result<Vec<Pattern>, _> = patterns
                .iter()
                .map(|p| Pattern::new(p).map_err(RustyZipError::from))
                .collect();
            Some(compiled?)
        }
        None => None,
    };

    let base_path = input_dir;

    // First pass: count files for capacity pre-allocation (reduces reallocations)
    let entries: Vec<_> = WalkDir::new(input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| !entry.path().is_dir())
        .collect();

    let estimated_count = entries.len();

    // Collect all files and separate into small (parallelizable) and large (sequential streaming)
    let mut small_files: Vec<(std::path::PathBuf, String)> = Vec::with_capacity(estimated_count);
    let mut large_files: Vec<LargeFileInfo> = Vec::with_capacity(estimated_count / 10); // Assume ~10% large files

    for entry in entries {
        let path = entry.path();
        // Note: directories already filtered above

        let relative_path = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        if !should_include_file(
            path,
            &relative_path,
            include_patterns.as_ref(),
            exclude_patterns.as_ref(),
        ) {
            continue;
        }

        // Check file size to decide if we can parallelize
        let file_size = path.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > PARALLEL_FILE_SIZE_THRESHOLD {
            large_files.push(LargeFileInfo {
                path: path.to_path_buf(),
                archive_name: relative_path,
            });
        } else {
            small_files.push((path.to_path_buf(), relative_path));
        }
    }

    // Read and compress small files in parallel (memory safe)
    let compressed_files: std::result::Result<Vec<CompressedFileData>, RustyZipError> =
        small_files
            .par_iter()
            .map(|(path, archive_name)| {
                // Read file
                let input_file = File::open(path)?;
                let last_modified = input_file
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(system_time_to_zip_datetime);

                let mut reader = std::io::BufReader::with_capacity(64 * 1024, input_file);
                let mut data = Vec::new();
                reader.read_to_end(&mut data)?;

                // Pre-compress if using deflate
                let compressed_data = if compression_level.0 > 0 {
                    use flate2::write::DeflateEncoder;
                    use flate2::Compression;

                    let mut encoder = DeflateEncoder::new(
                        Vec::new(),
                        Compression::new(compression_level.0),
                    );
                    encoder.write_all(&data)?;
                    encoder.finish()?
                } else {
                    data
                };

                Ok(CompressedFileData {
                    archive_name: archive_name.clone(),
                    data: compressed_data,
                    last_modified,
                })
            })
            .collect();

    let compressed_files = compressed_files?;

    // Write to ZIP sequentially (ZIP format requires sequential writes)
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // First write the small files that were compressed in parallel
    for file_data in compressed_files {
        add_bytes_to_zip_with_time(
            &mut zip,
            &file_data.data,
            &file_data.archive_name,
            password,
            encryption,
            compression_level,
            file_data.last_modified,
        )?;
    }

    // Then process large files sequentially using streaming (memory safe)
    for large_file in large_files {
        add_file_to_zip(
            &mut zip,
            &large_file.path,
            &large_file.archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Compress multiple files to a ZIP archive using parallel processing
#[cfg(feature = "parallel")]
pub fn compress_files_parallel(
    input_paths: &[&Path],
    prefixes: &[Option<&str>],
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    // Validate all files exist first
    for input_path in input_paths {
        if !input_path.exists() {
            return Err(RustyZipError::FileNotFound(
                input_path.display().to_string(),
            ));
        }
    }

    // Separate files into small (parallelizable) and large (sequential streaming)
    // Pre-allocate with estimated capacity to reduce reallocations
    let file_count = input_paths.len();
    let mut small_files: Vec<(&Path, String)> = Vec::with_capacity(file_count);
    let mut large_files: Vec<LargeFileInfo> = Vec::with_capacity(file_count / 10); // Assume ~10% large

    for (i, input_path) in input_paths.iter().enumerate() {
        let file_name = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");

        let prefix = prefixes.get(i).and_then(|p| *p);
        let archive_name = match prefix {
            Some(p) if !p.is_empty() => format!("{}/{}", p.trim_matches('/'), file_name),
            _ => file_name.to_string(),
        };

        // Check file size to decide if we can parallelize
        let file_size = input_path.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > PARALLEL_FILE_SIZE_THRESHOLD {
            large_files.push(LargeFileInfo {
                path: input_path.to_path_buf(),
                archive_name,
            });
        } else {
            small_files.push((*input_path, archive_name));
        }
    }

    // Read and compress small files in parallel (memory safe)
    let compressed_files: std::result::Result<Vec<CompressedFileData>, RustyZipError> = small_files
        .par_iter()
        .map(|(path, archive_name)| {
            let input_file = File::open(path)?;
            let last_modified = input_file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(system_time_to_zip_datetime);

            let mut reader = std::io::BufReader::with_capacity(64 * 1024, input_file);
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;

            Ok(CompressedFileData {
                archive_name: archive_name.clone(),
                data,
                last_modified,
            })
        })
        .collect();

    let compressed_files = compressed_files?;

    // Write to ZIP sequentially
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // First write the small files that were compressed in parallel
    for file_data in compressed_files {
        add_bytes_to_zip_with_time(
            &mut zip,
            &file_data.data,
            &file_data.archive_name,
            password,
            encryption,
            compression_level,
            file_data.last_modified,
        )?;
    }

    // Then process large files sequentially using streaming (memory safe)
    for large_file in large_files {
        add_file_to_zip(
            &mut zip,
            &large_file.path,
            &large_file.archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Check if a file should be included based on include/exclude patterns
fn should_include_file(
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

/// Add bytes directly to a ZIP writer
fn add_bytes_to_zip<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    add_bytes_to_zip_with_time(zip, data, archive_name, password, encryption, compression_level, None)
}

/// Add bytes directly to a ZIP writer with optional modification time
fn add_bytes_to_zip_with_time<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    last_modified: Option<zip::DateTime>,
) -> Result<()> {
    let (compression_method, level_option) = if compression_level.0 == 0 {
        (CompressionMethod::Stored, None)
    } else {
        (
            CompressionMethod::Deflated,
            Some(compression_level.0 as i64),
        )
    };

    let mut base_options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(level_option);

    // Set modification time if provided
    if let Some(mtime) = last_modified {
        base_options = base_options.last_modified_time(mtime);
    }

    match (password, encryption) {
        (Some(pwd), EncryptionMethod::Aes256) => {
            let options = base_options.with_aes_encryption(AesMode::Aes256, pwd);
            zip.start_file(archive_name, options)?;
        }
        (Some(pwd), EncryptionMethod::ZipCrypto) => {
            let options = base_options.with_deprecated_encryption(pwd.as_bytes());
            zip.start_file(archive_name, options)?;
        }
        _ => {
            zip.start_file(archive_name, base_options)?;
        }
    }

    zip.write_all(data)?;

    Ok(())
}

/// Convert a SystemTime to zip::DateTime
fn system_time_to_zip_datetime(system_time: std::time::SystemTime) -> Option<zip::DateTime> {
    use time::OffsetDateTime;

    let duration = system_time.duration_since(std::time::UNIX_EPOCH).ok()?;
    let datetime = OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64).ok()?;

    zip::DateTime::try_from(datetime).ok()
}

/// Add a single file to a ZIP writer using streaming (memory efficient)
fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    let input_file = File::open(file_path)?;

    // Get the file's modification time before wrapping in BufReader
    let last_modified = input_file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(system_time_to_zip_datetime);

    // Use BufReader for efficient reading
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, input_file);

    // Stream the file content using chunked writing
    add_reader_to_zip_with_time(
        zip,
        &mut reader,
        archive_name,
        password,
        encryption,
        compression_level,
        last_modified,
    )
}

/// Default maximum decompressed size (2 GB)
/// This limit prevents ZIP bomb attacks that could exhaust disk/memory
const DEFAULT_MAX_DECOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Default maximum compression ratio (500x)
/// Ratios above 500x are suspicious and may indicate a ZIP bomb
/// Note: Highly compressible data (e.g., repeated text) can legitimately reach 100-200x
const DEFAULT_MAX_COMPRESSION_RATIO: u64 = 500;

/// Validate that a path is safe and doesn't escape the output directory
///
/// This function implements multiple layers of path traversal protection:
/// 1. Rejects paths with ".." components
/// 2. Checks for null bytes and dangerous characters
/// 3. Normalizes and verifies the final path stays within bounds
/// 4. Uses canonicalize() when possible for symlink resolution
fn validate_output_path(output_base: &Path, target_path: &Path) -> Result<()> {
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
                return Err(RustyZipError::PathTraversal(
                    format!("Parent directory reference (..) in path: {}", target_path.display()),
                ));
            }
            std::path::Component::Normal(name) => {
                if let Some(name_str) = name.to_str() {
                    // Check for null bytes
                    if name_str.contains('\0') {
                        return Err(RustyZipError::PathTraversal(
                            format!("Null byte in path: {}", target_path.display()),
                        ));
                    }
                    // Check for other dangerous patterns (Windows-specific)
                    #[cfg(windows)]
                    {
                        // Check for reserved device names on Windows
                        let upper = name_str.to_uppercase();
                        let reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                                       "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                                       "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];
                        let base_name = upper.split('.').next().unwrap_or("");
                        if reserved.contains(&base_name) {
                            return Err(RustyZipError::PathTraversal(
                                format!("Reserved device name in path: {}", target_path.display()),
                            ));
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
        return Err(RustyZipError::PathTraversal(
            format!("Path escapes output directory: {}", target_path.display()),
        ));
    }

    // Additional check: if the full path exists, canonicalize and verify again
    // This catches symlink attacks where a file could point outside the directory
    if full_path.exists() {
        if let Ok(canonical_full) = full_path.canonicalize() {
            if !canonical_full.starts_with(&canonical_base) {
                return Err(RustyZipError::PathTraversal(
                    format!("Symlink escapes output directory: {}", target_path.display()),
                ));
            }
        }
    }

    Ok(())
}

/// Decompress a ZIP archive
///
/// # Arguments
/// * `input_path` - Path to the ZIP file
/// * `output_path` - Directory to extract files to
/// * `password` - Optional password for encrypted archives
/// * `withoutpath` - If true, extract files without their directory paths (flatten)
pub fn decompress_file(
    input_path: &Path,
    output_path: &Path,
    password: Option<&str>,
    withoutpath: bool,
) -> Result<()> {
    decompress_file_with_limits(
        input_path,
        output_path,
        password,
        withoutpath,
        DEFAULT_MAX_DECOMPRESSED_SIZE,
        DEFAULT_MAX_COMPRESSION_RATIO,
    )
}

/// Decompress a ZIP archive with configurable security limits
///
/// # Arguments
/// * `input_path` - Path to the ZIP file
/// * `output_path` - Directory to extract files to
/// * `password` - Optional password for encrypted archives
/// * `withoutpath` - If true, extract files without their directory paths (flatten)
/// * `max_size` - Maximum total decompressed size in bytes
/// * `max_ratio` - Maximum allowed compression ratio
pub fn decompress_file_with_limits(
    input_path: &Path,
    output_path: &Path,
    password: Option<&str>,
    withoutpath: bool,
    max_size: u64,
    max_ratio: u64,
) -> Result<()> {
    if !input_path.exists() {
        return Err(RustyZipError::FileNotFound(
            input_path.display().to_string(),
        ));
    }

    let file = File::open(input_path)?;
    let _compressed_size = file.metadata()?.len();
    let mut archive = ZipArchive::new(file)?;

    // Create output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path)?;
    }

    // Track total decompressed size for ZIP bomb detection
    let mut total_decompressed: u64 = 0;

    for i in 0..archive.len() {
        let mut file = match password {
            Some(pwd) => match archive.by_index_decrypt(i, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(RustyZipError::InvalidPassword);
                }
                Err(e) => return Err(e.into()),
            },
            None => archive.by_index(i)?,
        };

        // Get the mangled (safe) name
        let mangled_name = file.mangled_name();

        // Skip directories when withoutpath is enabled
        if file.is_dir() {
            if !withoutpath {
                // Validate path before creating directory
                validate_output_path(output_path, &mangled_name)?;
                let outpath = output_path.join(&mangled_name);
                fs::create_dir_all(&outpath)?;
            }
            continue;
        }

        // Check uncompressed size before extraction (ZIP bomb early detection)
        let uncompressed_size = file.size();
        total_decompressed = total_decompressed.saturating_add(uncompressed_size);

        // Check total size limit
        if total_decompressed > max_size {
            return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
        }

        // Check compression ratio (if compressed size is known and non-zero)
        let file_compressed_size = file.compressed_size();
        if file_compressed_size > 0 {
            let ratio = uncompressed_size / file_compressed_size;
            if ratio > max_ratio {
                return Err(RustyZipError::SuspiciousCompressionRatio(ratio, max_ratio));
            }
        }

        // Determine output path based on withoutpath flag
        let relative_path = if withoutpath {
            // Extract only the filename, stripping all directory components
            let filename = mangled_name
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("unnamed"));
            std::path::PathBuf::from(filename)
        } else {
            mangled_name.clone()
        };

        // Validate path traversal
        validate_output_path(output_path, &relative_path)?;

        let outpath = output_path.join(&relative_path);

        // Create parent directories if needed (only when preserving paths)
        if !withoutpath {
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
        }

        // Create output file and copy with size tracking
        let mut outfile = File::create(&outpath)?;
        let bytes_written = std::io::copy(&mut file, &mut outfile)?;

        // Verify actual size matches declared size (additional ZIP bomb check)
        if bytes_written > uncompressed_size {
            // File was larger than declared - update total
            total_decompressed = total_decompressed
                .saturating_sub(uncompressed_size)
                .saturating_add(bytes_written);
            if total_decompressed > max_size {
                // Clean up the file we just wrote
                let _ = fs::remove_file(&outpath);
                return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
            }
        }

        // Set file modification time to match the original
        if let Some(last_modified) = file.last_modified() {
            use time::OffsetDateTime;
            if let Ok(time) = OffsetDateTime::try_from(last_modified) {
                let unix_timestamp = time.unix_timestamp();
                let mtime = FileTime::from_unix_time(unix_timestamp, 0);
                // Setting modification time is non-critical, ignore failures
                let _ = filetime::set_file_mtime(&outpath, mtime);
            }
        }

        // Set permissions on Unix (non-critical, ignore failures)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                let _ = fs::set_permissions(&outpath, fs::Permissions::from_mode(mode));
            }
        }
    }

    Ok(())
}

/// Delete a file
#[allow(dead_code)]
pub fn delete_file(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    Ok(())
}

/// Compress multiple byte arrays into a ZIP archive in memory
///
/// # Arguments
/// * `files` - Slice of (archive_name, data) tuples
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level (0-9)
///
/// # Returns
/// The compressed ZIP archive as a byte vector
pub fn compress_bytes(
    files: &[(&str, &[u8])],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);

    for (archive_name, data) in files {
        add_bytes_to_zip(
            &mut zip,
            data,
            archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

/// Decompress a ZIP archive from bytes in memory
///
/// # Arguments
/// * `data` - The ZIP archive data
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_bytes(data: &[u8], password: Option<&str>) -> Result<Vec<(String, Vec<u8>)>> {
    decompress_bytes_with_limits(data, password, DEFAULT_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX_COMPRESSION_RATIO)
}

/// Decompress a ZIP archive from bytes in memory with configurable security limits
///
/// # Arguments
/// * `data` - The ZIP archive data
/// * `password` - Optional password for encrypted archives
/// * `max_size` - Maximum total decompressed size in bytes
/// * `max_ratio` - Maximum allowed compression ratio
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_bytes_with_limits(
    data: &[u8],
    password: Option<&str>,
    max_size: u64,
    max_ratio: u64,
) -> Result<Vec<(String, Vec<u8>)>> {
    let _compressed_size = data.len() as u64;
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    let mut results = Vec::new();
    let mut total_decompressed: u64 = 0;

    for i in 0..archive.len() {
        let mut file = match password {
            Some(pwd) => match archive.by_index_decrypt(i, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(RustyZipError::InvalidPassword);
                }
                Err(e) => return Err(e.into()),
            },
            None => archive.by_index(i)?,
        };

        // Skip directories
        if file.is_dir() {
            continue;
        }

        // Check uncompressed size before extraction (ZIP bomb early detection)
        let uncompressed_size = file.size();
        total_decompressed = total_decompressed.saturating_add(uncompressed_size);

        // Check total size limit
        if total_decompressed > max_size {
            return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
        }

        // Check compression ratio
        let file_compressed_size = file.compressed_size();
        if file_compressed_size > 0 {
            let ratio = uncompressed_size / file_compressed_size;
            if ratio > max_ratio {
                return Err(RustyZipError::SuspiciousCompressionRatio(ratio, max_ratio));
            }
        }

        let name = file.name().to_string();

        // Pre-allocate with declared size, but cap at a reasonable amount
        let capacity = (uncompressed_size as usize).min(64 * 1024 * 1024); // Cap at 64MB pre-allocation
        let mut content = Vec::with_capacity(capacity);
        file.read_to_end(&mut content)?;

        // Verify actual size (in case declared size was wrong)
        let actual_size = content.len() as u64;
        if actual_size > uncompressed_size {
            total_decompressed = total_decompressed
                .saturating_sub(uncompressed_size)
                .saturating_add(actual_size);
            if total_decompressed > max_size {
                return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
            }
        }

        results.push((name, content));
    }

    Ok(results)
}

// ============================================================================
// Streaming Compression Functions
// ============================================================================

/// Compress data from a reader to a writer in streaming fashion.
///
/// This function reads data in chunks and writes compressed output,
/// avoiding loading the entire file into memory.
///
/// # Arguments
/// * `output` - A Write + Seek destination for the ZIP archive
/// * `files` - Iterator of (archive_name, reader) pairs
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level (0-9)
pub fn compress_stream<W, R, I>(
    output: W,
    files: I,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()>
where
    W: Write + Seek,
    R: Read,
    I: IntoIterator<Item = (String, R)>,
{
    let mut zip = ZipWriter::new(output);

    for (archive_name, mut reader) in files {
        add_reader_to_zip(
            &mut zip,
            &mut reader,
            &archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Add data from a reader to the ZIP archive, streaming in chunks.
fn add_reader_to_zip<W, R>(
    zip: &mut ZipWriter<W>,
    reader: &mut R,
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()>
where
    W: Write + Seek,
    R: Read,
{
    add_reader_to_zip_with_time(zip, reader, archive_name, password, encryption, compression_level, None)
}

/// Add data from a reader to the ZIP archive with optional modification time, streaming in chunks.
fn add_reader_to_zip_with_time<W, R>(
    zip: &mut ZipWriter<W>,
    reader: &mut R,
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    last_modified: Option<zip::DateTime>,
) -> Result<()>
where
    W: Write + Seek,
    R: Read,
{
    let (compression_method, level_option) = if compression_level.0 == 0 {
        (CompressionMethod::Stored, None)
    } else {
        (
            CompressionMethod::Deflated,
            Some(compression_level.0 as i64),
        )
    };

    let mut base_options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(level_option);

    // Set modification time if provided
    if let Some(mtime) = last_modified {
        base_options = base_options.last_modified_time(mtime);
    }

    match (password, encryption) {
        (Some(pwd), EncryptionMethod::Aes256) => {
            let options = base_options.with_aes_encryption(AesMode::Aes256, pwd);
            zip.start_file(archive_name, options)?;
        }
        (Some(pwd), EncryptionMethod::ZipCrypto) => {
            let options = base_options.with_deprecated_encryption(pwd.as_bytes());
            zip.start_file(archive_name, options)?;
        }
        _ => {
            zip.start_file(archive_name, base_options)?;
        }
    }

    // Stream data in chunks (64KB)
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        zip.write_all(&buffer[..bytes_read])?;
    }

    Ok(())
}

/// Decompress a ZIP archive from a seekable reader, returning file info.
///
/// # Arguments
/// * `input` - A Read + Seek source containing the ZIP archive
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_stream_to_vec<R>(
    input: R,
    password: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>>
where
    R: Read + Seek,
{
    decompress_stream_to_vec_with_limits(input, password, DEFAULT_MAX_DECOMPRESSED_SIZE, DEFAULT_MAX_COMPRESSION_RATIO)
}

/// Decompress a ZIP archive from a seekable reader with configurable security limits.
///
/// # Arguments
/// * `input` - A Read + Seek source containing the ZIP archive
/// * `password` - Optional password for encrypted archives
/// * `max_size` - Maximum total decompressed size in bytes
/// * `max_ratio` - Maximum allowed compression ratio
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_stream_to_vec_with_limits<R>(
    input: R,
    password: Option<&str>,
    max_size: u64,
    max_ratio: u64,
) -> Result<Vec<(String, Vec<u8>)>>
where
    R: Read + Seek,
{
    let mut archive = ZipArchive::new(input)?;
    let mut results = Vec::new();
    let mut total_decompressed: u64 = 0;

    for i in 0..archive.len() {
        let mut file = match password {
            Some(pwd) => match archive.by_index_decrypt(i, pwd.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(RustyZipError::InvalidPassword);
                }
                Err(e) => return Err(e.into()),
            },
            None => archive.by_index(i)?,
        };

        // Skip directories
        if file.is_dir() {
            continue;
        }

        // Check uncompressed size before extraction (ZIP bomb early detection)
        let uncompressed_size = file.size();
        total_decompressed = total_decompressed.saturating_add(uncompressed_size);

        // Check total size limit
        if total_decompressed > max_size {
            return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
        }

        // Check compression ratio
        let file_compressed_size = file.compressed_size();
        if file_compressed_size > 0 {
            let ratio = uncompressed_size / file_compressed_size;
            if ratio > max_ratio {
                return Err(RustyZipError::SuspiciousCompressionRatio(ratio, max_ratio));
            }
        }

        let name = file.name().to_string();

        // Pre-allocate with declared size, but cap at a reasonable amount
        let capacity = (uncompressed_size as usize).min(64 * 1024 * 1024);
        let mut content = Vec::with_capacity(capacity);
        file.read_to_end(&mut content)?;

        // Verify actual size
        let actual_size = content.len() as u64;
        if actual_size > uncompressed_size {
            total_decompressed = total_decompressed
                .saturating_sub(uncompressed_size)
                .saturating_add(actual_size);
            if total_decompressed > max_size {
                return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
            }
        }

        results.push((name, content));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_compress_decompress_no_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_file = extract_path.join("test.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_compress_decompress_with_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("secret.txt");
        let output_path = temp_dir.path().join("secret.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Secret data").unwrap();

        // Compress with AES-256
        compress_file(
            &input_path,
            &output_path,
            Some("password123"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress with correct password
        decompress_file(&output_path, &extract_path, Some("password123"), false).unwrap();

        let extracted_file = extract_path.join("secret.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "Secret data");
    }

    #[test]
    fn test_encryption_method_from_str() {
        assert_eq!(
            EncryptionMethod::from_str("aes256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("zipcrypto").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("none").unwrap(),
            EncryptionMethod::None
        );
        assert!(EncryptionMethod::from_str("invalid").is_err());
    }

    #[test]
    fn test_encryption_method_from_str_case_insensitive() {
        assert_eq!(
            EncryptionMethod::from_str("AES256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("AES").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("aes-256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("ZIPCRYPTO").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("zip_crypto").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("legacy").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("NONE").unwrap(),
            EncryptionMethod::None
        );
        assert_eq!(
            EncryptionMethod::from_str("").unwrap(),
            EncryptionMethod::None
        );
    }

    #[test]
    fn test_compression_level_new() {
        assert_eq!(CompressionLevel::new(0).0, 0);
        assert_eq!(CompressionLevel::new(5).0, 5);
        assert_eq!(CompressionLevel::new(9).0, 9);
        // Should clamp to 9
        assert_eq!(CompressionLevel::new(10).0, 9);
        assert_eq!(CompressionLevel::new(100).0, 9);
    }

    #[test]
    fn test_compression_level_constants() {
        assert_eq!(CompressionLevel::STORE.0, 0);
        assert_eq!(CompressionLevel::FAST.0, 1);
        assert_eq!(CompressionLevel::DEFAULT.0, 6);
        assert_eq!(CompressionLevel::BEST.0, 9);
    }

    #[test]
    fn test_compress_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("test.zip");

        let result = compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_decompress_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.zip");
        let output_path = temp_dir.path().join("extracted");

        let result = decompress_file(&input_path, &output_path, None, false);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_decompress_wrong_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("secret.txt");
        let output_path = temp_dir.path().join("secret.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Secret data").unwrap();

        // Compress with password
        compress_file(
            &input_path,
            &output_path,
            Some("correct_password"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Try to decompress with wrong password
        let result = decompress_file(&output_path, &extract_path, Some("wrong_password"), false);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPassword => {}
            e => panic!("Expected InvalidPassword error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_decompress_zipcrypto() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("zipcrypto.txt");
        let output_path = temp_dir.path().join("zipcrypto.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"ZipCrypto encrypted content").unwrap();

        // Compress with ZipCrypto
        compress_file(
            &input_path,
            &output_path,
            Some("password"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, Some("password"), false).unwrap();

        let extracted_file = extract_path.join("zipcrypto.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "ZipCrypto encrypted content");
    }

    #[test]
    fn test_compress_multiple_files() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");
        let output_path = temp_dir.path().join("multi.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test files
        fs::write(&file1, "Content of file 1").unwrap();
        fs::write(&file2, "Content of file 2").unwrap();
        fs::write(&file3, "Content of file 3").unwrap();

        // Compress multiple files
        compress_files(
            &[file1.as_path(), file2.as_path(), file3.as_path()],
            &[None, None, None],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        // Verify all files
        assert_eq!(
            fs::read_to_string(extract_path.join("file1.txt")).unwrap(),
            "Content of file 1"
        );
        assert_eq!(
            fs::read_to_string(extract_path.join("file2.txt")).unwrap(),
            "Content of file 2"
        );
        assert_eq!(
            fs::read_to_string(extract_path.join("file3.txt")).unwrap(),
            "Content of file 3"
        );
    }

    #[test]
    fn test_compress_files_with_prefixes() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let output_path = temp_dir.path().join("prefixed.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test files
        fs::write(&file1, "File 1").unwrap();
        fs::write(&file2, "File 2").unwrap();

        // Compress with prefixes
        compress_files(
            &[file1.as_path(), file2.as_path()],
            &[Some("dir1"), Some("dir2/subdir")],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        // Verify files are in correct directories
        assert!(extract_path.join("dir1").join("file1.txt").exists());
        assert!(extract_path
            .join("dir2")
            .join("subdir")
            .join("file2.txt")
            .exists());
    }

    #[test]
    fn test_compress_directory_basic() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files
        fs::write(src_dir.join("file1.txt"), "File 1").unwrap();
        fs::write(src_dir.join("file2.txt"), "File 2").unwrap();

        let subdir = src_dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file3.txt"), "File 3").unwrap();

        let output_path = temp_dir.path().join("dir.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress directory
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            None,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        // Verify structure
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file2.txt").exists());
        assert!(extract_path.join("subdir").join("file3.txt").exists());
    }

    #[test]
    fn test_compress_directory_with_include_patterns() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files with different extensions
        fs::write(src_dir.join("file1.txt"), "Text file").unwrap();
        fs::write(src_dir.join("file2.rs"), "Rust file").unwrap();
        fs::write(src_dir.join("file3.txt"), "Another text file").unwrap();
        fs::write(src_dir.join("file4.py"), "Python file").unwrap();

        let output_path = temp_dir.path().join("filtered.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress only .txt files
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            Some(&["*.txt".to_string()]),
            None,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        // Verify only .txt files are included
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file3.txt").exists());
        assert!(!extract_path.join("file2.rs").exists());
        assert!(!extract_path.join("file4.py").exists());
    }

    #[test]
    fn test_compress_directory_with_exclude_patterns() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files
        fs::write(src_dir.join("file1.txt"), "Keep").unwrap();
        fs::write(src_dir.join("file2.txt"), "Keep").unwrap();
        fs::write(src_dir.join("secret.key"), "Exclude").unwrap();
        fs::write(src_dir.join("data.tmp"), "Exclude").unwrap();

        let output_path = temp_dir.path().join("excluded.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress excluding .key and .tmp files
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            Some(&["*.key".to_string(), "*.tmp".to_string()]),
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        // Verify excluded files are not included
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file2.txt").exists());
        assert!(!extract_path.join("secret.key").exists());
        assert!(!extract_path.join("data.tmp").exists());
    }

    #[test]
    fn test_compress_directory_not_a_directory() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        fs::write(&file_path, "I'm a file, not a directory").unwrap();

        let output_path = temp_dir.path().join("output.zip");

        let result = compress_directory(
            &file_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPath(msg) => {
                assert!(msg.contains("is not a directory"));
            }
            e => panic!("Expected InvalidPath error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_empty_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("empty.txt");
        let output_path = temp_dir.path().join("empty.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create empty file
        File::create(&input_path).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_file = extract_path.join("empty.txt");
        assert!(extracted_file.exists());
        assert_eq!(fs::read_to_string(extracted_file).unwrap(), "");
    }

    #[test]
    fn test_compress_binary_data() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("binary.bin");
        let output_path = temp_dir.path().join("binary.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create binary file with various byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        fs::write(&input_path, &binary_data).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_data = fs::read(extract_path.join("binary.bin")).unwrap();
        assert_eq!(extracted_data, binary_data);
    }

    #[test]
    fn test_compression_level_store() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("stored.txt");
        let output_path = temp_dir.path().join("stored.zip");
        let extract_path = temp_dir.path().join("extracted");

        let content = "This content will be stored without compression";
        fs::write(&input_path, content).unwrap();

        // Compress with STORE level (no compression)
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::STORE,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_content = fs::read_to_string(extract_path.join("stored.txt")).unwrap();
        assert_eq!(extracted_content, content);
    }

    #[test]
    fn test_compression_level_best() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("best.txt");
        let output_path = temp_dir.path().join("best.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Repetitive content that compresses well
        let content = "AAAA".repeat(1000);
        fs::write(&input_path, &content).unwrap();

        // Compress with BEST level
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::BEST,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_content = fs::read_to_string(extract_path.join("best.txt")).unwrap();
        assert_eq!(extracted_content, content);
    }

    #[test]
    fn test_delete_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("to_delete.txt");

        fs::write(&file_path, "Delete me").unwrap();
        assert!(file_path.exists());

        delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_delete_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        let result = delete_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_files_one_not_found() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("exists.txt");
        let file2 = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("output.zip");

        fs::write(&file1, "I exist").unwrap();

        let result = compress_files(
            &[file1.as_path(), file2.as_path()],
            &[None, None],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_with_password_no_encryption() {
        // When password is provided but encryption is None, no encryption should be applied
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.zip");
        let extract_path = temp_dir.path().join("extracted");

        fs::write(&input_path, "Test content").unwrap();

        compress_file(
            &input_path,
            &output_path,
            Some("password"),
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Should be able to decompress without password
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
        assert_eq!(content, "Test content");
    }

    #[test]
    fn test_compress_decompress_large_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("large.bin");
        let output_path = temp_dir.path().join("large.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create a 1MB file with random-ish data
        let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        fs::write(&input_path, &data).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let extracted_data = fs::read(extract_path.join("large.bin")).unwrap();
        assert_eq!(extracted_data.len(), data.len());
        assert_eq!(extracted_data, data);
    }

    // ========================================================================
    // In-Memory Compression Tests
    // ========================================================================

    #[test]
    fn test_compress_decompress_bytes_no_password() {
        let files = vec![
            ("hello.txt", b"Hello, World!".as_slice()),
            ("data.bin", &[0u8, 1, 2, 3, 4, 5]),
        ];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(!zip_data.is_empty());

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "hello.txt");
        assert_eq!(result[0].1, b"Hello, World!");
        assert_eq!(result[1].0, "data.bin");
        assert_eq!(result[1].1, &[0u8, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_compress_decompress_bytes_with_password_aes256() {
        let files = vec![("secret.txt", b"Secret data".as_slice())];

        // Compress with AES-256
        let zip_data = compress_bytes(
            &files,
            Some("password123"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with correct password
        let result = decompress_bytes(&zip_data, Some("password123")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "secret.txt");
        assert_eq!(result[0].1, b"Secret data");
    }

    #[test]
    fn test_compress_decompress_bytes_with_password_zipcrypto() {
        let files = vec![("legacy.txt", b"Legacy encrypted".as_slice())];

        // Compress with ZipCrypto
        let zip_data = compress_bytes(
            &files,
            Some("pass"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with correct password
        let result = decompress_bytes(&zip_data, Some("pass")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "legacy.txt");
        assert_eq!(result[0].1, b"Legacy encrypted");
    }

    #[test]
    fn test_decompress_bytes_wrong_password() {
        let files = vec![("test.txt", b"Test".as_slice())];

        // Compress with password
        let zip_data = compress_bytes(
            &files,
            Some("correct"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with wrong password
        let result = decompress_bytes(&zip_data, Some("wrong"));

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPassword => {}
            e => panic!("Expected InvalidPassword error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_bytes_empty_file() {
        let files = vec![("empty.txt", b"".as_slice())];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "empty.txt");
        assert_eq!(result[0].1, b"");
    }

    #[test]
    fn test_compress_bytes_with_subdirectory() {
        let files = vec![
            ("root.txt", b"Root file".as_slice()),
            ("subdir/nested.txt", b"Nested file".as_slice()),
            ("subdir/deep/file.txt", b"Deep nested".as_slice()),
        ];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "root.txt");
        assert_eq!(result[1].0, "subdir/nested.txt");
        assert_eq!(result[2].0, "subdir/deep/file.txt");
    }

    #[test]
    fn test_compress_bytes_binary_data() {
        // Binary data with all byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        let files = vec![("binary.bin", binary_data.as_slice())];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, binary_data);
    }

    #[test]
    fn test_compress_bytes_compression_levels() {
        let data = b"AAAA".repeat(1000);
        let files = vec![("data.txt", data.as_slice())];

        // Test STORE (no compression)
        let zip_store = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::STORE,
        )
        .unwrap();

        // Test BEST compression
        let zip_best =
            compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

        // BEST should be smaller than STORE for repetitive data
        assert!(zip_best.len() < zip_store.len());

        // Both should decompress correctly
        let result_store = decompress_bytes(&zip_store, None).unwrap();
        let result_best = decompress_bytes(&zip_best, None).unwrap();

        assert_eq!(result_store[0].1, data);
        assert_eq!(result_best[0].1, data);
    }

    #[test]
    fn test_compress_bytes_multiple_files() {
        let files: Vec<(&str, &[u8])> = (0..10)
            .map(|i| {
                let name = format!("file{}.txt", i);
                let content = format!("Content {}", i);
                // Leak to get 'static lifetime for test
                (
                    Box::leak(name.into_boxed_str()) as &str,
                    Box::leak(content.into_bytes().into_boxed_slice()) as &[u8],
                )
            })
            .collect();

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 10);
        for (i, (name, content)) in result.iter().enumerate() {
            assert_eq!(name, &format!("file{}.txt", i));
            assert_eq!(content, format!("Content {}", i).as_bytes());
        }
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[test]
    fn test_error_io_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test io error");
        let err: RustyZipError = io_err.into();
        match err {
            RustyZipError::Io(_) => {}
            e => panic!("Expected Io error, got {:?}", e),
        }
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_error_file_not_found() {
        let err = RustyZipError::FileNotFound("/path/to/file.txt".to_string());
        assert!(err.to_string().contains("File not found"));
        assert!(err.to_string().contains("/path/to/file.txt"));
    }

    #[test]
    fn test_error_invalid_path() {
        let err = RustyZipError::InvalidPath("bad/path".to_string());
        assert!(err.to_string().contains("Invalid path"));
    }

    #[test]
    fn test_error_invalid_password() {
        let err = RustyZipError::InvalidPassword;
        assert!(err.to_string().contains("Invalid password"));
    }

    #[test]
    fn test_error_unsupported_encryption() {
        let err = RustyZipError::UnsupportedEncryption("unknown".to_string());
        assert!(err.to_string().contains("Unsupported encryption"));
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn test_error_pattern_error() {
        let err = RustyZipError::PatternError("invalid pattern [".to_string());
        assert!(err.to_string().contains("Pattern error"));
    }

    #[test]
    fn test_error_path_traversal() {
        let err = RustyZipError::PathTraversal("../../../etc/passwd".to_string());
        assert!(err.to_string().contains("Path traversal"));
        assert!(err.to_string().contains("../../../etc/passwd"));
    }

    #[test]
    fn test_error_zip_bomb() {
        let err = RustyZipError::ZipBomb(100_000_000_000, 10_000_000_000);
        assert!(err.to_string().contains("ZIP bomb"));
        assert!(err.to_string().contains("100000000000"));
        assert!(err.to_string().contains("10000000000"));
    }

    #[test]
    fn test_error_suspicious_compression_ratio() {
        let err = RustyZipError::SuspiciousCompressionRatio(5000, 1000);
        assert!(err.to_string().contains("compression ratio"));
        assert!(err.to_string().contains("5000"));
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_error_glob_pattern_conversion() {
        // Test invalid glob pattern error conversion
        let result = glob::Pattern::new("[invalid");
        assert!(result.is_err());
        let err: RustyZipError = result.unwrap_err().into();
        match err {
            RustyZipError::PatternError(_) => {}
            e => panic!("Expected PatternError, got {:?}", e),
        }
    }

    #[test]
    fn test_encryption_method_from_str_invalid() {
        let result = EncryptionMethod::from_str("invalid_method");
        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::UnsupportedEncryption(msg) => {
                assert!(msg.contains("invalid_method"));
            }
            e => panic!("Expected UnsupportedEncryption error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_directory_invalid_pattern() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("test.txt"), "test").unwrap();

        let output_path = temp_dir.path().join("output.zip");

        // Invalid glob pattern should return error
        let result = compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            Some(&["[invalid".to_string()]),
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::PatternError(_) => {}
            e => panic!("Expected PatternError, got {:?}", e),
        }
    }

    // ========================================================================
    // Security Tests - Path Traversal
    // ========================================================================

    #[test]
    fn test_path_traversal_validation() {
        use std::path::Path;

        let output_base = Path::new("/tmp/extract");

        // Test that parent dir (..) is rejected
        let result = validate_output_path(output_base, Path::new("../etc/passwd"));
        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::PathTraversal(_) => {}
            e => panic!("Expected PathTraversal error, got {:?}", e),
        }

        // Test that absolute path components are handled
        let result = validate_output_path(output_base, Path::new("foo/../../../bar"));
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_safe_paths() {
        let temp_dir = tempdir().unwrap();
        let output_base = temp_dir.path();

        // Safe relative paths should pass
        assert!(validate_output_path(output_base, Path::new("file.txt")).is_ok());
        assert!(validate_output_path(output_base, Path::new("subdir/file.txt")).is_ok());
        assert!(validate_output_path(output_base, Path::new("a/b/c/file.txt")).is_ok());
    }

    // ========================================================================
    // Security Tests - ZIP Bomb Protection
    // ========================================================================

    #[test]
    fn test_decompress_with_size_limit() {
        // Create a ZIP with a known file
        let files = vec![("test.txt", b"Hello World".as_slice())];
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Should succeed with reasonable limit
        let result = decompress_bytes_with_limits(&zip_data, None, 1024 * 1024, 1000);
        assert!(result.is_ok());

        // Should fail with very small limit
        let result = decompress_bytes_with_limits(&zip_data, None, 5, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::ZipBomb(_, _) => {}
            e => panic!("Expected ZipBomb error, got {:?}", e),
        }
    }

    #[test]
    fn test_decompress_file_with_limits() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create a test file
        fs::write(&input_path, "Hello, World!").unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Should succeed with reasonable limit
        let result = decompress_file_with_limits(
            &output_path,
            &extract_path,
            None,
            false,
            1024 * 1024,
            1000,
        );
        assert!(result.is_ok());

        // Clean up for next test
        fs::remove_dir_all(&extract_path).unwrap();

        // Should fail with very small limit
        let result = decompress_file_with_limits(
            &output_path,
            &extract_path,
            None,
            false,
            5,
            1000,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::ZipBomb(_, _) => {}
            e => panic!("Expected ZipBomb error, got {:?}", e),
        }
    }

    // ========================================================================
    // Compat API Tests - ZipCrypto Verification
    // ========================================================================

    /// Helper to check if a ZIP file uses ZipCrypto encryption
    fn is_zipcrypto_encrypted(zip_data: &[u8]) -> bool {
        use zip::ZipArchive;
        use std::io::Cursor;

        let cursor = Cursor::new(zip_data);
        let archive = ZipArchive::new(cursor).unwrap();

        // Check the first file's encryption
        if archive.len() > 0 {
            // Try to read without password - should fail if encrypted
            let cursor = Cursor::new(zip_data);
            let mut archive = ZipArchive::new(cursor).unwrap();

            let result = archive.by_index(0);
            let is_encrypted = match result {
                Ok(_) => false, // Not encrypted or AES
                Err(zip::result::ZipError::UnsupportedArchive(ref msg)) => {
                    // ZipCrypto shows as "Password required to decrypt file"
                    msg.contains("Password")
                }
                Err(_) => false,
            };
            drop(result);
            is_encrypted
        } else {
            false
        }
    }

    /// Helper to verify a file can be decrypted with ZipCrypto
    fn can_decrypt_with_zipcrypto(zip_data: &[u8], password: &str) -> bool {
        use zip::ZipArchive;
        use std::io::Cursor;

        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        if archive.len() > 0 {
            match archive.by_index_decrypt(0, password.as_bytes()) {
                Ok(mut file) => {
                    let mut content = Vec::new();
                    file.read_to_end(&mut content).is_ok()
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }

    #[test]
    fn test_zipcrypto_vs_aes256_encryption() {
        let files = vec![("secret.txt", b"Secret data".as_slice())];

        // Compress with ZipCrypto
        let zip_crypto = compress_bytes(
            &files,
            Some("password"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Compress with AES256
        let zip_aes = compress_bytes(
            &files,
            Some("password"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Both should decrypt successfully
        let result_crypto = decompress_bytes(&zip_crypto, Some("password"));
        let result_aes = decompress_bytes(&zip_aes, Some("password"));

        assert!(result_crypto.is_ok());
        assert!(result_aes.is_ok());

        // Verify content is correct
        assert_eq!(result_crypto.unwrap()[0].1, b"Secret data");
        assert_eq!(result_aes.unwrap()[0].1, b"Secret data");

        // ZipCrypto and AES256 produce different file sizes (AES has more overhead)
        // AES256 adds extra headers for encryption
        assert_ne!(zip_crypto.len(), zip_aes.len());
    }

    #[test]
    fn test_compat_compress_uses_zipcrypto() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("compat.zip");

        // Create test file
        fs::write(&input_path, "Test content for compat API").unwrap();

        // Use the files compression with ZipCrypto (simulating compat behavior)
        compress_files(
            &[input_path.as_path()],
            &[None],
            &output_path,
            Some("password123"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Read the ZIP file
        let zip_data = fs::read(&output_path).unwrap();

        // Verify it's encrypted
        assert!(is_zipcrypto_encrypted(&zip_data));

        // Verify it can be decrypted with the password
        assert!(can_decrypt_with_zipcrypto(&zip_data, "password123"));

        // Verify wrong password fails
        assert!(!can_decrypt_with_zipcrypto(&zip_data, "wrongpassword"));
    }

    #[test]
    fn test_compat_compress_multiple_files_uses_zipcrypto() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let output_path = temp_dir.path().join("multi_compat.zip");

        // Create test files
        fs::write(&file1, "Content 1").unwrap();
        fs::write(&file2, "Content 2").unwrap();

        // Compress with ZipCrypto (compat API behavior)
        compress_files(
            &[file1.as_path(), file2.as_path()],
            &[Some("dir1"), Some("dir2")],
            &output_path,
            Some("testpass"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Read and verify
        let zip_data = fs::read(&output_path).unwrap();

        // Verify encryption
        assert!(is_zipcrypto_encrypted(&zip_data));
        assert!(can_decrypt_with_zipcrypto(&zip_data, "testpass"));

        // Decompress and verify contents
        let extract_path = temp_dir.path().join("extracted");
        decompress_file(&output_path, &extract_path, Some("testpass"), false).unwrap();

        assert!(extract_path.join("dir1").join("file1.txt").exists());
        assert!(extract_path.join("dir2").join("file2.txt").exists());
    }

    #[test]
    fn test_compat_no_password_no_encryption() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("no_encrypt.zip");

        fs::write(&input_path, "Unencrypted content").unwrap();

        // Compress without password (compat API uses None encryption)
        compress_files(
            &[input_path.as_path()],
            &[None],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Read and verify it's NOT encrypted
        let zip_data = fs::read(&output_path).unwrap();
        assert!(!is_zipcrypto_encrypted(&zip_data));

        // Should decompress without password
        let extract_path = temp_dir.path().join("extracted");
        decompress_file(&output_path, &extract_path, None, false).unwrap();

        let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
        assert_eq!(content, "Unencrypted content");
    }

    #[test]
    fn test_compat_decompress_zipcrypto() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("zipcrypto.zip");
        let extract_path = temp_dir.path().join("extracted");

        fs::write(&input_path, "ZipCrypto encrypted file").unwrap();

        // Compress with ZipCrypto
        compress_file(
            &input_path,
            &output_path,
            Some("password"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress (simulating compat uncompress)
        decompress_file(&output_path, &extract_path, Some("password"), false).unwrap();

        let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
        assert_eq!(content, "ZipCrypto encrypted file");
    }

    #[test]
    fn test_compat_decompress_withoutpath() {
        let temp_dir = tempdir().unwrap();

        // Create ZIP with nested structure using ZipCrypto
        let files = vec![
            ("dir1/file1.txt", b"File 1".as_slice()),
            ("dir1/dir2/file2.txt", b"File 2".as_slice()),
        ];

        let zip_data = compress_bytes(
            &files,
            Some("pass"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let zip_path = temp_dir.path().join("nested.zip");
        fs::write(&zip_path, &zip_data).unwrap();

        // Extract with withoutpath=true (flatten structure)
        let extract_path = temp_dir.path().join("flat");
        decompress_file(&zip_path, &extract_path, Some("pass"), true).unwrap();

        // Files should be flattened (no subdirectories)
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file2.txt").exists());
        assert!(!extract_path.join("dir1").exists());
    }
}
