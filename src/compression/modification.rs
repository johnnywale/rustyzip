//! Archive modification functionality for ZIP archives.
//!
//! This module provides functions to modify existing ZIP archives:
//! - Add files to an existing archive
//! - Remove files from an archive
//! - Rename files within an archive
//! - Update/replace file contents in an archive
//!
//! Note: ZIP files don't support in-place modification, so these functions
//! work by creating a new archive with the desired changes and replacing
//! the original file atomically (write to temp file, then rename).
//!
//! # Security
//!
//! All archive names are validated to prevent path traversal attacks (Zip Slip).
//! Names containing `..`, absolute paths, or null bytes are rejected.
//!
//! # Duplicate Handling
//!
//! Adding a file with a name that already exists in the archive will return an error.
//! Use [`update_in_archive`] to replace existing files.
//!
//! # Performance
//!
//! This module uses streaming I/O and raw byte copying where possible:
//! - **File operations**: Stream directly from/to disk without loading entire archive into memory
//! - **Unchanged entries**: Copied as raw compressed bytes (no decompress/recompress)
//! - **Encrypted entries**: Can be copied without the password (raw passthrough)
//!
//! This makes operations like remove and rename nearly instantaneous regardless of archive size.
//!
//! # Constraints
//!
//! - The archive's parent directory must be writable for atomic operations
//! - Modifying encrypted entry *contents* requires the password

use super::security::{
    validate_archive_entry_name, SecurityPolicy, DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION,
};
use super::types::{CompressionLevel, EncryptionMethod};
use super::utils::{add_bytes_to_zip_with_time, add_file_to_zip};
use crate::error::{Result, RustyZipError};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

/// Default maximum archive size for modification operations (100 MB).
/// This prevents memory exhaustion from loading very large archives.
///
/// **Deprecated**: Use `SecurityPolicy::default().max_archive_size_for_modification` instead.
#[deprecated(
    since = "1.1.0",
    note = "Use SecurityPolicy::default().max_archive_size_for_modification instead"
)]
#[allow(dead_code)]
pub const DEFAULT_MAX_MODIFICATION_SIZE: u64 = DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION;

// =============================================================================
// Progress Callback Types
// =============================================================================

/// Progress event for archive modification operations.
///
/// This enum is part of the public API for progress callbacks during
/// archive modification operations. While the callback infrastructure is
/// in place, it's not yet exposed in the public functions.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ProgressEvent<'a> {
    /// Operation started
    Started {
        /// Total number of entries to process
        total_entries: usize,
    },
    /// An entry was processed
    EntryProcessed {
        /// Index of the processed entry (0-based)
        index: usize,
        /// Name of the entry
        name: &'a str,
        /// Whether this entry was modified (vs raw copied)
        modified: bool,
    },
    /// Operation completed successfully
    Completed {
        /// Total entries in the final archive
        total_entries: usize,
    },
}

/// Trait for progress callbacks during archive modification.
pub trait ProgressCallback: FnMut(ProgressEvent<'_>) {}
impl<F: FnMut(ProgressEvent<'_>)> ProgressCallback for F {}

// =============================================================================
// Security Helper Functions
// =============================================================================

/// Check archive size against the security policy limit.
/// Returns an error if the archive exceeds the limit.
fn check_archive_size(size: u64, policy: &SecurityPolicy) -> Result<()> {
    if policy.modification_size_limit_enabled() && size > policy.max_archive_size_for_modification {
        return Err(RustyZipError::ZipBomb(
            size,
            policy.max_archive_size_for_modification,
        ));
    }
    Ok(())
}

/// Check if a file is a symlink and whether that's allowed by the security policy.
/// Returns an error if symlinks are not allowed and the file is a symlink.
fn check_symlink(file: &Path, policy: &SecurityPolicy) -> Result<()> {
    if !policy.allow_symlinks_in_input && file.is_symlink() {
        return Err(RustyZipError::SymlinkNotAllowed(format!(
            "Cannot add symlink to archive (security risk): {}",
            file.display()
        )));
    }
    Ok(())
}

/// Check input file size against the security policy limit.
/// Returns an error if the file exceeds the limit.
fn check_input_file_size(file: &Path, policy: &SecurityPolicy) -> Result<()> {
    if policy.modification_size_limit_enabled() {
        let file_size = std::fs::metadata(file)?.len();
        if file_size > policy.max_archive_size_for_modification {
            return Err(RustyZipError::ZipBomb(
                file_size,
                policy.max_archive_size_for_modification,
            ));
        }
    }
    Ok(())
}

/// Get all file names in an archive as a HashSet.
fn get_archive_file_names<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;
        names.insert(file.name().to_string());
    }
    Ok(names)
}

/// Check for duplicate names when adding files to an archive.
/// Also checks for duplicates within the new_names array itself.
fn check_duplicate_names<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    new_names: &[&str],
) -> Result<()> {
    // First check for duplicates within the input itself
    check_input_duplicates(new_names)?;

    // Then check against existing archive entries
    let existing_names = get_archive_file_names(archive)?;
    for name in new_names {
        if existing_names.contains(*name) {
            return Err(RustyZipError::InvalidPath(format!(
                "File '{}' already exists in archive. Use update_in_archive to replace.",
                name
            )));
        }
    }
    Ok(())
}

/// Check for duplicate names within an input array.
fn check_input_duplicates(names: &[&str]) -> Result<()> {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(*name) {
            return Err(RustyZipError::InvalidPath(format!(
                "Duplicate archive name '{}' in input. Each file must have a unique name.",
                name
            )));
        }
    }
    Ok(())
}

// =============================================================================
// Atomic Write Helpers (using tempfile crate for auto-cleanup)
// =============================================================================

/// Create a temp file in the same directory as the target for atomic operations.
///
/// Using `NamedTempFile` provides several safety benefits:
/// - **Auto-cleanup on drop**: If the process panics or is killed, the temp file
///   is automatically deleted (no orphaned .tmp files).
/// - **Same filesystem**: Created in the target's directory, so rename is atomic.
/// - **Unique naming**: No race conditions between processes.
///
/// # Arguments
/// * `target_path` - The final destination path (temp file will be in same directory)
///
/// # Returns
/// A tuple of (NamedTempFile, File) where the File is a reopened handle for writing.
/// The NamedTempFile is kept for cleanup and persist operations.
/// On Windows, we need separate handles because the file can't be renamed while open.
fn create_temp_file(target_path: &Path) -> Result<(NamedTempFile, File)> {
    let parent = target_path.parent().unwrap_or(Path::new("."));
    let temp_file = NamedTempFile::new_in(parent).map_err(RustyZipError::Io)?;
    // Reopen to get a separate handle - on Windows, this allows us to close
    // the write handle before calling persist()
    let write_handle = temp_file.reopen().map_err(RustyZipError::Io)?;
    Ok((temp_file, write_handle))
}

/// Persist a temp file to its final destination atomically.
///
/// This performs an atomic rename operation. If the rename fails,
/// the temp file is automatically cleaned up (thanks to NamedTempFile's Drop impl).
fn persist_temp_file(temp_file: NamedTempFile, target_path: &Path) -> Result<()> {
    temp_file.persist(target_path).map_err(|e| {
        // The error contains the NamedTempFile, which will be dropped and cleaned up
        RustyZipError::Io(e.error)
    })?;
    Ok(())
}

// =============================================================================
// Core Copy Functions (Raw + Streaming)
// =============================================================================

/// Copy entries from source to destination using raw byte copying where possible.
///
/// This is the optimized version that:
/// - Uses raw byte copying for unchanged entries (no decompress/recompress)
/// - Supports encrypted entries without needing the password
/// - Preserves archive comments
/// - Supports progress callbacks
///
/// # Arguments
/// * `source` - Source archive to copy from
/// * `dest` - Destination zip writer
/// * `exclude` - Set of file names to exclude (skip)
/// * `renames` - Array of (old_name, new_name) pairs for renaming
/// * `progress` - Optional progress callback
fn copy_entries_raw<R: Read + Seek, W: Write + Seek>(
    source: &mut ZipArchive<R>,
    dest: &mut ZipWriter<W>,
    exclude: &HashSet<&str>,
    renames: &[(&str, &str)],
    mut progress: Option<&mut dyn ProgressCallback>,
) -> Result<()> {
    let total = source.len();

    // Notify start
    if let Some(ref mut cb) = progress {
        cb(ProgressEvent::Started {
            total_entries: total,
        });
    }

    for i in 0..total {
        // Get file info using by_index_raw (doesn't require decryption)
        let raw_file = source.by_index_raw(i)?;
        let original_name = raw_file.name().to_string();

        // Skip excluded files
        if exclude.contains(original_name.as_str()) {
            continue;
        }

        // Check for renames
        let target_name = renames
            .iter()
            .find(|(old, _)| *old == original_name)
            .map(|(_, new)| *new)
            .unwrap_or(&original_name);

        // Use raw copy - this preserves compression and encryption without re-processing
        // For renames, we need to use raw_copy_file_rename if available, or fall back
        if target_name == original_name {
            // Direct raw copy - most efficient
            dest.raw_copy_file(raw_file)?;
        } else {
            // Need to rename - raw_copy_file_rename handles this efficiently
            dest.raw_copy_file_rename(raw_file, target_name)?;
        }

        // Notify progress
        if let Some(ref mut cb) = progress {
            cb(ProgressEvent::EntryProcessed {
                index: i,
                name: target_name,
                modified: false, // Raw copy = not modified
            });
        }
    }

    Ok(())
}

/// Copy entries with content modification support.
///
/// This version is used when we need to actually read/modify content.
/// Falls back to decompression for entries that need modification.
///
/// # Note
/// This function cannot copy encrypted entries without the password.
/// If the source archive contains encrypted files that need content modification,
/// this will fail with an `InvalidPassword` error.
///
/// Currently unused as raw copy handles all current operations efficiently.
/// Kept for future operations that may need to modify entry content.
#[allow(dead_code)]
fn copy_entries_with_content<R: Read + Seek, W: Write + Seek>(
    source: &mut ZipArchive<R>,
    dest: &mut ZipWriter<W>,
    exclude: &HashSet<&str>,
    renames: &[(&str, &str)],
    mut progress: Option<&mut dyn ProgressCallback>,
) -> Result<()> {
    let total = source.len();

    if let Some(ref mut cb) = progress {
        cb(ProgressEvent::Started {
            total_entries: total,
        });
    }

    for i in 0..total {
        // First check if we should skip or can raw-copy
        let file_info = source.by_index_raw(i)?;
        let original_name = file_info.name().to_string();
        let is_encrypted = file_info.encrypted();
        drop(file_info);

        // Skip excluded files
        if exclude.contains(original_name.as_str()) {
            continue;
        }

        // Check for renames
        let target_name = renames
            .iter()
            .find(|(old, _)| *old == original_name)
            .map(|(_, new)| *new)
            .unwrap_or(&original_name);

        // For non-excluded, non-renamed entries, use raw copy when possible
        let needs_content_access = false; // In this function, we're just copying

        if !needs_content_access {
            // Use raw copy
            let raw_file = source.by_index_raw(i)?;
            if target_name == original_name {
                dest.raw_copy_file(raw_file)?;
            } else {
                dest.raw_copy_file_rename(raw_file, target_name)?;
            }
        } else {
            // Need to decompress - this path requires password for encrypted files
            let mut file = source.by_index(i).map_err(|e| {
                if is_encrypted {
                    if let zip::result::ZipError::UnsupportedArchive(msg) = &e {
                        if msg.contains("password") || msg.contains("Password") {
                            return RustyZipError::InvalidPassword;
                        }
                    }
                }
                RustyZipError::from(e)
            })?;

            // Set up options preserving metadata
            let mut options = SimpleFileOptions::default()
                .compression_method(file.compression())
                .last_modified_time(file.last_modified().unwrap_or_default());

            if let Some(mode) = file.unix_mode() {
                options = options.unix_permissions(mode);
            }

            if file.is_dir() {
                dest.add_directory(target_name, options)?;
            } else {
                dest.start_file(target_name, options)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                dest.write_all(&buffer)?;
            }
        }

        if let Some(ref mut cb) = progress {
            cb(ProgressEvent::EntryProcessed {
                index: i,
                name: target_name,
                modified: false,
            });
        }
    }

    Ok(())
}

/// Preserve archive comment from source to destination.
fn copy_archive_comment<R: Read + Seek, W: Write + Seek>(
    source: &ZipArchive<R>,
    dest: &mut ZipWriter<W>,
) {
    let comment = source.comment();
    if !comment.is_empty() {
        dest.set_comment(String::from_utf8_lossy(comment).into_owned());
    }
}

// =============================================================================
// Public API: File-based Operations (Streaming)
// =============================================================================

/// Add files to an existing ZIP archive.
///
/// Uses default security policy. For custom security settings, use
/// [`add_to_archive_with_policy`].
///
/// # Arguments
/// * `archive_path` - Path to the existing ZIP archive
/// * `files` - Slice of file paths to add
/// * `archive_names` - Names for the files in the archive (must match files length)
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level to use
///
/// # Errors
/// Returns an error if:
/// - The archive doesn't exist or isn't a valid ZIP
/// - Any of the input files don't exist
/// - The number of files doesn't match the number of archive names
/// - Archive exceeds size limit (100 MB by default)
/// - Input file is a symlink (blocked by default)
pub fn add_to_archive(
    archive_path: &Path,
    files: &[&Path],
    archive_names: &[&str],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    add_to_archive_with_policy(
        archive_path,
        files,
        archive_names,
        password,
        encryption,
        compression_level,
        &SecurityPolicy::default(),
    )
}

/// Add files to an existing ZIP archive with custom security policy.
///
/// This function uses streaming I/O - it doesn't load the entire archive into memory.
/// Existing entries are copied using raw bytes (no decompress/recompress).
///
/// # Arguments
/// * `archive_path` - Path to the existing ZIP archive
/// * `files` - Slice of file paths to add
/// * `archive_names` - Names for the files in the archive (must match files length)
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level to use
/// * `policy` - Security policy to apply
///
/// # Example
/// ```rust,ignore
/// use rustyzip::compression::{add_to_archive_with_policy, SecurityPolicy};
///
/// // Allow larger archives
/// let policy = SecurityPolicy::new()
///     .with_max_modification_size(500 * 1024 * 1024); // 500 MB
///
/// add_to_archive_with_policy(
///     Path::new("large.zip"),
///     &[Path::new("file.txt")],
///     &["file.txt"],
///     None,
///     EncryptionMethod::None,
///     CompressionLevel::DEFAULT,
///     &policy,
/// )?;
/// ```
pub fn add_to_archive_with_policy(
    archive_path: &Path,
    files: &[&Path],
    archive_names: &[&str],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    policy: &SecurityPolicy,
) -> Result<()> {
    if files.len() != archive_names.len() {
        return Err(RustyZipError::InvalidPath(
            "Number of files must match number of archive names".to_string(),
        ));
    }

    // Validate all archive names for path traversal attacks
    for name in archive_names {
        validate_archive_entry_name(name)?;
    }

    if !archive_path.exists() {
        return Err(RustyZipError::FileNotFound(
            archive_path.display().to_string(),
        ));
    }

    // Verify all input files exist, are not directories, check symlink policy, and check file sizes
    for file in files {
        if !file.exists() {
            return Err(RustyZipError::FileNotFound(file.display().to_string()));
        }
        if file.is_dir() {
            return Err(RustyZipError::InvalidPath(format!(
                "Cannot add directory '{}' as a file. Use compress_directory() to add directories, \
                or add files individually.",
                file.display()
            )));
        }
        check_symlink(file, policy)?;
        check_input_file_size(file, policy)?;
    }

    // SECURITY: Check archive size
    let metadata = std::fs::metadata(archive_path)?;
    check_archive_size(metadata.len(), policy)?;

    // Open source archive for streaming
    let source_file = File::open(archive_path)?;
    let mut source_archive = ZipArchive::new(BufReader::new(source_file))?;

    // Check for duplicate names
    check_duplicate_names(&mut source_archive, archive_names)?;

    // Create temp file for output (auto-cleanup on drop if not persisted)
    let (temp_file, write_handle) = create_temp_file(archive_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(write_handle));

    // Copy existing entries using raw bytes (efficient!)
    copy_entries_raw(
        &mut source_archive,
        &mut zip_writer,
        &HashSet::new(),
        &[],
        None,
    )?;

    // Copy archive comment
    copy_archive_comment(&source_archive, &mut zip_writer);

    // IMPORTANT: Close source archive BEFORE persist on Windows
    // Windows doesn't allow renaming to a path with an open handle
    drop(source_archive);

    // Add new files
    for (file_path, archive_name) in files.iter().zip(archive_names.iter()) {
        add_file_to_zip(
            &mut zip_writer,
            file_path,
            archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    // Finish writing (must complete before persist)
    zip_writer.finish()?;

    // Atomic rename (temp file auto-cleaned if this fails)
    persist_temp_file(temp_file, archive_path)
}

/// Add bytes to an existing ZIP archive.
///
/// Uses default security policy. For custom security settings, use
/// [`add_bytes_to_archive_with_policy`].
pub fn add_bytes_to_archive(
    archive_path: &Path,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    add_bytes_to_archive_with_policy(
        archive_path,
        data,
        archive_name,
        password,
        encryption,
        compression_level,
        &SecurityPolicy::default(),
    )
}

/// Add bytes to an existing ZIP archive with custom security policy.
pub fn add_bytes_to_archive_with_policy(
    archive_path: &Path,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    policy: &SecurityPolicy,
) -> Result<()> {
    validate_archive_entry_name(archive_name)?;

    if !archive_path.exists() {
        return Err(RustyZipError::FileNotFound(
            archive_path.display().to_string(),
        ));
    }

    // SECURITY: Check data size
    if policy.modification_size_limit_enabled()
        && data.len() as u64 > policy.max_archive_size_for_modification
    {
        return Err(RustyZipError::ZipBomb(
            data.len() as u64,
            policy.max_archive_size_for_modification,
        ));
    }

    // SECURITY: Check archive size
    let metadata = std::fs::metadata(archive_path)?;
    check_archive_size(metadata.len(), policy)?;

    // Open source archive
    let source_file = File::open(archive_path)?;
    let mut source_archive = ZipArchive::new(BufReader::new(source_file))?;

    // Check for duplicate names
    check_duplicate_names(&mut source_archive, &[archive_name])?;

    // Create temp file (auto-cleanup on drop)
    let (temp_file, write_handle) = create_temp_file(archive_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(write_handle));

    copy_entries_raw(
        &mut source_archive,
        &mut zip_writer,
        &HashSet::new(),
        &[],
        None,
    )?;

    copy_archive_comment(&source_archive, &mut zip_writer);

    // Close source archive before persist (required on Windows)
    drop(source_archive);

    // Add new data
    add_bytes_to_zip_with_time(
        &mut zip_writer,
        data,
        archive_name,
        password,
        encryption,
        compression_level,
        None,
    )?;

    zip_writer.finish()?;

    persist_temp_file(temp_file, archive_path)
}

/// Remove files from a ZIP archive.
///
/// Uses default security policy. For custom security settings, use
/// [`remove_from_archive_with_policy`].
///
/// # Performance
/// This operation uses raw byte copying - it's nearly instantaneous
/// regardless of archive size since files are not decompressed.
pub fn remove_from_archive(archive_path: &Path, file_names: &[&str]) -> Result<usize> {
    remove_from_archive_with_policy(archive_path, file_names, &SecurityPolicy::default())
}

/// Remove files from a ZIP archive with custom security policy.
///
/// # Performance
/// Uses raw byte copying for remaining entries - O(n) where n is the
/// number of entries, but extremely fast since no decompression occurs.
pub fn remove_from_archive_with_policy(
    archive_path: &Path,
    file_names: &[&str],
    policy: &SecurityPolicy,
) -> Result<usize> {
    if !archive_path.exists() {
        return Err(RustyZipError::FileNotFound(
            archive_path.display().to_string(),
        ));
    }

    let metadata = std::fs::metadata(archive_path)?;
    check_archive_size(metadata.len(), policy)?;

    // Open source archive
    let source_file = File::open(archive_path)?;
    let mut source_archive = ZipArchive::new(BufReader::new(source_file))?;

    // Count files to remove
    let exclude_set: HashSet<&str> = file_names.iter().copied().collect();
    let mut removed_count = 0;
    for i in 0..source_archive.len() {
        let file = source_archive.by_index_raw(i)?;
        if exclude_set.contains(file.name()) {
            removed_count += 1;
        }
    }

    if removed_count == 0 {
        return Ok(0);
    }

    // Create temp file (auto-cleanup on drop)
    let (temp_file, write_handle) = create_temp_file(archive_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(write_handle));

    copy_entries_raw(
        &mut source_archive,
        &mut zip_writer,
        &exclude_set,
        &[],
        None,
    )?;
    copy_archive_comment(&source_archive, &mut zip_writer);

    // Close source archive before persist (required on Windows)
    drop(source_archive);

    zip_writer.finish()?;

    persist_temp_file(temp_file, archive_path)?;
    Ok(removed_count)
}

/// Rename a file within a ZIP archive.
///
/// Uses default security policy. For custom security settings, use
/// [`rename_in_archive_with_policy`].
///
/// # Performance
/// Uses raw byte copying - the file content is not decompressed.
/// Works on encrypted archives without the password.
pub fn rename_in_archive(archive_path: &Path, old_name: &str, new_name: &str) -> Result<()> {
    rename_in_archive_with_policy(archive_path, old_name, new_name, &SecurityPolicy::default())
}

/// Rename a file within a ZIP archive with custom security policy.
///
/// # Performance
/// Uses raw byte copying with rename support - extremely fast.
/// Works on encrypted archives without needing the password.
pub fn rename_in_archive_with_policy(
    archive_path: &Path,
    old_name: &str,
    new_name: &str,
    policy: &SecurityPolicy,
) -> Result<()> {
    validate_archive_entry_name(new_name)?;

    if !archive_path.exists() {
        return Err(RustyZipError::FileNotFound(
            archive_path.display().to_string(),
        ));
    }

    let metadata = std::fs::metadata(archive_path)?;
    check_archive_size(metadata.len(), policy)?;

    // Open source archive
    let source_file = File::open(archive_path)?;
    let mut source_archive = ZipArchive::new(BufReader::new(source_file))?;

    // Verify old file exists and new name doesn't conflict
    let existing_names = get_archive_file_names(&mut source_archive)?;

    if !existing_names.contains(old_name) {
        return Err(RustyZipError::FileNotFound(format!(
            "'{}' not found in archive",
            old_name
        )));
    }

    if old_name != new_name && existing_names.contains(new_name) {
        return Err(RustyZipError::InvalidPath(format!(
            "File '{}' already exists in archive",
            new_name
        )));
    }

    // Create temp file (auto-cleanup on drop)
    let (temp_file, write_handle) = create_temp_file(archive_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(write_handle));

    let renames = [(old_name, new_name)];
    copy_entries_raw(
        &mut source_archive,
        &mut zip_writer,
        &HashSet::new(),
        &renames,
        None,
    )?;
    copy_archive_comment(&source_archive, &mut zip_writer);

    // Close source archive before persist (required on Windows)
    drop(source_archive);

    zip_writer.finish()?;

    persist_temp_file(temp_file, archive_path)
}

/// Update (replace) a file's content within a ZIP archive.
///
/// Uses default security policy. For custom security settings, use
/// [`update_in_archive_with_policy`].
///
/// # Encryption Behavior
///
/// The `password` and `encryption` parameters apply to the **new entry only**.
/// Existing entries in the archive are copied using raw bytes, preserving their
/// original encryption settings without requiring the password.
///
/// **Important:** To maintain a consistent archive, you should:
/// - Use `detect_encryption()` to determine the archive's encryption method
/// - Pass the same encryption method and password when updating
/// - If the archive uses `EncryptionMethod::Mixed`, consider which encryption
///   method is appropriate for the entry being updated
///
/// # Example
/// ```ignore
/// use rustyzip::compression::{detect_encryption, update_in_archive, EncryptionMethod};
///
/// // Detect existing encryption
/// let method = detect_encryption(Path::new("archive.zip"))?;
/// if method == EncryptionMethod::Mixed {
///     // Handle mixed encryption - decide which method to use
/// }
///
/// // Update with matching encryption
/// update_in_archive(
///     Path::new("archive.zip"),
///     "file.txt",
///     b"new content",
///     Some("password"),
///     method,  // Use detected method for consistency
///     CompressionLevel::DEFAULT,
/// )?;
/// ```
pub fn update_in_archive(
    archive_path: &Path,
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    update_in_archive_with_policy(
        archive_path,
        file_name,
        new_data,
        password,
        encryption,
        compression_level,
        &SecurityPolicy::default(),
    )
}

/// Update (replace) a file's content within a ZIP archive with custom security policy.
///
/// # Performance
/// Unchanged entries are copied using raw bytes (no decompress/recompress).
/// Only the updated entry is recompressed.
///
/// # Encryption Consistency
/// The `encryption` and `password` parameters apply only to the new entry.
/// Existing entries retain their original encryption. To maintain consistency:
/// - Use `detect_encryption()` to determine the archive's encryption
/// - Pass matching encryption parameters
/// - For `Mixed` archives, choose the appropriate method for each entry
pub fn update_in_archive_with_policy(
    archive_path: &Path,
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    policy: &SecurityPolicy,
) -> Result<()> {
    if !archive_path.exists() {
        return Err(RustyZipError::FileNotFound(
            archive_path.display().to_string(),
        ));
    }

    // SECURITY: Check new data size
    if policy.modification_size_limit_enabled()
        && new_data.len() as u64 > policy.max_archive_size_for_modification
    {
        return Err(RustyZipError::ZipBomb(
            new_data.len() as u64,
            policy.max_archive_size_for_modification,
        ));
    }

    let metadata = std::fs::metadata(archive_path)?;
    check_archive_size(metadata.len(), policy)?;

    // Open source archive
    let source_file = File::open(archive_path)?;
    let mut source_archive = ZipArchive::new(BufReader::new(source_file))?;

    // Verify file exists
    let existing_names = get_archive_file_names(&mut source_archive)?;
    if !existing_names.contains(file_name) {
        return Err(RustyZipError::FileNotFound(format!(
            "'{}' not found in archive",
            file_name
        )));
    }

    // Create temp file (auto-cleanup on drop)
    let (temp_file, write_handle) = create_temp_file(archive_path)?;
    let mut zip_writer = ZipWriter::new(BufWriter::new(write_handle));

    // Exclude the file we're updating
    let exclude_set: HashSet<&str> = [file_name].into_iter().collect();
    copy_entries_raw(
        &mut source_archive,
        &mut zip_writer,
        &exclude_set,
        &[],
        None,
    )?;

    copy_archive_comment(&source_archive, &mut zip_writer);

    // Close source archive before persist (required on Windows)
    drop(source_archive);

    // Add the updated file
    add_bytes_to_zip_with_time(
        &mut zip_writer,
        new_data,
        file_name,
        password,
        encryption,
        compression_level,
        None,
    )?;

    zip_writer.finish()?;

    persist_temp_file(temp_file, archive_path)
}

// =============================================================================
// Public API: In-Memory Operations (Bytes)
// =============================================================================

/// Add files to a ZIP archive in memory.
///
/// Uses default security policy. For custom security settings, use
/// [`add_to_archive_bytes_with_policy`].
pub fn add_to_archive_bytes(
    archive_data: &[u8],
    files_data: &[(&[u8], &str)],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<Vec<u8>> {
    add_to_archive_bytes_with_policy(
        archive_data,
        files_data,
        password,
        encryption,
        compression_level,
        &SecurityPolicy::default(),
    )
}

/// Add files to a ZIP archive in memory with custom security policy.
pub fn add_to_archive_bytes_with_policy(
    archive_data: &[u8],
    files_data: &[(&[u8], &str)],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    policy: &SecurityPolicy,
) -> Result<Vec<u8>> {
    check_archive_size(archive_data.len() as u64, policy)?;

    // Validate names and sizes
    for (data, name) in files_data {
        validate_archive_entry_name(name)?;
        if policy.modification_size_limit_enabled()
            && data.len() as u64 > policy.max_archive_size_for_modification
        {
            return Err(RustyZipError::ZipBomb(
                data.len() as u64,
                policy.max_archive_size_for_modification,
            ));
        }
    }

    let cursor = Cursor::new(archive_data);
    let mut source_archive = ZipArchive::new(cursor)?;

    let new_names: Vec<&str> = files_data.iter().map(|(_, name)| *name).collect();
    check_duplicate_names(&mut source_archive, &new_names)?;

    let mut buffer = Vec::new();
    {
        let mut zip_writer = ZipWriter::new(Cursor::new(&mut buffer));

        copy_entries_raw(
            &mut source_archive,
            &mut zip_writer,
            &HashSet::new(),
            &[],
            None,
        )?;

        copy_archive_comment(&source_archive, &mut zip_writer);

        for (data, name) in files_data {
            add_bytes_to_zip_with_time(
                &mut zip_writer,
                data,
                name,
                password,
                encryption,
                compression_level,
                None,
            )?;
        }

        zip_writer.finish()?;
    }

    Ok(buffer)
}

/// Remove files from a ZIP archive in memory.
pub fn remove_from_archive_bytes(
    archive_data: &[u8],
    file_names: &[&str],
) -> Result<(Vec<u8>, usize)> {
    remove_from_archive_bytes_with_policy(archive_data, file_names, &SecurityPolicy::default())
}

/// Remove files from a ZIP archive in memory with custom security policy.
pub fn remove_from_archive_bytes_with_policy(
    archive_data: &[u8],
    file_names: &[&str],
    policy: &SecurityPolicy,
) -> Result<(Vec<u8>, usize)> {
    check_archive_size(archive_data.len() as u64, policy)?;

    let cursor = Cursor::new(archive_data);
    let mut source_archive = ZipArchive::new(cursor)?;

    let exclude_set: HashSet<&str> = file_names.iter().copied().collect();

    let mut removed_count = 0;
    for i in 0..source_archive.len() {
        let file = source_archive.by_index_raw(i)?;
        if exclude_set.contains(file.name()) {
            removed_count += 1;
        }
    }

    let mut buffer = Vec::new();
    {
        let mut zip_writer = ZipWriter::new(Cursor::new(&mut buffer));
        copy_entries_raw(
            &mut source_archive,
            &mut zip_writer,
            &exclude_set,
            &[],
            None,
        )?;
        copy_archive_comment(&source_archive, &mut zip_writer);
        zip_writer.finish()?;
    }

    Ok((buffer, removed_count))
}

/// Rename a file within a ZIP archive in memory.
pub fn rename_in_archive_bytes(
    archive_data: &[u8],
    old_name: &str,
    new_name: &str,
) -> Result<Vec<u8>> {
    rename_in_archive_bytes_with_policy(
        archive_data,
        old_name,
        new_name,
        &SecurityPolicy::default(),
    )
}

/// Rename a file within a ZIP archive in memory with custom security policy.
pub fn rename_in_archive_bytes_with_policy(
    archive_data: &[u8],
    old_name: &str,
    new_name: &str,
    policy: &SecurityPolicy,
) -> Result<Vec<u8>> {
    check_archive_size(archive_data.len() as u64, policy)?;
    validate_archive_entry_name(new_name)?;

    let cursor = Cursor::new(archive_data);
    let mut source_archive = ZipArchive::new(cursor)?;

    let existing_names = get_archive_file_names(&mut source_archive)?;

    if !existing_names.contains(old_name) {
        return Err(RustyZipError::FileNotFound(format!(
            "'{}' not found in archive",
            old_name
        )));
    }

    if old_name != new_name && existing_names.contains(new_name) {
        return Err(RustyZipError::InvalidPath(format!(
            "File '{}' already exists in archive",
            new_name
        )));
    }

    let mut buffer = Vec::new();
    {
        let mut zip_writer = ZipWriter::new(Cursor::new(&mut buffer));
        let renames = [(old_name, new_name)];
        copy_entries_raw(
            &mut source_archive,
            &mut zip_writer,
            &HashSet::new(),
            &renames,
            None,
        )?;
        copy_archive_comment(&source_archive, &mut zip_writer);
        zip_writer.finish()?;
    }

    Ok(buffer)
}

/// Update (replace) a file's content within a ZIP archive in memory.
pub fn update_in_archive_bytes(
    archive_data: &[u8],
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<Vec<u8>> {
    update_in_archive_bytes_with_policy(
        archive_data,
        file_name,
        new_data,
        password,
        encryption,
        compression_level,
        &SecurityPolicy::default(),
    )
}

/// Update (replace) a file's content within a ZIP archive in memory with custom security policy.
pub fn update_in_archive_bytes_with_policy(
    archive_data: &[u8],
    file_name: &str,
    new_data: &[u8],
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    policy: &SecurityPolicy,
) -> Result<Vec<u8>> {
    check_archive_size(archive_data.len() as u64, policy)?;

    if policy.modification_size_limit_enabled()
        && new_data.len() as u64 > policy.max_archive_size_for_modification
    {
        return Err(RustyZipError::ZipBomb(
            new_data.len() as u64,
            policy.max_archive_size_for_modification,
        ));
    }

    let cursor = Cursor::new(archive_data);
    let mut source_archive = ZipArchive::new(cursor)?;

    let existing_names = get_archive_file_names(&mut source_archive)?;
    if !existing_names.contains(file_name) {
        return Err(RustyZipError::FileNotFound(format!(
            "'{}' not found in archive",
            file_name
        )));
    }

    let mut buffer = Vec::new();
    {
        let mut zip_writer = ZipWriter::new(Cursor::new(&mut buffer));

        let exclude_set: HashSet<&str> = [file_name].into_iter().collect();
        copy_entries_raw(
            &mut source_archive,
            &mut zip_writer,
            &exclude_set,
            &[],
            None,
        )?;

        copy_archive_comment(&source_archive, &mut zip_writer);

        add_bytes_to_zip_with_time(
            &mut zip_writer,
            new_data,
            file_name,
            password,
            encryption,
            compression_level,
            None,
        )?;

        zip_writer.finish()?;
    }

    Ok(buffer)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{compress_file, list_archive};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_archive(temp_dir: &TempDir) -> std::path::PathBuf {
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file1, "Content of file 1").unwrap();
        fs::write(&file2, "Content of file 2").unwrap();

        let archive_path = temp_dir.path().join("test.zip");
        compress_file(
            &file1,
            &archive_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        add_to_archive(
            &archive_path,
            &[file2.as_path()],
            &["file2.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        archive_path
    }

    #[test]
    fn test_add_to_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let new_file = temp_dir.path().join("new_file.txt");
        fs::write(&new_file, "New content").unwrap();

        add_to_archive(
            &archive_path,
            &[new_file.as_path()],
            &["subdir/new_file.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let files = list_archive(&archive_path).unwrap();
        assert!(files.contains(&"file1.txt".to_string()));
        assert!(files.contains(&"file2.txt".to_string()));
        assert!(files.contains(&"subdir/new_file.txt".to_string()));
    }

    #[test]
    fn test_add_bytes_to_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        add_bytes_to_archive(
            &archive_path,
            b"Hello from bytes!",
            "bytes_file.txt",
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let files = list_archive(&archive_path).unwrap();
        assert!(files.contains(&"bytes_file.txt".to_string()));
    }

    #[test]
    fn test_remove_from_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let files_before = list_archive(&archive_path).unwrap();
        assert_eq!(files_before.len(), 2);

        let removed = remove_from_archive(&archive_path, &["file1.txt"]).unwrap();
        assert_eq!(removed, 1);

        let files_after = list_archive(&archive_path).unwrap();
        assert_eq!(files_after.len(), 1);
        assert!(!files_after.contains(&"file1.txt".to_string()));
        assert!(files_after.contains(&"file2.txt".to_string()));
    }

    #[test]
    fn test_remove_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let removed = remove_from_archive(&archive_path, &["nonexistent.txt"]).unwrap();
        assert_eq!(removed, 0);

        let files = list_archive(&archive_path).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_rename_in_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        rename_in_archive(&archive_path, "file1.txt", "renamed.txt").unwrap();

        let files = list_archive(&archive_path).unwrap();
        assert!(!files.contains(&"file1.txt".to_string()));
        assert!(files.contains(&"renamed.txt".to_string()));
        assert!(files.contains(&"file2.txt".to_string()));
    }

    #[test]
    fn test_rename_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let result = rename_in_archive(&archive_path, "nonexistent.txt", "new_name.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_update_in_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        update_in_archive(
            &archive_path,
            "file1.txt",
            b"Updated content!",
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let files = list_archive(&archive_path).unwrap();
        assert!(files.contains(&"file1.txt".to_string()));
        assert_eq!(files.len(), 2);

        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir(&extract_dir).unwrap();
        crate::compression::decompress_file(&archive_path, &extract_dir, None, false).unwrap();

        let content = fs::read_to_string(extract_dir.join("file1.txt")).unwrap();
        assert_eq!(content, "Updated content!");
    }

    #[test]
    fn test_update_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let result = update_in_archive(
            &archive_path,
            "nonexistent.txt",
            b"New content",
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_variants() {
        let temp_dir = TempDir::new().unwrap();

        let file1 = temp_dir.path().join("file1.txt");
        fs::write(&file1, "Content 1").unwrap();
        let archive_path = temp_dir.path().join("test.zip");
        compress_file(
            &file1,
            &archive_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let archive_data = fs::read(&archive_path).unwrap();

        // Test add_to_archive_bytes
        let modified = add_to_archive_bytes(
            &archive_data,
            &[(b"New file content", "new.txt")],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let cursor = Cursor::new(&modified);
        let archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 2);

        // Test remove_from_archive_bytes
        let (modified, count) = remove_from_archive_bytes(&modified, &["new.txt"]).unwrap();
        assert_eq!(count, 1);

        let cursor = Cursor::new(&modified);
        let archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 1);

        // Test rename_in_archive_bytes
        let modified = rename_in_archive_bytes(&modified, "file1.txt", "renamed.txt").unwrap();

        let cursor = Cursor::new(&modified);
        let mut archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.by_index(0).unwrap().name(), "renamed.txt");

        // Test update_in_archive_bytes
        let modified = update_in_archive_bytes(
            &modified,
            "renamed.txt",
            b"Updated!",
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let cursor = Cursor::new(&modified);
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut file = archive.by_name("renamed.txt").unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "Updated!");
    }

    // Security tests

    #[test]
    fn test_validate_archive_name_rejects_parent_dir() {
        assert!(validate_archive_entry_name("../etc/passwd").is_err());
        assert!(validate_archive_entry_name("foo/../../../etc/passwd").is_err());
        assert!(validate_archive_entry_name("..\\Windows\\System32").is_err());
        assert!(validate_archive_entry_name("foo\\..\\..\\secret").is_err());
    }

    #[test]
    fn test_validate_archive_name_rejects_absolute_paths() {
        assert!(validate_archive_entry_name("/etc/passwd").is_err());
        assert!(validate_archive_entry_name("\\Windows\\System32").is_err());
        assert!(validate_archive_entry_name("C:\\Windows\\System32").is_err());
        assert!(validate_archive_entry_name("D:\\secret.txt").is_err());
    }

    #[test]
    fn test_validate_archive_name_rejects_null_bytes() {
        assert!(validate_archive_entry_name("file\0.txt").is_err());
        assert!(validate_archive_entry_name("foo/bar\0/baz").is_err());
    }

    #[test]
    fn test_validate_archive_name_rejects_empty() {
        assert!(validate_archive_entry_name("").is_err());
    }

    #[test]
    fn test_validate_archive_name_accepts_safe_names() {
        assert!(validate_archive_entry_name("file.txt").is_ok());
        assert!(validate_archive_entry_name("subdir/file.txt").is_ok());
        assert!(validate_archive_entry_name("a/b/c/d/file.txt").is_ok());
        assert!(validate_archive_entry_name("file with spaces.txt").is_ok());
        assert!(validate_archive_entry_name("文件.txt").is_ok());
        assert!(validate_archive_entry_name("..hidden").is_ok());
        assert!(validate_archive_entry_name("foo..bar").is_ok());
    }

    #[test]
    fn test_add_to_archive_rejects_path_traversal() {
        let temp_dir = TempDir::new().unwrap();

        let file1 = temp_dir.path().join("file1.txt");
        fs::write(&file1, "Content").unwrap();
        let archive_path = temp_dir.path().join("test.zip");
        compress_file(
            &file1,
            &archive_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file2, "Malicious").unwrap();

        let result = add_to_archive(
            &archive_path,
            &[file2.as_path()],
            &["../../../etc/malicious.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RustyZipError::PathTraversal(_)
        ));
    }

    #[test]
    fn test_custom_security_policy_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let policy = SecurityPolicy::new().with_max_modification_size(1);

        let new_file = temp_dir.path().join("new_file.txt");
        fs::write(&new_file, "Content").unwrap();

        let result = add_to_archive_with_policy(
            &archive_path,
            &[new_file.as_path()],
            &["new_file.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            &policy,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustyZipError::ZipBomb(_, _)));
    }

    #[test]
    fn test_duplicate_name_detection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let new_file = temp_dir.path().join("new_content.txt");
        fs::write(&new_file, "New content").unwrap();

        let result = add_to_archive(
            &archive_path,
            &[new_file.as_path()],
            &["file1.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
    }

    #[test]
    fn test_duplicate_names_in_input() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let file1 = temp_dir.path().join("a.txt");
        let file2 = temp_dir.path().join("b.txt");
        fs::write(&file1, "Content A").unwrap();
        fs::write(&file2, "Content B").unwrap();

        let result = add_to_archive(
            &archive_path,
            &[file1.as_path(), file2.as_path()],
            &["same_name.txt", "same_name.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
    }

    #[test]
    fn test_directory_rejection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let result = add_to_archive(
            &archive_path,
            &[subdir.as_path()],
            &["subdir"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
    }

    #[test]
    fn test_validate_archive_name_rejects_windows_reserved_chars() {
        assert!(validate_archive_entry_name("file<name.txt").is_err());
        assert!(validate_archive_entry_name("file>name.txt").is_err());
        assert!(validate_archive_entry_name("file:name.txt").is_err());
        assert!(validate_archive_entry_name("file\"name.txt").is_err());
        assert!(validate_archive_entry_name("file|name.txt").is_err());
        assert!(validate_archive_entry_name("file?name.txt").is_err());
        assert!(validate_archive_entry_name("file*name.txt").is_err());
    }

    #[test]
    fn test_validate_archive_name_rejects_windows_reserved_device_names() {
        assert!(validate_archive_entry_name("CON").is_err());
        assert!(validate_archive_entry_name("con").is_err());
        assert!(validate_archive_entry_name("Con.txt").is_err());
        assert!(validate_archive_entry_name("PRN").is_err());
        assert!(validate_archive_entry_name("AUX").is_err());
        assert!(validate_archive_entry_name("NUL").is_err());
        assert!(validate_archive_entry_name("COM1").is_err());
        assert!(validate_archive_entry_name("com9.dat").is_err());
        assert!(validate_archive_entry_name("LPT1").is_err());
        assert!(validate_archive_entry_name("lpt9.log").is_err());
        assert!(validate_archive_entry_name("subdir/CON").is_err());
        assert!(validate_archive_entry_name("subdir/nul.txt").is_err());
        // These should be OK - names that START with reserved names but aren't exact matches
        assert!(validate_archive_entry_name("CONSOLE").is_ok()); // Not "CON"
        assert!(validate_archive_entry_name("CONSOLE.txt").is_ok()); // Not "CON.txt"
        assert!(validate_archive_entry_name("console.log").is_ok()); // Not "con.log"
        assert!(validate_archive_entry_name("CONMAN.exe").is_ok()); // Not "CON.exe"
        assert!(validate_archive_entry_name("icon.png").is_ok());
        assert!(validate_archive_entry_name("COM10").is_ok()); // Only COM1-9 are reserved
        assert!(validate_archive_entry_name("LPT10.txt").is_ok()); // Only LPT1-9 are reserved
        assert!(validate_archive_entry_name("PRINTER.txt").is_ok()); // Not "PRN"
        assert!(validate_archive_entry_name("AUXILIARY.dat").is_ok()); // Not "AUX"
        assert!(validate_archive_entry_name("NULL.txt").is_ok()); // Not "NUL" (extra L)
    }

    #[test]
    fn test_validate_archive_name_rejects_control_characters() {
        assert!(validate_archive_entry_name("file\nname.txt").is_err());
        assert!(validate_archive_entry_name("file\rname.txt").is_err());
        assert!(validate_archive_entry_name("file\tname.txt").is_err());
        assert!(validate_archive_entry_name("file\x01name.txt").is_err());
        assert!(validate_archive_entry_name("file\x1Fname.txt").is_err());
    }

    #[test]
    fn test_rename_to_existing_name_fails() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let result = rename_in_archive(&archive_path, "file1.txt", "file2.txt");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
    }

    #[test]
    fn test_rename_to_same_name_succeeds() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let result = rename_in_archive(&archive_path, "file1.txt", "file1.txt");
        assert!(result.is_ok());

        let files = list_archive(&archive_path).unwrap();
        assert!(files.contains(&"file1.txt".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_rejection() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let target_file = temp_dir.path().join("target.txt");
        fs::write(&target_file, "Target content").unwrap();
        let symlink_path = temp_dir.path().join("symlink.txt");
        symlink(&target_file, &symlink_path).unwrap();

        let result = add_to_archive(
            &archive_path,
            &[symlink_path.as_path()],
            &["symlink.txt"],
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RustyZipError::SymlinkNotAllowed(_)
        ));
    }

    // Test for progress callback
    #[test]
    fn test_progress_callback() {
        let temp_dir = TempDir::new().unwrap();

        let file1 = temp_dir.path().join("file1.txt");
        fs::write(&file1, "Content 1").unwrap();
        let archive_path = temp_dir.path().join("test.zip");
        compress_file(
            &file1,
            &archive_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Test that ProgressEvent can be used
        let mut events = Vec::new();
        let mut callback = |event: ProgressEvent| {
            events.push(format!("{:?}", event));
        };

        // The callback type works
        let _: &mut dyn ProgressCallback = &mut callback;
    }
}
