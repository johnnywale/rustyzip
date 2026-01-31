//! Unified archive management with the "Handle" pattern.
//!
//! Provides a [`ZipHandle`] struct that maintains an open file handle and
//! in-memory representation of the archive index, allowing efficient batch
//! modifications with a single I/O pass.
//!
//! # Example
//! ```ignore
//! use rustyzip::compression::ZipHandle;
//!
//! let mut archive = ZipHandle::open("data.zip")?;
//!
//! // Queue multiple modifications
//! archive.rename("old_name.txt", "new_name.txt")?;
//! archive.remove("temp.log")?;
//! archive.add_bytes("new_file.txt", b"Hello, World!")?;
//!
//! // Commit all changes in a single atomic operation
//! archive.commit()?;
//! ```

use crate::error::{Result, RustyZipError};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zip::read::ZipArchive;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use super::security::validate_archive_entry_name;
use super::types::{CompressionLevel, EncryptionMethod};
use super::utils::add_bytes_to_zip;

/// Represents a pending operation on the archive.
#[derive(Debug, Clone)]
enum PendingOperation {
    /// Rename a file: (old_name, new_name)
    Rename { from: String, to: String },
    /// Remove a file
    Remove { name: String },
    /// Add new content
    Add {
        name: String,
        data: Vec<u8>,
        compression_level: CompressionLevel,
    },
    /// Update existing content
    Update {
        name: String,
        data: Vec<u8>,
        compression_level: CompressionLevel,
    },
}

/// A handle to an open ZIP archive that supports batch modifications.
///
/// Operations are queued in memory and only applied when [`commit()`](ZipHandle::commit)
/// is called, performing a single efficient I/O pass.
///
/// # Performance: The Cost of `commit()`
///
/// **Important**: `commit()` rewrites the ENTIRE archive. The ZIP format doesn't support
/// in-place modifications, so every commit creates a new archive file, copies all
/// unchanged entries, and atomically replaces the original.
///
/// For a 10 GB archive:
/// - **Good**: Queue multiple operations, call `commit()` once → copies 10 GB once
/// - **Bad**: Call `commit()` after each operation → copies 10 GB per operation
///
/// ```ignore
/// // GOOD: Batch operations (10 GB copied once)
/// archive.remove("a.txt")?;
/// archive.remove("b.txt")?;
/// archive.remove("c.txt")?;
/// archive.commit()?;  // Single rewrite
///
/// // BAD: Separate commits (30 GB copied total!)
/// archive.remove("a.txt")?;
/// archive.commit()?;  // Rewrites entire archive
/// archive.remove("b.txt")?;
/// archive.commit()?;  // Rewrites entire archive again
/// archive.remove("c.txt")?;
/// archive.commit()?;  // And again...
/// ```
///
/// # Thread Safety
/// `ZipHandle` is not thread-safe. For concurrent access, use external synchronization.
///
/// # Example
/// ```ignore
/// let mut archive = ZipHandle::open("archive.zip")?;
///
/// // These operations are queued, not immediately applied
/// archive.rename("old.txt", "new.txt")?;
/// archive.remove("unwanted.log")?;
///
/// // Check if we have pending changes
/// if archive.has_pending_changes() {
///     archive.commit()?; // Applies all changes atomically
/// }
/// ```
pub struct ZipHandle {
    /// Path to the archive file
    path: PathBuf,
    /// List of file names in the archive (cached)
    file_names: Vec<String>,
    /// Pending operations to apply on commit
    pending_operations: Vec<PendingOperation>,
    /// Password for encrypted archives
    password: Option<String>,
    /// Encryption method for new files
    encryption: EncryptionMethod,
}

impl ZipHandle {
    /// Open an existing ZIP archive.
    ///
    /// # Arguments
    /// * `path` - Path to the ZIP file
    ///
    /// # Errors
    /// Returns an error if the file doesn't exist or isn't a valid ZIP archive.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(RustyZipError::FileNotFound(path.display().to_string()));
        }

        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        let file_names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.by_index_raw(i).ok().map(|f| f.name().to_string()))
            .collect();

        Ok(Self {
            path: path.to_path_buf(),
            file_names,
            pending_operations: Vec::new(),
            password: None,
            encryption: EncryptionMethod::None,
        })
    }

    /// Create a new empty ZIP archive.
    ///
    /// # Arguments
    /// * `path` - Path where the archive will be created
    ///
    /// # Errors
    /// Returns an error if the file can't be created.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Create an empty ZIP file
        let file = File::create(path)?;
        let zip = ZipWriter::new(file);
        zip.finish()?;

        Ok(Self {
            path: path.to_path_buf(),
            file_names: Vec::new(),
            pending_operations: Vec::new(),
            password: None,
            encryption: EncryptionMethod::None,
        })
    }

    /// Set the password for encryption/decryption.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the encryption method for new files.
    pub fn with_encryption(mut self, encryption: EncryptionMethod) -> Self {
        self.encryption = encryption;
        self
    }

    /// Get the path to the archive.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get a list of all file names in the archive.
    ///
    /// This reflects the current state including pending operations.
    pub fn file_names(&self) -> Vec<String> {
        let mut names: HashSet<String> = self.file_names.iter().cloned().collect();

        // Apply pending operations to get current view
        for op in &self.pending_operations {
            match op {
                PendingOperation::Rename { from, to } => {
                    names.remove(from);
                    names.insert(to.clone());
                }
                PendingOperation::Remove { name } => {
                    names.remove(name);
                }
                PendingOperation::Add { name, .. } => {
                    names.insert(name.clone());
                }
                PendingOperation::Update { name, .. } => {
                    // Update doesn't change the name set
                    names.insert(name.clone());
                }
            }
        }

        names.into_iter().collect()
    }

    /// Check if a file exists in the archive (considering pending operations).
    pub fn contains(&self, name: &str) -> bool {
        self.file_names().iter().any(|n| n == name)
    }

    /// Get the number of files in the archive (considering pending operations).
    pub fn len(&self) -> usize {
        self.file_names().len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if there are pending changes to commit.
    pub fn has_pending_changes(&self) -> bool {
        !self.pending_operations.is_empty()
    }

    /// Get the number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending_operations.len()
    }

    /// Queue a rename operation.
    ///
    /// # Arguments
    /// * `from` - Current name of the file
    /// * `to` - New name for the file
    ///
    /// # Errors
    /// Returns an error if the source file doesn't exist or the target name is invalid.
    pub fn rename(&mut self, from: impl Into<String>, to: impl Into<String>) -> Result<()> {
        let from = from.into();
        let to = to.into();

        // Validate the new name
        validate_archive_entry_name(&to)?;

        // Check source exists (considering pending operations)
        if !self.contains(&from) {
            return Err(RustyZipError::FileNotFound(format!(
                "'{}' not found in archive",
                from
            )));
        }

        // Check target doesn't exist (unless it's the same as source)
        if from != to && self.contains(&to) {
            return Err(RustyZipError::InvalidPath(format!(
                "'{}' already exists in archive",
                to
            )));
        }

        self.pending_operations
            .push(PendingOperation::Rename { from, to });
        Ok(())
    }

    /// Queue a remove operation.
    ///
    /// # Arguments
    /// * `name` - Name of the file to remove
    ///
    /// # Errors
    /// Returns an error if the file doesn't exist.
    pub fn remove(&mut self, name: impl Into<String>) -> Result<()> {
        let name = name.into();

        if !self.contains(&name) {
            return Err(RustyZipError::FileNotFound(format!(
                "'{}' not found in archive",
                name
            )));
        }

        self.pending_operations
            .push(PendingOperation::Remove { name });
        Ok(())
    }

    /// Queue adding new content to the archive.
    ///
    /// # Arguments
    /// * `name` - Name for the new file in the archive
    /// * `data` - Content to add
    ///
    /// # Errors
    /// Returns an error if the name is invalid or already exists.
    pub fn add_bytes(&mut self, name: impl Into<String>, data: impl Into<Vec<u8>>) -> Result<()> {
        self.add_bytes_with_level(name, data, CompressionLevel::default())
    }

    /// Queue adding new content with a specific compression level.
    pub fn add_bytes_with_level(
        &mut self,
        name: impl Into<String>,
        data: impl Into<Vec<u8>>,
        compression_level: CompressionLevel,
    ) -> Result<()> {
        let name = name.into();
        let data = data.into();

        validate_archive_entry_name(&name)?;

        if self.contains(&name) {
            return Err(RustyZipError::InvalidPath(format!(
                "'{}' already exists in archive",
                name
            )));
        }

        self.pending_operations.push(PendingOperation::Add {
            name,
            data,
            compression_level,
        });
        Ok(())
    }

    /// Queue updating existing content in the archive.
    ///
    /// # Arguments
    /// * `name` - Name of the file to update
    /// * `data` - New content
    ///
    /// # Errors
    /// Returns an error if the file doesn't exist.
    pub fn update_bytes(
        &mut self,
        name: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Result<()> {
        self.update_bytes_with_level(name, data, CompressionLevel::default())
    }

    /// Queue updating existing content with a specific compression level.
    pub fn update_bytes_with_level(
        &mut self,
        name: impl Into<String>,
        data: impl Into<Vec<u8>>,
        compression_level: CompressionLevel,
    ) -> Result<()> {
        let name = name.into();
        let data = data.into();

        if !self.contains(&name) {
            return Err(RustyZipError::FileNotFound(format!(
                "'{}' not found in archive",
                name
            )));
        }

        self.pending_operations.push(PendingOperation::Update {
            name,
            data,
            compression_level,
        });
        Ok(())
    }

    /// Discard all pending operations.
    pub fn discard(&mut self) {
        self.pending_operations.clear();
    }

    /// Commit all pending operations to the archive.
    ///
    /// This performs a single efficient I/O pass, creating a new archive
    /// with all modifications and atomically replacing the original.
    ///
    /// # Errors
    /// Returns an error if the commit fails. On failure, the original archive
    /// is left unchanged.
    pub fn commit(&mut self) -> Result<()> {
        if self.pending_operations.is_empty() {
            return Ok(());
        }

        // Build a map of operations for efficient lookup
        let mut renames: HashMap<String, String> = HashMap::new();
        let mut removes: HashSet<String> = HashSet::new();
        let mut adds: HashMap<String, (Vec<u8>, CompressionLevel)> = HashMap::new();
        let mut updates: HashMap<String, (Vec<u8>, CompressionLevel)> = HashMap::new();

        for op in &self.pending_operations {
            match op {
                PendingOperation::Rename { from, to } => {
                    renames.insert(from.clone(), to.clone());
                }
                PendingOperation::Remove { name } => {
                    removes.insert(name.clone());
                }
                PendingOperation::Add {
                    name,
                    data,
                    compression_level,
                } => {
                    adds.insert(name.clone(), (data.clone(), *compression_level));
                }
                PendingOperation::Update {
                    name,
                    data,
                    compression_level,
                } => {
                    updates.insert(name.clone(), (data.clone(), *compression_level));
                }
            }
        }

        // Create temp file in the same directory for atomic rename
        let parent = self.path.parent().unwrap_or(Path::new("."));
        let temp_file = NamedTempFile::new_in(parent)?;
        let write_handle = temp_file.reopen()?;

        // Open source archive
        let source_file = File::open(&self.path)?;
        let mut source_archive = ZipArchive::new(source_file)?;

        // Create new archive
        let mut zip_writer = ZipWriter::new(write_handle);

        // Copy/transform existing entries
        for i in 0..source_archive.len() {
            let mut entry = source_archive.by_index_raw(i)?;
            let original_name = entry.name().to_string();

            // Skip removed files
            if removes.contains(&original_name) {
                continue;
            }

            // Determine the output name (handle renames)
            let output_name = renames
                .get(&original_name)
                .cloned()
                .unwrap_or_else(|| original_name.clone());

            // Check if this file is being updated
            if let Some((new_data, compression_level)) = updates.get(&original_name) {
                // Write updated content
                add_bytes_to_zip(
                    &mut zip_writer,
                    new_data,
                    &output_name,
                    self.password.as_deref(),
                    self.encryption,
                    *compression_level,
                )?;
            } else {
                // Copy file with raw data (preserves compression)
                let options = SimpleFileOptions::default()
                    .compression_method(entry.compression())
                    .last_modified_time(
                        entry
                            .last_modified()
                            .unwrap_or_else(zip::DateTime::default_for_write),
                    );

                zip_writer.start_file(&output_name, options)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                zip_writer.write_all(&data)?;
            }
        }

        // Add new files
        for (name, (data, compression_level)) in adds {
            add_bytes_to_zip(
                &mut zip_writer,
                &data,
                &name,
                self.password.as_deref(),
                self.encryption,
                compression_level,
            )?;
        }

        zip_writer.finish()?;

        // Close source archive before replacing
        drop(source_archive);

        // Atomic replace
        temp_file.persist(&self.path).map_err(|e| {
            RustyZipError::Io(std::io::Error::other(format!(
                "Failed to persist temp file: {}",
                e
            )))
        })?;

        // Update internal state
        self.file_names = self.file_names();
        self.pending_operations.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{compress_file, decompress_file};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_archive(temp_dir: &TempDir) -> PathBuf {
        let src1 = temp_dir.path().join("file1.txt");
        let src2 = temp_dir.path().join("file2.txt");
        fs::write(&src1, "Content of file 1").unwrap();
        fs::write(&src2, "Content of file 2").unwrap();

        let archive_path = temp_dir.path().join("test.zip");

        // Create archive with two files
        compress_file(
            &src1,
            &archive_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Add second file
        let mut handle = ZipHandle::open(&archive_path).unwrap();
        handle.add_bytes("file2.txt", "Content of file 2").unwrap();
        handle.commit().unwrap();

        archive_path
    }

    #[test]
    fn test_open_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let handle = ZipHandle::open(&archive_path).unwrap();
        assert_eq!(handle.len(), 2);
        assert!(handle.contains("file1.txt"));
        assert!(handle.contains("file2.txt"));
    }

    #[test]
    fn test_create_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("new.zip");

        let handle = ZipHandle::create(&archive_path).unwrap();
        assert!(handle.is_empty());
        assert!(archive_path.exists());
    }

    #[test]
    fn test_rename_operation() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        handle.rename("file1.txt", "renamed.txt").unwrap();
        assert!(handle.has_pending_changes());

        handle.commit().unwrap();

        // Verify the rename
        let handle = ZipHandle::open(&archive_path).unwrap();
        assert!(!handle.contains("file1.txt"));
        assert!(handle.contains("renamed.txt"));
    }

    #[test]
    fn test_remove_operation() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        assert_eq!(handle.len(), 2);

        handle.remove("file1.txt").unwrap();
        handle.commit().unwrap();

        let handle = ZipHandle::open(&archive_path).unwrap();
        assert_eq!(handle.len(), 1);
        assert!(!handle.contains("file1.txt"));
    }

    #[test]
    fn test_add_operation() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        handle.add_bytes("new_file.txt", "New content").unwrap();
        handle.commit().unwrap();

        let handle = ZipHandle::open(&archive_path).unwrap();
        assert_eq!(handle.len(), 3);
        assert!(handle.contains("new_file.txt"));
    }

    #[test]
    fn test_batch_operations() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();

        // Queue multiple operations
        handle.rename("file1.txt", "first.txt").unwrap();
        handle.remove("file2.txt").unwrap();
        handle.add_bytes("new.txt", "Brand new").unwrap();

        assert_eq!(handle.pending_count(), 3);

        // Commit all at once
        handle.commit().unwrap();

        let handle = ZipHandle::open(&archive_path).unwrap();
        assert_eq!(handle.len(), 2);
        assert!(handle.contains("first.txt"));
        assert!(handle.contains("new.txt"));
        assert!(!handle.contains("file1.txt"));
        assert!(!handle.contains("file2.txt"));
    }

    #[test]
    fn test_discard_operations() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        handle.remove("file1.txt").unwrap();
        assert!(handle.has_pending_changes());

        handle.discard();
        assert!(!handle.has_pending_changes());

        // Original archive should be unchanged
        let handle = ZipHandle::open(&archive_path).unwrap();
        assert!(handle.contains("file1.txt"));
    }

    #[test]
    fn test_update_operation() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        handle
            .update_bytes("file1.txt", "Updated content!")
            .unwrap();
        handle.commit().unwrap();

        // Extract and verify content
        let output_dir = temp_dir.path().join("output");
        fs::create_dir(&output_dir).unwrap();
        decompress_file(&archive_path, &output_dir, None, false).unwrap();

        let content = fs::read_to_string(output_dir.join("file1.txt")).unwrap();
        assert_eq!(content, "Updated content!");
    }

    #[test]
    fn test_error_rename_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        let result = handle.rename("nonexistent.txt", "new.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_add_duplicate() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir);

        let mut handle = ZipHandle::open(&archive_path).unwrap();
        let result = handle.add_bytes("file1.txt", "Duplicate");
        assert!(result.is_err());
    }
}
