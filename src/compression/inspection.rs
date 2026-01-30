//! Archive inspection functionality for ZIP archives.
//!
//! This module provides functions to inspect ZIP archive contents without extraction,
//! including listing files, getting metadata, and checking for specific files.

use super::types::EncryptionMethod;
use crate::error::{Result, RustyZipError};
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

/// Information about a single file in a ZIP archive.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// File name (including path within archive)
    pub name: String,
    /// Uncompressed size in bytes
    pub size: u64,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// Whether this entry is a directory
    pub is_dir: bool,
    /// Whether this file is encrypted
    pub is_encrypted: bool,
    /// CRC32 checksum
    pub crc32: u32,
    /// Compression method name
    pub compression_method: String,
    /// Last modified time as Unix timestamp (if available)
    pub last_modified: Option<i64>,
    /// Unix mode/permissions (if available)
    /// Contains file type and permission bits (e.g., 0o100755 for executable file)
    pub unix_mode: Option<u32>,
    /// Whether this is a symbolic link
    pub is_symlink: bool,
}

impl FileInfo {
    /// Calculate the compression ratio (uncompressed/compressed).
    /// Returns 1.0 for uncompressed files or directories.
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_size == 0 || self.is_dir {
            1.0
        } else {
            self.size as f64 / self.compressed_size as f64
        }
    }

    /// Check if this file is executable (Unix).
    /// Returns true if any execute bit is set.
    pub fn is_executable(&self) -> bool {
        self.unix_mode
            .map(|mode| mode & 0o111 != 0)
            .unwrap_or(false)
    }

    /// Get the permission bits only (without file type).
    /// Returns the lower 12 bits of the Unix mode.
    pub fn permissions(&self) -> Option<u32> {
        self.unix_mode.map(|mode| mode & 0o7777)
    }

    /// Get the file type from Unix mode.
    /// Returns S_IFREG, S_IFDIR, S_IFLNK, etc.
    pub fn file_type(&self) -> Option<u32> {
        self.unix_mode.map(|mode| mode & 0o170000)
    }
}

/// Summary information about a ZIP archive.
#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    /// Total number of entries (files and directories)
    pub total_entries: usize,
    /// Number of files (excluding directories)
    pub file_count: usize,
    /// Number of directories
    pub dir_count: usize,
    /// Total uncompressed size of all files
    pub total_size: u64,
    /// Total compressed size of all files
    pub total_compressed_size: u64,
    /// Encryption method used (None, ZipCrypto, or Aes256)
    pub encryption: EncryptionMethod,
    /// Whether the archive contains any encrypted files
    pub has_encrypted_files: bool,
    /// Archive comment (if any)
    pub comment: String,
}

impl ArchiveInfo {
    /// Calculate the overall compression ratio.
    pub fn compression_ratio(&self) -> f64 {
        if self.total_compressed_size == 0 {
            1.0
        } else {
            self.total_size as f64 / self.total_compressed_size as f64
        }
    }
}

/// List all files in a ZIP archive.
///
/// # Arguments
/// * `path` - Path to the ZIP file
///
/// # Returns
/// A vector of file names in the archive
pub fn list_archive(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    list_archive_from_reader(archive)
}

/// List all files in a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Returns
/// A vector of file names in the archive
pub fn list_archive_bytes(data: &[u8]) -> Result<Vec<String>> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    list_archive_from_reader(archive)
}

/// Internal function to list files from a ZipArchive reader.
fn list_archive_from_reader<R: Read + Seek>(mut archive: ZipArchive<R>) -> Result<Vec<String>> {
    let mut names = Vec::with_capacity(archive.len());

    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;
        names.push(file.name().to_string());
    }

    Ok(names)
}

/// Get detailed information about a ZIP archive.
///
/// # Arguments
/// * `path` - Path to the ZIP file
///
/// # Returns
/// Archive metadata including file count, total size, and encryption info
pub fn get_archive_info(path: &Path) -> Result<ArchiveInfo> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    get_archive_info_from_reader(archive)
}

/// Get detailed information about a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Returns
/// Archive metadata including file count, total size, and encryption info
pub fn get_archive_info_bytes(data: &[u8]) -> Result<ArchiveInfo> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    get_archive_info_from_reader(archive)
}

/// Internal function to get archive info from a ZipArchive reader.
fn get_archive_info_from_reader<R: Read + Seek>(mut archive: ZipArchive<R>) -> Result<ArchiveInfo> {
    let total_entries = archive.len();
    let mut file_count = 0;
    let mut dir_count = 0;
    let mut total_size: u64 = 0;
    let mut total_compressed_size: u64 = 0;
    let mut has_encrypted_files = false;
    let mut encryption = EncryptionMethod::None;

    for i in 0..total_entries {
        let file = archive.by_index_raw(i)?;

        if file.is_dir() {
            dir_count += 1;
        } else {
            file_count += 1;
            total_size = total_size.saturating_add(file.size());
            total_compressed_size = total_compressed_size.saturating_add(file.compressed_size());
        }

        if file.encrypted() && !has_encrypted_files {
            has_encrypted_files = true;
            // Detect encryption type
            if let Some(extra_data) = file.extra_data() {
                if extra_data.len() >= 2 && extra_data[0] == 0x01 && extra_data[1] == 0x99 {
                    encryption = EncryptionMethod::Aes256;
                } else {
                    encryption = EncryptionMethod::ZipCrypto;
                }
            } else {
                encryption = EncryptionMethod::ZipCrypto;
            }
        }
    }

    let comment = archive
        .comment()
        .iter()
        .map(|&b| b as char)
        .collect::<String>();

    Ok(ArchiveInfo {
        total_entries,
        file_count,
        dir_count,
        total_size,
        total_compressed_size,
        encryption,
        has_encrypted_files,
        comment,
    })
}

/// Get detailed information about a specific file in a ZIP archive.
///
/// # Arguments
/// * `path` - Path to the ZIP file
/// * `file_name` - Name of the file within the archive
///
/// # Returns
/// File metadata if found, or an error if the file doesn't exist
pub fn get_file_info(path: &Path, file_name: &str) -> Result<FileInfo> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    get_file_info_from_reader(archive, file_name)
}

/// Get detailed information about a specific file in a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
/// * `file_name` - Name of the file within the archive
///
/// # Returns
/// File metadata if found, or an error if the file doesn't exist
pub fn get_file_info_bytes(data: &[u8], file_name: &str) -> Result<FileInfo> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    get_file_info_from_reader(archive, file_name)
}

/// Internal function to get file info from a ZipArchive reader.
fn get_file_info_from_reader<R: Read + Seek>(
    mut archive: ZipArchive<R>,
    file_name: &str,
) -> Result<FileInfo> {
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;

        if file.name() == file_name {
            return Ok(extract_file_info(&file));
        }
    }

    Err(RustyZipError::FileNotFound(format!(
        "'{}' not found in archive",
        file_name
    )))
}

/// Get information about all files in a ZIP archive.
///
/// # Arguments
/// * `path` - Path to the ZIP file
///
/// # Returns
/// A vector of FileInfo for all entries in the archive
pub fn get_all_file_info(path: &Path) -> Result<Vec<FileInfo>> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    get_all_file_info_from_reader(archive)
}

/// Get information about all files in a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Returns
/// A vector of FileInfo for all entries in the archive
pub fn get_all_file_info_bytes(data: &[u8]) -> Result<Vec<FileInfo>> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    get_all_file_info_from_reader(archive)
}

/// Internal function to get all file info from a ZipArchive reader.
fn get_all_file_info_from_reader<R: Read + Seek>(
    mut archive: ZipArchive<R>,
) -> Result<Vec<FileInfo>> {
    let mut infos = Vec::with_capacity(archive.len());

    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;
        infos.push(extract_file_info(&file));
    }

    Ok(infos)
}

/// Extract FileInfo from a ZipFile entry.
fn extract_file_info<R: Read>(file: &zip::read::ZipFile<'_, R>) -> FileInfo {
    let compression_method = format!("{:?}", file.compression());

    let last_modified = file.last_modified().and_then(|dt| {
        use time::OffsetDateTime;
        OffsetDateTime::try_from(dt)
            .ok()
            .map(|t| t.unix_timestamp())
    });

    let unix_mode = file.unix_mode();

    // Check if this is a symlink (Unix mode S_IFLNK = 0o120000)
    let is_symlink = unix_mode
        .map(|mode| mode & 0o170000 == 0o120000)
        .unwrap_or(false);

    FileInfo {
        name: file.name().to_string(),
        size: file.size(),
        compressed_size: file.compressed_size(),
        is_dir: file.is_dir(),
        is_encrypted: file.encrypted(),
        crc32: file.crc32(),
        compression_method,
        last_modified,
        unix_mode,
        is_symlink,
    }
}

/// Check if a file exists in a ZIP archive.
///
/// # Arguments
/// * `path` - Path to the ZIP file
/// * `file_name` - Name of the file to check for
///
/// # Returns
/// true if the file exists in the archive, false otherwise
pub fn has_file(path: &Path, file_name: &str) -> Result<bool> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    has_file_from_reader(archive, file_name)
}

/// Check if a file exists in a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
/// * `file_name` - Name of the file to check for
///
/// # Returns
/// true if the file exists in the archive, false otherwise
pub fn has_file_bytes(data: &[u8], file_name: &str) -> Result<bool> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    has_file_from_reader(archive, file_name)
}

/// Internal function to check for file existence from a ZipArchive reader.
fn has_file_from_reader<R: Read + Seek>(
    mut archive: ZipArchive<R>,
    file_name: &str,
) -> Result<bool> {
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)?;
        if file.name() == file_name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A lazy iterator over files in a ZIP archive.
///
/// This iterator yields `FileInfo` items one at a time without loading
/// the entire archive contents into memory. Useful for large archives
/// or when you only need to process a subset of files.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::ArchiveIterator;
/// use std::path::Path;
///
/// let iter = ArchiveIterator::from_path(Path::new("archive.zip"))?;
/// for result in iter {
///     match result {
///         Ok(info) => println!("{}: {} bytes", info.name, info.size),
///         Err(e) => eprintln!("Error reading entry: {}", e),
///     }
/// }
///
/// // Or filter entries lazily
/// let iter = ArchiveIterator::from_path(Path::new("archive.zip"))?;
/// let large_files: Vec<_> = iter
///     .filter_map(|r| r.ok())
///     .filter(|info| info.size > 1_000_000)
///     .collect();
/// ```
pub struct ArchiveIterator<R: Read + Seek> {
    archive: ZipArchive<R>,
    current_index: usize,
    total_entries: usize,
}

impl ArchiveIterator<File> {
    /// Create an iterator from a file path.
    ///
    /// # Arguments
    /// * `path` - Path to the ZIP file
    ///
    /// # Errors
    /// Returns an error if the file doesn't exist or can't be opened as a ZIP archive.
    pub fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(RustyZipError::FileNotFound(path.display().to_string()));
        }

        let file = File::open(path)?;
        let archive = ZipArchive::new(file)?;
        let total_entries = archive.len();

        Ok(Self {
            archive,
            current_index: 0,
            total_entries,
        })
    }
}

impl<R: Read + Seek> ArchiveIterator<R> {
    /// Create an iterator from any reader that implements Read + Seek.
    ///
    /// # Arguments
    /// * `reader` - A reader containing ZIP archive data
    ///
    /// # Errors
    /// Returns an error if the data can't be parsed as a ZIP archive.
    pub fn from_reader(reader: R) -> Result<Self> {
        let archive = ZipArchive::new(reader)?;
        let total_entries = archive.len();

        Ok(Self {
            archive,
            current_index: 0,
            total_entries,
        })
    }

    /// Get the total number of entries in the archive.
    pub fn len(&self) -> usize {
        self.total_entries
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.total_entries == 0
    }

    /// Get the number of remaining entries to iterate.
    pub fn remaining(&self) -> usize {
        self.total_entries.saturating_sub(self.current_index)
    }

    /// Skip the next n entries.
    pub fn skip_entries(&mut self, n: usize) {
        self.current_index = self.current_index.saturating_add(n).min(self.total_entries);
    }

    /// Reset the iterator to the beginning.
    pub fn reset(&mut self) {
        self.current_index = 0;
    }
}

impl<R: Read + Seek> Iterator for ArchiveIterator<R> {
    type Item = Result<FileInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.total_entries {
            return None;
        }

        let result = self
            .archive
            .by_index_raw(self.current_index)
            .map(|file| extract_file_info(&file))
            .map_err(RustyZipError::from);

        self.current_index += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl<R: Read + Seek> ExactSizeIterator for ArchiveIterator<R> {}

/// Create an iterator over files in a ZIP archive from a path.
///
/// This is a convenience function that creates an [`ArchiveIterator`].
///
/// # Arguments
/// * `path` - Path to the ZIP file
///
/// # Example
/// ```ignore
/// use rustyzip::compression::iter_archive;
///
/// for result in iter_archive(Path::new("archive.zip"))? {
///     let info = result?;
///     println!("{}: {} bytes", info.name, info.size);
/// }
/// ```
pub fn iter_archive(path: &Path) -> Result<ArchiveIterator<File>> {
    ArchiveIterator::from_path(path)
}

/// Create an iterator over files in a ZIP archive from bytes.
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Example
/// ```ignore
/// use rustyzip::compression::iter_archive_bytes;
///
/// let data = std::fs::read("archive.zip")?;
/// for result in iter_archive_bytes(&data)? {
///     let info = result?;
///     println!("{}: {} bytes", info.name, info.size);
/// }
/// ```
pub fn iter_archive_bytes(data: &[u8]) -> Result<ArchiveIterator<Cursor<&[u8]>>> {
    let cursor = Cursor::new(data);
    ArchiveIterator::from_reader(cursor)
}

// ============================================================================
// Cached Archive (Pre-loaded Index for Fast Access)
// ============================================================================

/// A cached archive that pre-loads the central directory index for fast access.
///
/// This provides improved performance for repeated access by caching file
/// metadata in memory. Unlike memory mapping, this approach is safe and
/// works on all filesystems.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::CachedArchive;
///
/// let archive = CachedArchive::open("large_archive.zip")?;
/// println!("Archive has {} files", archive.len());
///
/// // Fast repeated access to file info
/// if let Some(info) = archive.get("important.txt") {
///     println!("Size: {} bytes", info.size);
/// }
/// ```
pub struct CachedArchive {
    /// Cached file information
    files: Vec<FileInfo>,
    /// Name to index lookup for fast access
    name_index: std::collections::HashMap<String, usize>,
    /// Archive summary
    archive_info: ArchiveInfo,
}

impl CachedArchive {
    /// Open a ZIP archive and cache its central directory.
    ///
    /// # Arguments
    /// * `path` - Path to the ZIP file
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file doesn't exist
    /// - The file isn't a valid ZIP archive
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(RustyZipError::FileNotFound(path.display().to_string()));
        }

        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        let mut files = Vec::with_capacity(archive.len());
        let mut name_index = std::collections::HashMap::with_capacity(archive.len());

        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i)?;
            let info = extract_file_info(&entry);
            name_index.insert(info.name.clone(), i);
            files.push(info);
        }

        // Re-open to get archive info
        let file = File::open(path)?;
        let archive = ZipArchive::new(file)?;
        let archive_info = get_archive_info_from_reader(archive)?;

        Ok(Self {
            files,
            name_index,
            archive_info,
        })
    }

    /// Open a ZIP archive from bytes and cache its central directory.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)?;

        let mut files = Vec::with_capacity(archive.len());
        let mut name_index = std::collections::HashMap::with_capacity(archive.len());

        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i)?;
            let info = extract_file_info(&entry);
            name_index.insert(info.name.clone(), i);
            files.push(info);
        }

        // Re-create to get archive info
        let cursor = Cursor::new(data);
        let archive = ZipArchive::new(cursor)?;
        let archive_info = get_archive_info_from_reader(archive)?;

        Ok(Self {
            files,
            name_index,
            archive_info,
        })
    }

    /// Get the number of entries in the archive.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get information about a specific file by index.
    pub fn get_by_index(&self, index: usize) -> Option<&FileInfo> {
        self.files.get(index)
    }

    /// Get information about a file by name.
    pub fn get(&self, name: &str) -> Option<&FileInfo> {
        self.name_index.get(name).and_then(|&i| self.files.get(i))
    }

    /// Check if a file exists in the archive.
    pub fn contains(&self, name: &str) -> bool {
        self.name_index.contains_key(name)
    }

    /// Get a list of all file names in the archive.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| f.name.as_str())
    }

    /// Get an iterator over all file information.
    pub fn iter(&self) -> impl Iterator<Item = &FileInfo> {
        self.files.iter()
    }

    /// Get the archive summary information.
    pub fn archive_info(&self) -> &ArchiveInfo {
        &self.archive_info
    }

    /// Get all files matching a glob pattern.
    pub fn find(&self, pattern: &str) -> Result<Vec<&FileInfo>> {
        let pat = glob::Pattern::new(pattern).map_err(RustyZipError::from)?;
        Ok(self.files.iter().filter(|f| pat.matches(&f.name)).collect())
    }

    /// Get files larger than a specified size.
    pub fn files_larger_than(&self, size: u64) -> impl Iterator<Item = &FileInfo> {
        self.files.iter().filter(move |f| f.size > size)
    }

    /// Get files with a specific extension.
    pub fn files_with_extension(&self, ext: &str) -> impl Iterator<Item = &FileInfo> + '_ {
        let ext_lower = ext.to_lowercase();
        self.files.iter().filter(move |f| {
            f.name
                .rsplit('.')
                .next()
                .map(|e| e.to_lowercase() == ext_lower)
                .unwrap_or(false)
        })
    }
}

/// Open a ZIP archive with cached central directory for fast repeated access.
///
/// This is a convenience function that creates a [`CachedArchive`].
///
/// # Arguments
/// * `path` - Path to the ZIP file
pub fn open_cached(path: &Path) -> Result<CachedArchive> {
    CachedArchive::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{compress_file, CompressionLevel, EncryptionMethod};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_archive(
        temp_dir: &TempDir,
        password: Option<&str>,
        encryption: EncryptionMethod,
    ) -> std::path::PathBuf {
        // Create a test file
        let src_path = temp_dir.path().join("test_file.txt");
        fs::write(&src_path, "Hello, World! This is test content.").unwrap();

        // Create archive
        let archive_path = temp_dir.path().join("test.zip");
        compress_file(
            &src_path,
            &archive_path,
            password,
            encryption,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        archive_path
    }

    #[test]
    fn test_list_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        let files = list_archive(&archive_path).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], "test_file.txt");
    }

    #[test]
    fn test_list_archive_not_found() {
        let result = list_archive(Path::new("/nonexistent/archive.zip"));
        assert!(result.is_err());
    }

    #[test]
    fn test_get_archive_info() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        let info = get_archive_info(&archive_path).unwrap();
        assert_eq!(info.total_entries, 1);
        assert_eq!(info.file_count, 1);
        assert_eq!(info.dir_count, 0);
        assert!(!info.has_encrypted_files);
        assert_eq!(info.encryption, EncryptionMethod::None);
    }

    #[test]
    fn test_get_archive_info_encrypted() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path =
            create_test_archive(&temp_dir, Some("password"), EncryptionMethod::Aes256);

        let info = get_archive_info(&archive_path).unwrap();
        assert!(info.has_encrypted_files);
        assert_eq!(info.encryption, EncryptionMethod::Aes256);
    }

    #[test]
    fn test_get_file_info() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        let info = get_file_info(&archive_path, "test_file.txt").unwrap();
        assert_eq!(info.name, "test_file.txt");
        assert!(!info.is_dir);
        assert!(!info.is_encrypted);
        assert!(info.size > 0);
    }

    #[test]
    fn test_get_file_info_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        let result = get_file_info(&archive_path, "nonexistent.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_has_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        assert!(has_file(&archive_path, "test_file.txt").unwrap());
        assert!(!has_file(&archive_path, "nonexistent.txt").unwrap());
    }

    #[test]
    fn test_get_all_file_info() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(&temp_dir, None, EncryptionMethod::None);

        let infos = get_all_file_info(&archive_path).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "test_file.txt");
    }

    #[test]
    fn test_compression_ratio() {
        let info = FileInfo {
            name: "test.txt".to_string(),
            size: 1000,
            compressed_size: 500,
            is_dir: false,
            is_encrypted: false,
            crc32: 0,
            compression_method: "Deflated".to_string(),
            last_modified: None,
            unix_mode: None,
            is_symlink: false,
        };

        assert!((info.compression_ratio() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_file_info_unix_mode() {
        let info = FileInfo {
            name: "script.sh".to_string(),
            size: 100,
            compressed_size: 50,
            is_dir: false,
            is_encrypted: false,
            crc32: 0,
            compression_method: "Deflated".to_string(),
            last_modified: None,
            unix_mode: Some(0o100755), // Regular file, executable
            is_symlink: false,
        };

        assert!(info.is_executable());
        assert_eq!(info.permissions(), Some(0o755));
        assert_eq!(info.file_type(), Some(0o100000)); // S_IFREG
    }

    #[test]
    fn test_file_info_symlink() {
        let info = FileInfo {
            name: "link".to_string(),
            size: 10,
            compressed_size: 10,
            is_dir: false,
            is_encrypted: false,
            crc32: 0,
            compression_method: "Stored".to_string(),
            last_modified: None,
            unix_mode: Some(0o120777), // Symlink
            is_symlink: true,
        };

        assert!(info.is_symlink);
        assert_eq!(info.file_type(), Some(0o120000)); // S_IFLNK
    }
}
