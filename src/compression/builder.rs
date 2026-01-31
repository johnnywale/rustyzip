//! Builder pattern for compression operations.
//!
//! Provides a fluent API for configuring and executing compression operations
//! with many optional parameters.
//!
//! # Example
//! ```ignore
//! use rustyzip::compression::{CompressionBuilder, EncryptionMethod, CompressionLevel};
//! use std::path::Path;
//!
//! // Compress files with builder pattern
//! CompressionBuilder::new()
//!     .add_file(Path::new("file1.txt"))
//!     .add_file_with_prefix(Path::new("file2.txt"), "subdir")
//!     .output(Path::new("archive.zip"))
//!     .password("secret")
//!     .encryption(EncryptionMethod::Aes256)
//!     .compression_level(CompressionLevel::Best)
//!     .compress()?;
//!
//! // Compress directory with builder pattern
//! CompressionBuilder::new()
//!     .input_directory(Path::new("./my_folder"))
//!     .output(Path::new("archive.zip"))
//!     .include_patterns(&["*.rs", "*.toml"])
//!     .exclude_patterns(&["target/**"])
//!     .compress()?;
//!
//! // With progress callback
//! CompressionBuilder::new()
//!     .add_files(&[Path::new("file1.txt"), Path::new("file2.txt")])
//!     .output(Path::new("archive.zip"))
//!     .on_progress(|progress| {
//!         println!("Progress: {}/{} files ({}%)",
//!             progress.files_processed,
//!             progress.total_files,
//!             progress.percentage());
//!     })
//!     .compress()?;
//! ```

use crate::error::{Result, RustyZipError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::types::{
    CompressionLevel, DirectoryCompressionOptions, EncryptionMethod, SymlinkHandling,
};

#[cfg(feature = "parallel")]
use super::parallel::ParallelConfig;

/// Progress information for compression operations.
///
/// Passed to the progress callback during compression to report current state.
#[derive(Debug, Clone)]
pub struct CompressionProgress {
    /// Name of the current file being processed
    pub current_file: String,
    /// Number of files processed so far
    pub files_processed: usize,
    /// Total number of files to process
    pub total_files: usize,
    /// Bytes processed so far (across all files)
    pub bytes_processed: u64,
    /// Total bytes to process (if known)
    pub total_bytes: Option<u64>,
}

impl CompressionProgress {
    /// Calculate progress percentage (0-100).
    pub fn percentage(&self) -> u8 {
        if self.total_files == 0 {
            100
        } else {
            ((self.files_processed as f64 / self.total_files as f64) * 100.0) as u8
        }
    }

    /// Calculate byte progress percentage (0-100), if total is known.
    pub fn byte_percentage(&self) -> Option<u8> {
        self.total_bytes.map(|total| {
            if total == 0 {
                100
            } else {
                ((self.bytes_processed as f64 / total as f64) * 100.0) as u8
            }
        })
    }

    /// Check if compression is complete.
    pub fn is_complete(&self) -> bool {
        self.files_processed >= self.total_files
    }
}

/// Progress callback type for compression operations.
///
/// Called periodically during compression with current progress information.
///
/// # Thread Safety
///
/// The callback is wrapped in `Arc` and must be `Send + Sync` because it may be
/// called from **worker threads** in parallel compression mode. This means:
///
/// - You cannot capture `&mut` references directly
/// - Use interior mutability (`Mutex`, `AtomicUsize`, etc.) to update shared state
/// - Keep the callback fast to avoid blocking worker threads
///
/// # Example with Thread-Safe Counter
/// ```ignore
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::sync::Arc;
///
/// let files_done = Arc::new(AtomicUsize::new(0));
/// let files_done_clone = Arc::clone(&files_done);
///
/// Compressor::new()
///     .add_files(&paths)
///     .output("archive.zip")
///     .on_progress(move |progress| {
///         files_done_clone.store(progress.files_processed, Ordering::Relaxed);
///         // Update UI here (must be thread-safe!)
///     })
///     .compress()?;
///
/// println!("Compressed {} files", files_done.load(Ordering::Relaxed));
/// ```
pub type ProgressCallback = Arc<dyn Fn(&CompressionProgress) + Send + Sync>;

// ============================================================================
// Typestate Pattern Implementation
// ============================================================================

/// Marker type indicating no input has been specified.
#[derive(Debug, Clone, Copy)]
pub struct NoInput;

/// Marker type indicating files have been specified as input.
#[derive(Debug, Clone, Copy)]
pub struct HasFiles;

/// Marker type indicating a directory has been specified as input.
#[derive(Debug, Clone, Copy)]
pub struct HasDirectory;

/// Typestate builder for compression operations with compile-time safety.
///
/// This builder uses the typestate pattern to ensure that `compress()` can only
/// be called after an input (files or directory) has been specified.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::{Compressor, EncryptionMethod};
/// use std::path::Path;
///
/// // This compiles - input is specified
/// Compressor::new()
///     .add_file(Path::new("test.txt"))  // Returns Compressor<HasFiles>
///     .output(Path::new("archive.zip"))
///     .compress()?;  // Only available on Compressor<HasFiles> or Compressor<HasDirectory>
///
/// // This would NOT compile - no input specified
/// // Compressor::new()
/// //     .output(Path::new("archive.zip"))
/// //     .compress();  // Error: compress() not defined for Compressor<NoInput>
/// ```
pub struct Compressor<State = NoInput> {
    /// Individual files to compress
    files: Vec<(PathBuf, Option<String>)>,
    /// Directory to compress
    directory: Option<PathBuf>,
    /// Output path for the ZIP archive
    output: Option<PathBuf>,
    /// Password for encryption
    password: Option<String>,
    /// Encryption method
    encryption: EncryptionMethod,
    /// Compression level
    compression_level: CompressionLevel,
    /// Include patterns (for directory compression)
    include_patterns: Vec<String>,
    /// Exclude patterns (for directory compression)
    exclude_patterns: Vec<String>,
    /// Parallel configuration
    #[cfg(feature = "parallel")]
    parallel_config: Option<ParallelConfig>,
    /// Progress callback
    progress_callback: Option<ProgressCallback>,
    /// How to handle symbolic links during compression
    symlink_handling: SymlinkHandling,
    /// Phantom data to hold the state type
    _state: std::marker::PhantomData<State>,
}

impl Default for Compressor<NoInput> {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor<NoInput> {
    /// Create a new Compressor with no input specified.
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            directory: None,
            output: None,
            password: None,
            encryption: EncryptionMethod::default(),
            compression_level: CompressionLevel::default(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            #[cfg(feature = "parallel")]
            parallel_config: None,
            progress_callback: None,
            symlink_handling: SymlinkHandling::default(),
            _state: std::marker::PhantomData,
        }
    }

    /// Add a file to compress (transitions to HasFiles state).
    pub fn add_file(self, path: impl AsRef<Path>) -> Compressor<HasFiles> {
        let mut files = self.files;
        files.push((path.as_ref().to_path_buf(), None));
        Compressor {
            files,
            directory: self.directory,
            output: self.output,
            password: self.password,
            encryption: self.encryption,
            compression_level: self.compression_level,
            include_patterns: self.include_patterns,
            exclude_patterns: self.exclude_patterns,
            #[cfg(feature = "parallel")]
            parallel_config: self.parallel_config,
            progress_callback: self.progress_callback,
            symlink_handling: self.symlink_handling,
            _state: std::marker::PhantomData,
        }
    }

    /// Add multiple files to compress (transitions to HasFiles state).
    pub fn add_files(
        self,
        paths: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Compressor<HasFiles> {
        let mut files = self.files;
        for path in paths {
            files.push((path.as_ref().to_path_buf(), None));
        }
        Compressor {
            files,
            directory: self.directory,
            output: self.output,
            password: self.password,
            encryption: self.encryption,
            compression_level: self.compression_level,
            include_patterns: self.include_patterns,
            exclude_patterns: self.exclude_patterns,
            #[cfg(feature = "parallel")]
            parallel_config: self.parallel_config,
            progress_callback: self.progress_callback,
            symlink_handling: self.symlink_handling,
            _state: std::marker::PhantomData,
        }
    }

    /// Set a directory to compress (transitions to HasDirectory state).
    pub fn input_directory(self, path: impl AsRef<Path>) -> Compressor<HasDirectory> {
        Compressor {
            files: self.files,
            directory: Some(path.as_ref().to_path_buf()),
            output: self.output,
            password: self.password,
            encryption: self.encryption,
            compression_level: self.compression_level,
            include_patterns: self.include_patterns,
            exclude_patterns: self.exclude_patterns,
            #[cfg(feature = "parallel")]
            parallel_config: self.parallel_config,
            progress_callback: self.progress_callback,
            symlink_handling: self.symlink_handling,
            _state: std::marker::PhantomData,
        }
    }
}

impl Compressor<HasFiles> {
    /// Add another file to compress.
    pub fn add_file(mut self, path: impl AsRef<Path>) -> Self {
        self.files.push((path.as_ref().to_path_buf(), None));
        self
    }

    /// Add a file with a prefix (subdirectory in archive).
    pub fn add_file_with_prefix(
        mut self,
        path: impl AsRef<Path>,
        prefix: impl Into<String>,
    ) -> Self {
        self.files
            .push((path.as_ref().to_path_buf(), Some(prefix.into())));
        self
    }

    /// Conditionally add a file if the Option is Some.
    ///
    /// This is useful for fluent chains with conditional logic, avoiding
    /// the need to break the chain due to typestate transitions.
    ///
    /// # Example
    /// ```ignore
    /// let readme = if include_readme { Some("README.md") } else { None };
    /// Compressor::new()
    ///     .add_file("main.rs")
    ///     .add_optional_file(readme)  // Only added if Some
    ///     .output("archive.zip")
    ///     .compress()?;
    /// ```
    pub fn add_optional_file(mut self, path: Option<impl AsRef<Path>>) -> Self {
        if let Some(p) = path {
            self.files.push((p.as_ref().to_path_buf(), None));
        }
        self
    }

    /// Conditionally add a file with prefix if the Option is Some.
    pub fn add_optional_file_with_prefix(
        mut self,
        path: Option<impl AsRef<Path>>,
        prefix: impl Into<String>,
    ) -> Self {
        if let Some(p) = path {
            self.files
                .push((p.as_ref().to_path_buf(), Some(prefix.into())));
        }
        self
    }

    /// Add multiple files to compress.
    pub fn add_files(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        for path in paths {
            self.files.push((path.as_ref().to_path_buf(), None));
        }
        self
    }
}

/// Common methods available in all states
impl<S> Compressor<S> {
    /// Set the output path for the ZIP archive.
    pub fn output(mut self, path: impl AsRef<Path>) -> Self {
        self.output = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the password for encryption.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the encryption method.
    pub fn encryption(mut self, method: EncryptionMethod) -> Self {
        self.encryption = method;
        self
    }

    /// Set the compression level.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Set how symbolic links should be handled.
    pub fn symlink_handling(mut self, handling: SymlinkHandling) -> Self {
        self.symlink_handling = handling;
        self
    }

    /// Set parallel configuration for compression.
    #[cfg(feature = "parallel")]
    pub fn parallel_config(mut self, config: ParallelConfig) -> Self {
        self.parallel_config = Some(config);
        self
    }

    /// Set a progress callback.
    pub fn on_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(&CompressionProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }
}

impl Compressor<HasDirectory> {
    /// Add include patterns for directory compression.
    pub fn include_patterns(mut self, patterns: &[impl AsRef<str>]) -> Self {
        self.include_patterns
            .extend(patterns.iter().map(|p| p.as_ref().to_string()));
        self
    }

    /// Add exclude patterns for directory compression.
    pub fn exclude_patterns(mut self, patterns: &[impl AsRef<str>]) -> Self {
        self.exclude_patterns
            .extend(patterns.iter().map(|p| p.as_ref().to_string()));
        self
    }
}

/// Trait for states that can be compressed
pub trait CanCompress {
    fn do_compress(&self) -> Result<()>;
}

impl CanCompress for Compressor<HasFiles> {
    fn do_compress(&self) -> Result<()> {
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| RustyZipError::InvalidPath("No output path specified".to_string()))?;

        let password = self.password.as_deref();
        compress_files_internal(
            &self.files,
            output,
            password,
            self.encryption,
            self.compression_level,
            #[cfg(feature = "parallel")]
            self.parallel_config.as_ref(),
        )
    }
}

impl CanCompress for Compressor<HasDirectory> {
    fn do_compress(&self) -> Result<()> {
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| RustyZipError::InvalidPath("No output path specified".to_string()))?;

        let dir = self
            .directory
            .as_ref()
            .expect("HasDirectory state guarantees directory is set");

        let password = self.password.as_deref();
        let include = if self.include_patterns.is_empty() {
            None
        } else {
            Some(self.include_patterns.as_slice())
        };
        let exclude = if self.exclude_patterns.is_empty() {
            None
        } else {
            Some(self.exclude_patterns.as_slice())
        };

        let options = DirectoryCompressionOptions {
            password,
            encryption: self.encryption,
            compression_level: self.compression_level,
            include_patterns: include,
            exclude_patterns: exclude,
        };

        #[cfg(feature = "parallel")]
        {
            compress_directory_internal(dir, output, &options, self.parallel_config.as_ref())
        }

        #[cfg(not(feature = "parallel"))]
        {
            compress_directory_internal(dir, output, &options)
        }
    }
}

impl Compressor<HasFiles> {
    /// Execute the compression operation.
    ///
    /// This method is only available when files have been added.
    pub fn compress(&self) -> Result<()> {
        self.do_compress()
    }
}

impl Compressor<HasDirectory> {
    /// Execute the compression operation.
    ///
    /// This method is only available when a directory has been set.
    pub fn compress(&self) -> Result<()> {
        self.do_compress()
    }
}

// Internal helper functions for compression
#[cfg(feature = "parallel")]
fn compress_files_internal(
    files: &[(PathBuf, Option<String>)],
    output: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    parallel_config: Option<&ParallelConfig>,
) -> Result<()> {
    use super::parallel::{compress_files_parallel, compress_files_parallel_with_config};

    let paths: Vec<&Path> = files.iter().map(|(p, _)| p.as_path()).collect();
    let prefixes: Vec<Option<&str>> = files.iter().map(|(_, prefix)| prefix.as_deref()).collect();

    if let Some(config) = parallel_config {
        compress_files_parallel_with_config(
            &paths,
            &prefixes,
            output,
            password,
            encryption,
            compression_level,
            config,
        )
    } else {
        compress_files_parallel(
            &paths,
            &prefixes,
            output,
            password,
            encryption,
            compression_level,
        )
    }
}

#[cfg(not(feature = "parallel"))]
fn compress_files_internal(
    files: &[(PathBuf, Option<String>)],
    output: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    use super::sequential::compress_files_sequential;

    let paths: Vec<&Path> = files.iter().map(|(p, _)| p.as_path()).collect();
    let prefixes: Vec<Option<&str>> = files.iter().map(|(_, prefix)| prefix.as_deref()).collect();

    compress_files_sequential(
        &paths,
        &prefixes,
        output,
        password,
        encryption,
        compression_level,
    )
}

#[cfg(feature = "parallel")]
fn compress_directory_internal(
    dir: &Path,
    output: &Path,
    options: &DirectoryCompressionOptions,
    parallel_config: Option<&ParallelConfig>,
) -> Result<()> {
    use super::parallel::compress_directory_parallel_with_config;

    let config = parallel_config.cloned().unwrap_or_default();
    compress_directory_parallel_with_config(dir, output, options, &config)
}

#[cfg(not(feature = "parallel"))]
fn compress_directory_internal(
    dir: &Path,
    output: &Path,
    options: &DirectoryCompressionOptions,
) -> Result<()> {
    use super::sequential::compress_directory_sequential;
    compress_directory_sequential(
        dir,
        output,
        options.password,
        options.encryption,
        options.compression_level,
        options.include_patterns,
        options.exclude_patterns,
    )
}

// ============================================================================
// Original Builder (kept for backward compatibility)
// ============================================================================

/// Builder for compression operations.
///
/// Provides a fluent API for configuring compression with many optional parameters.
pub struct CompressionBuilder {
    /// Individual files to compress
    files: Vec<(PathBuf, Option<String>)>,
    /// Directory to compress (mutually exclusive with files)
    directory: Option<PathBuf>,
    /// Output path for the ZIP archive
    output: Option<PathBuf>,
    /// Password for encryption
    password: Option<String>,
    /// Encryption method
    encryption: EncryptionMethod,
    /// Compression level
    compression_level: CompressionLevel,
    /// Include patterns (for directory compression)
    include_patterns: Vec<String>,
    /// Exclude patterns (for directory compression)
    exclude_patterns: Vec<String>,
    /// Parallel configuration
    #[cfg(feature = "parallel")]
    parallel_config: Option<ParallelConfig>,
    /// Progress callback
    progress_callback: Option<ProgressCallback>,
    /// How to handle symbolic links during compression
    symlink_handling: SymlinkHandling,
}

impl Default for CompressionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressionBuilder {
    /// Create a new CompressionBuilder with default settings.
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            directory: None,
            output: None,
            password: None,
            encryption: EncryptionMethod::default(),
            compression_level: CompressionLevel::default(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            #[cfg(feature = "parallel")]
            parallel_config: None,
            progress_callback: None,
            symlink_handling: SymlinkHandling::default(),
        }
    }

    /// Add a file to compress (placed at root of archive).
    pub fn add_file(mut self, path: impl AsRef<Path>) -> Self {
        self.files.push((path.as_ref().to_path_buf(), None));
        self
    }

    /// Add a file to compress with a prefix (subdirectory in archive).
    pub fn add_file_with_prefix(
        mut self,
        path: impl AsRef<Path>,
        prefix: impl Into<String>,
    ) -> Self {
        self.files
            .push((path.as_ref().to_path_buf(), Some(prefix.into())));
        self
    }

    /// Add multiple files to compress.
    pub fn add_files(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        for path in paths {
            self.files.push((path.as_ref().to_path_buf(), None));
        }
        self
    }

    /// Set a directory to compress (mutually exclusive with individual files).
    pub fn input_directory(mut self, path: impl AsRef<Path>) -> Self {
        self.directory = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the output path for the ZIP archive.
    pub fn output(mut self, path: impl AsRef<Path>) -> Self {
        self.output = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the password for encryption.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the encryption method.
    pub fn encryption(mut self, method: EncryptionMethod) -> Self {
        self.encryption = method;
        self
    }

    /// Set the compression level.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Add include patterns for directory compression.
    pub fn include_patterns(mut self, patterns: &[impl AsRef<str>]) -> Self {
        self.include_patterns
            .extend(patterns.iter().map(|p| p.as_ref().to_string()));
        self
    }

    /// Add exclude patterns for directory compression.
    pub fn exclude_patterns(mut self, patterns: &[impl AsRef<str>]) -> Self {
        self.exclude_patterns
            .extend(patterns.iter().map(|p| p.as_ref().to_string()));
        self
    }

    /// Set parallel configuration for compression.
    #[cfg(feature = "parallel")]
    pub fn parallel_config(mut self, config: ParallelConfig) -> Self {
        self.parallel_config = Some(config);
        self
    }

    /// Set how symbolic links should be handled during compression.
    ///
    /// Options:
    /// - `SymlinkHandling::Follow` (default): Follow symlinks and store target content
    /// - `SymlinkHandling::Preserve`: Store symlinks as symlinks in the archive
    /// - `SymlinkHandling::Skip`: Don't include symlinks in the archive
    ///
    /// **Note**: Not all ZIP tools support symlinks. Symlinks are stored using
    /// Unix mode bits (S_IFLNK) with the target path as the file content.
    ///
    /// # Security Warning
    /// When extracting archives with symlinks, be careful to validate that
    /// symlink targets don't point outside the extraction directory (path traversal).
    pub fn symlink_handling(mut self, handling: SymlinkHandling) -> Self {
        self.symlink_handling = handling;
        self
    }

    /// Enable symlink preservation (shorthand for `symlink_handling(SymlinkHandling::Preserve)`).
    pub fn preserve_symlinks(self) -> Self {
        self.symlink_handling(SymlinkHandling::Preserve)
    }

    /// Skip symlinks entirely (shorthand for `symlink_handling(SymlinkHandling::Skip)`).
    pub fn skip_symlinks(self) -> Self {
        self.symlink_handling(SymlinkHandling::Skip)
    }

    /// Set a progress callback to monitor compression progress.
    ///
    /// The callback will be called periodically during compression with
    /// information about the current progress.
    ///
    /// # Example
    /// ```ignore
    /// CompressionBuilder::new()
    ///     .add_files(&paths)
    ///     .output(Path::new("archive.zip"))
    ///     .on_progress(|progress| {
    ///         println!("Processing: {} ({}/{})",
    ///             progress.current_file,
    ///             progress.files_processed,
    ///             progress.total_files);
    ///     })
    ///     .compress()?;
    /// ```
    pub fn on_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(&CompressionProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Execute the compression operation.
    ///
    /// # Errors
    /// - `InvalidPath` if no output path is specified
    /// - `InvalidPath` if neither files nor directory is specified
    /// - Various IO and ZIP errors during compression
    pub fn compress(&self) -> Result<()> {
        let output = self
            .output
            .as_ref()
            .ok_or_else(|| RustyZipError::InvalidPath("No output path specified".to_string()))?;

        let password = self.password.as_deref();

        // Directory compression
        if let Some(ref dir) = self.directory {
            let include = if self.include_patterns.is_empty() {
                None
            } else {
                Some(self.include_patterns.as_slice())
            };
            let exclude = if self.exclude_patterns.is_empty() {
                None
            } else {
                Some(self.exclude_patterns.as_slice())
            };

            let options = DirectoryCompressionOptions {
                password,
                encryption: self.encryption,
                compression_level: self.compression_level,
                include_patterns: include,
                exclude_patterns: exclude,
            };
            return self.compress_directory_internal(dir, output, &options);
        }

        // Files compression
        if !self.files.is_empty() {
            return self.compress_files_internal(output, password);
        }

        Err(RustyZipError::InvalidPath(
            "No files or directory specified for compression".to_string(),
        ))
    }

    #[cfg(feature = "parallel")]
    fn compress_directory_internal(
        &self,
        dir: &Path,
        output: &Path,
        options: &DirectoryCompressionOptions,
    ) -> Result<()> {
        use super::parallel::compress_directory_parallel_with_config;

        let config = self.parallel_config.clone().unwrap_or_default();
        compress_directory_parallel_with_config(dir, output, options, &config)
    }

    #[cfg(not(feature = "parallel"))]
    fn compress_directory_internal(
        &self,
        dir: &Path,
        output: &Path,
        options: &DirectoryCompressionOptions,
    ) -> Result<()> {
        use super::sequential::compress_directory_sequential;
        compress_directory_sequential(
            dir,
            output,
            options.password,
            options.encryption,
            options.compression_level,
            options.include_patterns,
            options.exclude_patterns,
        )
    }

    #[cfg(feature = "parallel")]
    fn compress_files_internal(&self, output: &Path, password: Option<&str>) -> Result<()> {
        use super::parallel::{compress_files_parallel, compress_files_parallel_with_config};

        let paths: Vec<&Path> = self.files.iter().map(|(p, _)| p.as_path()).collect();
        let prefixes: Vec<Option<&str>> = self
            .files
            .iter()
            .map(|(_, prefix)| prefix.as_deref())
            .collect();

        if let Some(ref config) = self.parallel_config {
            compress_files_parallel_with_config(
                &paths,
                &prefixes,
                output,
                password,
                self.encryption,
                self.compression_level,
                config,
            )
        } else {
            compress_files_parallel(
                &paths,
                &prefixes,
                output,
                password,
                self.encryption,
                self.compression_level,
            )
        }
    }

    #[cfg(not(feature = "parallel"))]
    fn compress_files_internal(&self, output: &Path, password: Option<&str>) -> Result<()> {
        use super::sequential::compress_files_sequential;

        let paths: Vec<&Path> = self.files.iter().map(|(p, _)| p.as_path()).collect();
        let prefixes: Vec<Option<&str>> = self
            .files
            .iter()
            .map(|(_, prefix)| prefix.as_deref())
            .collect();

        compress_files_sequential(
            &paths,
            &prefixes,
            output,
            password,
            self.encryption,
            self.compression_level,
        )
    }
}
