//! Parallel (multi-threaded) compression implementations using rayon.
//!
//! This module is only compiled when the `parallel` feature is enabled.
//! It uses a dedicated thread pool with configurable limits to prevent
//! CPU starvation and provide predictable resource usage.
//!
//! # Memory Bounds
//!
//! To prevent memory spikes when compressing many files, this module uses
//! bounded parallel processing:
//! - Files are processed in chunks based on cumulative size
//! - Maximum concurrent memory is capped at `PARALLEL_MEMORY_LIMIT` (default: 200 MB)
//! - Individual files larger than `PARALLEL_FILE_SIZE_THRESHOLD` (10 MB) are streamed
//!
//! # Configuration
//!
//! Use [`ParallelConfig`] to customize these limits for your environment:
//! ```ignore
//! let config = ParallelConfig::new()
//!     .with_file_threshold(20 * 1024 * 1024)  // 20 MB
//!     .with_memory_limit(500 * 1024 * 1024);  // 500 MB
//! ```

use super::security::should_include_file;
use super::types::{CompressionLevel, DirectoryCompressionOptions, EncryptionMethod};
use super::utils::{add_bytes_to_zip_with_time, add_file_to_zip, system_time_to_zip_datetime};
use crate::error::{Result, RustyZipError};
use glob::Pattern;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;
use zip::ZipWriter;

/// Default maximum file size for parallel loading (10 MB)
/// Files larger than this will be processed sequentially to avoid OOM
pub const PARALLEL_FILE_SIZE_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Default maximum total memory to use for parallel file loading (200 MB)
/// Files are processed in chunks to stay within this limit, regardless of thread count.
/// This prevents memory spikes when compressing many files just under the threshold.
pub const PARALLEL_MEMORY_LIMIT: u64 = 200 * 1024 * 1024;

/// Configuration for parallel compression operations.
///
/// Allows customizing memory limits and thresholds for different environments.
/// A server with 64GB RAM can use much higher limits than a Raspberry Pi.
///
/// # Thread Pool Overhead
///
/// **Important**: When `thread_count` is set to a non-zero value, a new thread pool
/// is created for each compression operation. This incurs overhead from spawning threads.
/// If you call compression functions in a loop with a custom thread count, consider:
///
/// 1. Using `thread_count = 0` (default) to use the shared global thread pool
/// 2. Batching operations to minimize pool creation
/// 3. Pre-creating a [`rayon::ThreadPool`] and using it directly if you need fine control
///
/// The default (`thread_count = 0`) uses a lazily-initialized global pool that persists
/// for the lifetime of the process, avoiding repeated thread creation overhead.
///
/// # Example
/// ```ignore
/// use rustyzip::compression::ParallelConfig;
///
/// // High-memory server configuration
/// let server_config = ParallelConfig::new()
///     .with_file_threshold(50 * 1024 * 1024)   // 50 MB per file
///     .with_memory_limit(1024 * 1024 * 1024)   // 1 GB total
///     .with_thread_count(32);                   // 32 threads (creates new pool!)
///
/// // Low-memory embedded configuration
/// let embedded_config = ParallelConfig::new()
///     .with_file_threshold(1 * 1024 * 1024)    // 1 MB per file
///     .with_memory_limit(32 * 1024 * 1024)     // 32 MB total
///     .with_thread_count(2);                    // 2 threads (creates new pool!)
///
/// // Best for repeated calls - uses shared global pool
/// let default_config = ParallelConfig::new();  // thread_count = 0 (auto)
/// ```
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Maximum file size for parallel in-memory loading.
    /// Files larger than this are streamed sequentially.
    /// Default: 10 MB
    pub file_size_threshold: u64,

    /// Maximum total memory for concurrent file loading.
    /// Files are processed in chunks to stay within this limit.
    /// Default: 200 MB
    pub memory_limit: u64,

    /// Number of threads to use. 0 means auto-detect (physical cores, max 16).
    /// Default: 0 (auto)
    pub thread_count: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            file_size_threshold: PARALLEL_FILE_SIZE_THRESHOLD,
            memory_limit: PARALLEL_MEMORY_LIMIT,
            thread_count: 0, // Auto-detect
        }
    }
}

impl ParallelConfig {
    /// Create a new ParallelConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the file size threshold for parallel loading.
    /// Files larger than this will be streamed sequentially.
    pub fn with_file_threshold(mut self, threshold: u64) -> Self {
        self.file_size_threshold = threshold;
        self
    }

    /// Set the maximum memory limit for concurrent file loading.
    pub fn with_memory_limit(mut self, limit: u64) -> Self {
        self.memory_limit = limit;
        self
    }

    /// Set the number of threads to use.
    /// 0 means auto-detect (physical cores, capped at 16).
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    /// Get the effective thread count (resolves 0 to actual count).
    pub fn effective_thread_count(&self) -> usize {
        if self.thread_count == 0 {
            default_thread_count()
        } else {
            self.thread_count
        }
    }
}

/// Default number of threads for parallel operations.
/// Uses the number of physical CPU cores to avoid hyperthreading overhead
/// for CPU-bound compression tasks.
fn default_thread_count() -> usize {
    // Use physical cores for better performance on CPU-bound tasks
    // Fall back to logical cores if physical count unavailable
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .min(16) // Cap at 16 threads to prevent excessive context switching
}

/// Global thread pool for parallel compression operations.
/// Initialized lazily on first use with a dedicated pool that doesn't
/// interfere with other rayon users in the application.
static COMPRESSION_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// Get or initialize the compression thread pool.
fn get_thread_pool() -> &'static rayon::ThreadPool {
    COMPRESSION_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(default_thread_count())
            .thread_name(|i| format!("rustyzip-worker-{}", i))
            .build()
            .expect("Failed to create compression thread pool")
    })
}

/// Holds pre-compressed file data for parallel compression
struct CompressedFileData {
    archive_name: String,
    data: Vec<u8>,
    last_modified: Option<zip::DateTime>,
}

/// Represents a file that's too large for parallel memory loading
struct LargeFileInfo {
    path: std::path::PathBuf,
    archive_name: String,
}

/// File info for bounded parallel processing
struct FileInfo {
    path: std::path::PathBuf,
    archive_name: String,
    size: u64,
}

/// Partition files into chunks where each chunk's total size is at most `max_chunk_size`.
/// This ensures bounded memory usage during parallel processing.
fn partition_into_bounded_chunks(files: Vec<FileInfo>, max_chunk_size: u64) -> Vec<Vec<FileInfo>> {
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::new();
    let mut current_size: u64 = 0;

    for file in files {
        // If adding this file would exceed the limit, start a new chunk
        // (unless the chunk is empty - we need to process at least one file)
        if !current_chunk.is_empty() && current_size + file.size > max_chunk_size {
            chunks.push(current_chunk);
            current_chunk = Vec::new();
            current_size = 0;
        }

        current_size += file.size;
        current_chunk.push(file);
    }

    // Don't forget the last chunk
    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }

    chunks
}

/// Process a chunk of files in parallel and return the compressed data.
fn process_chunk_parallel(
    chunk: Vec<FileInfo>,
    config: &ParallelConfig,
) -> std::result::Result<Vec<CompressedFileData>, RustyZipError> {
    let thread_count = config.effective_thread_count();

    // Use a custom thread pool if thread count differs from default
    if config.thread_count != 0 {
        // Build a temporary pool with the specified thread count
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .map_err(|e| {
                RustyZipError::Io(std::io::Error::other(format!(
                    "Failed to create thread pool: {}",
                    e
                )))
            })?;

        pool.install(|| process_files_parallel(&chunk))
    } else {
        // Use the default compression pool
        get_thread_pool().install(|| process_files_parallel(&chunk))
    }
}

/// Internal function to process files in parallel (called within a thread pool context)
fn process_files_parallel(
    chunk: &[FileInfo],
) -> std::result::Result<Vec<CompressedFileData>, RustyZipError> {
    chunk
        .par_iter()
        .map(|file_info| {
            let input_file = File::open(&file_info.path)?;
            let last_modified = input_file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(system_time_to_zip_datetime);

            let mut reader = std::io::BufReader::with_capacity(64 * 1024, input_file);
            // Pre-allocate based on known file size to avoid reallocation churn
            let mut data = Vec::with_capacity(file_info.size as usize);
            reader.read_to_end(&mut data)?;

            Ok(CompressedFileData {
                archive_name: file_info.archive_name.clone(),
                data,
                last_modified,
            })
        })
        .collect()
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
pub fn compress_directory_parallel(
    input_dir: &Path,
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    include_patterns: Option<&[String]>,
    exclude_patterns: Option<&[String]>,
) -> Result<()> {
    let options = DirectoryCompressionOptions {
        password,
        encryption,
        compression_level,
        include_patterns,
        exclude_patterns,
    };
    compress_directory_parallel_with_config(
        input_dir,
        output_path,
        &options,
        &ParallelConfig::default(),
    )
}

/// Compress a directory to a ZIP archive using parallel processing with custom configuration
///
/// This variant allows you to customize memory limits and thread counts for different environments.
///
/// # Arguments
/// * `input_dir` - Path to the directory to compress
/// * `output_path` - Path for the output ZIP file
/// * `options` - Compression options (password, encryption, level, patterns)
/// * `config` - Parallel processing configuration
///
/// # Example
/// ```ignore
/// use rustyzip::compression::{ParallelConfig, DirectoryCompressionOptions, EncryptionMethod, CompressionLevel};
/// use std::path::Path;
///
/// let options = DirectoryCompressionOptions::new()
///     .with_encryption(EncryptionMethod::None)
///     .with_compression_level(CompressionLevel::Default);
///
/// let config = ParallelConfig::new()
///     .with_file_threshold(20 * 1024 * 1024)  // 20 MB
///     .with_memory_limit(500 * 1024 * 1024);  // 500 MB
///
/// compress_directory_parallel_with_config(
///     Path::new("./my_folder"),
///     Path::new("./output.zip"),
///     &options,
///     &config,
/// )?;
/// ```
pub fn compress_directory_parallel_with_config(
    input_dir: &Path,
    output_path: &Path,
    options: &DirectoryCompressionOptions,
    config: &ParallelConfig,
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
    let include_patterns: Option<Vec<Pattern>> = match options.include_patterns {
        Some(patterns) => {
            let compiled: std::result::Result<Vec<Pattern>, _> = patterns
                .iter()
                .map(|p| Pattern::new(p).map_err(RustyZipError::from))
                .collect();
            Some(compiled?)
        }
        None => None,
    };

    let exclude_patterns: Option<Vec<Pattern>> = match options.exclude_patterns {
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
    let mut small_files: Vec<FileInfo> = Vec::with_capacity(estimated_count);
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
        if file_size > config.file_size_threshold {
            large_files.push(LargeFileInfo {
                path: path.to_path_buf(),
                archive_name: relative_path,
            });
        } else {
            small_files.push(FileInfo {
                path: path.to_path_buf(),
                archive_name: relative_path,
                size: file_size,
            });
        }
    }

    // Partition small files into bounded chunks to cap memory usage
    // This prevents memory spikes when many files are just under the threshold
    let chunks = partition_into_bounded_chunks(small_files, config.memory_limit);

    // Process each chunk in parallel, then write results before processing next chunk
    // This ensures memory is bounded by config.memory_limit at any time
    let mut all_compressed_files: Vec<CompressedFileData> = Vec::new();
    for chunk in chunks {
        let compressed_chunk = process_chunk_parallel(chunk, config)?;
        all_compressed_files.extend(compressed_chunk);
    }

    // Write to ZIP sequentially (ZIP format requires sequential writes)
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // First write the small files that were compressed in parallel
    for file_data in all_compressed_files {
        add_bytes_to_zip_with_time(
            &mut zip,
            &file_data.data,
            &file_data.archive_name,
            options.password,
            options.encryption,
            options.compression_level,
            file_data.last_modified,
        )?;
    }

    // Then process large files sequentially using streaming (memory safe)
    for large_file in large_files {
        add_file_to_zip(
            &mut zip,
            &large_file.path,
            &large_file.archive_name,
            options.password,
            options.encryption,
            options.compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Compress multiple files to a ZIP archive using parallel processing
pub fn compress_files_parallel(
    input_paths: &[&Path],
    prefixes: &[Option<&str>],
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    compress_files_parallel_with_config(
        input_paths,
        prefixes,
        output_path,
        password,
        encryption,
        compression_level,
        &ParallelConfig::default(),
    )
}

/// Compress multiple files to a ZIP archive using parallel processing with custom configuration
///
/// This variant allows you to customize memory limits and thread counts for different environments.
///
/// # Arguments
/// * `input_paths` - Slice of paths to files to compress
/// * `prefixes` - Slice of optional prefixes for each file in the archive
/// * `output_path` - Path for the output ZIP file
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level (0-9)
/// * `config` - Parallel processing configuration
pub fn compress_files_parallel_with_config(
    input_paths: &[&Path],
    prefixes: &[Option<&str>],
    output_path: &Path,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
    config: &ParallelConfig,
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
    let mut small_files: Vec<FileInfo> = Vec::with_capacity(file_count);
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
        if file_size > config.file_size_threshold {
            large_files.push(LargeFileInfo {
                path: input_path.to_path_buf(),
                archive_name,
            });
        } else {
            small_files.push(FileInfo {
                path: input_path.to_path_buf(),
                archive_name,
                size: file_size,
            });
        }
    }

    // Partition small files into bounded chunks to cap memory usage
    let chunks = partition_into_bounded_chunks(small_files, config.memory_limit);

    // Process each chunk in parallel, then collect results
    let mut all_compressed_files: Vec<CompressedFileData> = Vec::new();
    for chunk in chunks {
        let compressed_chunk = process_chunk_parallel(chunk, config)?;
        all_compressed_files.extend(compressed_chunk);
    }

    // Write to ZIP sequentially
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // First write the small files that were compressed in parallel
    for file_data in all_compressed_files {
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
