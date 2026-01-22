//! Parallel (multi-threaded) compression implementations using rayon.
//!
//! This module is only compiled when the `parallel` feature is enabled.
//! It uses a dedicated thread pool with configurable limits to prevent
//! CPU starvation and provide predictable resource usage.

use super::security::should_include_file;
use super::types::{CompressionLevel, EncryptionMethod};
use super::utils::{add_bytes_to_zip_with_time, add_file_to_zip, system_time_to_zip_datetime};
use crate::error::{Result, RustyZipError};
use glob::Pattern;
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;
use zip::ZipWriter;

/// Maximum file size for parallel loading (10 MB)
/// Files larger than this will be processed sequentially to avoid OOM
pub const PARALLEL_FILE_SIZE_THRESHOLD: u64 = 10 * 1024 * 1024;

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

    // Read and compress small files in parallel using dedicated thread pool
    let compressed_files: std::result::Result<Vec<CompressedFileData>, RustyZipError> =
        get_thread_pool().install(|| {
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

                    // Note: Do NOT pre-compress here. The ZIP writer in add_bytes_to_zip_with_time
                    // handles compression. Pre-compressing would cause double compression,
                    // resulting in extracted files containing raw deflate bytes.

                    Ok(CompressedFileData {
                        archive_name: archive_name.clone(),
                        data,
                        last_modified,
                    })
                })
                .collect()
        });

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

    // Read and compress small files in parallel using dedicated thread pool
    let compressed_files: std::result::Result<Vec<CompressedFileData>, RustyZipError> =
        get_thread_pool().install(|| {
            small_files
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
                .collect()
        });

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
