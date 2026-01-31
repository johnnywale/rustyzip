//! Sequential (single-threaded) compression implementations.

use super::security::should_include_file;
use super::types::{CompressionLevel, EncryptionMethod};
use super::utils::{add_bytes_to_zip, add_file_to_zip};
use crate::error::{Result, RustyZipError};
use glob::Pattern;
use std::fs::File;
use std::io::Cursor;
use std::path::Path;
use walkdir::WalkDir;
use zip::ZipWriter;

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
        .ok_or_else(|| {
            RustyZipError::InvalidPath(format!(
                "'{}' - cannot extract filename (path may contain invalid UTF-8 or be empty)",
                input_path.display()
            ))
        })?;

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

/// Sequential implementation of multi-file compression
#[allow(dead_code)] // Used when parallel feature is disabled
pub fn compress_files_sequential(
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
            .ok_or_else(|| {
                RustyZipError::InvalidPath(format!(
                    "'{}' - cannot extract filename (path may contain invalid UTF-8 or be empty)",
                    input_path.display()
                ))
            })?;

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

/// Sequential implementation of directory compression
#[allow(dead_code)] // Used when parallel feature is disabled
pub fn compress_directory_sequential(
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
