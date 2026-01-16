//! Decompression functionality for ZIP archives.

use super::security::{
    validate_output_path, DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE,
};
use crate::error::{Result, RustyZipError};
use filetime::FileTime;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

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

/// Decompress a ZIP archive from bytes in memory
///
/// # Arguments
/// * `data` - The ZIP archive data
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_bytes(data: &[u8], password: Option<&str>) -> Result<Vec<(String, Vec<u8>)>> {
    decompress_bytes_with_limits(
        data,
        password,
        DEFAULT_MAX_DECOMPRESSED_SIZE,
        DEFAULT_MAX_COMPRESSION_RATIO,
    )
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
