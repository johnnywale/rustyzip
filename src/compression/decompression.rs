//! Decompression functionality for ZIP archives.

use super::security::{
    validate_output_path, DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE,
};
use super::types::EncryptionMethod;
use crate::error::{Result, RustyZipError};
use filetime::FileTime;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use zip::ZipArchive;

// =============================================================================
// Bounded Copy (Disk Exhaustion Protection)
// =============================================================================

/// Copy bytes from reader to writer with a hard limit.
///
/// This function protects against "lying header" ZIP bombs where the declared
/// size in the ZIP header is small but the actual decompressed data is huge.
/// Unlike `std::io::copy`, this function **stops immediately** when the limit
/// is reached, preventing disk exhaustion attacks.
///
/// # Arguments
/// * `reader` - Source to read from
/// * `writer` - Destination to write to
/// * `limit` - Maximum number of bytes to copy
///
/// # Returns
/// * `Ok(bytes_written)` if copy completed within limit
/// * `Err(ZipBomb)` if limit was exceeded
fn bounded_copy<R: Read, W: Write>(reader: &mut R, writer: &mut W, limit: u64) -> Result<u64> {
    const BUFFER_SIZE: usize = 64 * 1024; // 64 KB buffer
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_written: u64 = 0;

    loop {
        // Calculate how much we can still read without exceeding the limit
        let remaining = limit.saturating_sub(total_written);
        if remaining == 0 {
            // We've hit the limit - check if there's more data
            // Try to read one more byte to detect if the stream has more
            let mut probe = [0u8; 1];
            if reader.read(&mut probe)? > 0 {
                // There's more data - this is a ZIP bomb
                return Err(RustyZipError::ZipBomb(total_written + 1, limit));
            }
            // Stream ended exactly at limit - that's fine
            break;
        }

        // Read up to buffer size or remaining quota, whichever is smaller
        let to_read = std::cmp::min(BUFFER_SIZE as u64, remaining) as usize;
        let bytes_read = reader.read(&mut buffer[..to_read])?;

        if bytes_read == 0 {
            // End of stream
            break;
        }

        writer.write_all(&buffer[..bytes_read])?;
        total_written += bytes_read as u64;
    }

    Ok(total_written)
}

/// Detect the encryption method used in a ZIP file.
///
/// This function examines ALL files in the ZIP archive and returns:
/// - `EncryptionMethod::None` if no files are encrypted
/// - `EncryptionMethod::Aes256` if all encrypted files use AES-256
/// - `EncryptionMethod::ZipCrypto` if all encrypted files use ZipCrypto
/// - `EncryptionMethod::Mixed` if files use different encryption methods
///
/// # Arguments
/// * `path` - Path to the ZIP file
///
/// # Returns
/// The detected `EncryptionMethod`
pub fn detect_encryption(path: &Path) -> Result<EncryptionMethod> {
    if !path.exists() {
        return Err(RustyZipError::FileNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let archive = ZipArchive::new(file)?;
    detect_encryption_from_archive(archive)
}

/// Detect the encryption method from ZIP data in memory.
///
/// This function examines ALL files in the ZIP archive and returns:
/// - `EncryptionMethod::None` if no files are encrypted
/// - `EncryptionMethod::Aes256` if all encrypted files use AES-256
/// - `EncryptionMethod::ZipCrypto` if all encrypted files use ZipCrypto
/// - `EncryptionMethod::Mixed` if files use different encryption methods
///
/// # Arguments
/// * `data` - The ZIP archive data as bytes
///
/// # Returns
/// The detected `EncryptionMethod`
pub fn detect_encryption_bytes(data: &[u8]) -> Result<EncryptionMethod> {
    let cursor = Cursor::new(data);
    let archive = ZipArchive::new(cursor)?;
    detect_encryption_from_archive(archive)
}

/// Detect the encryption method for a single file entry.
/// Returns None for unencrypted files.
fn detect_single_file_encryption<R: Read>(
    file: &zip::read::ZipFile<'_, R>,
) -> Option<EncryptionMethod> {
    if !file.encrypted() {
        return None;
    }

    // Check for AES encryption by looking for AES extra field header (0x9901)
    // The extra data starts with the header ID in little-endian format
    if let Some(extra_data) = file.extra_data() {
        if extra_data.len() >= 2 && extra_data[0] == 0x01 && extra_data[1] == 0x99 {
            return Some(EncryptionMethod::Aes256);
        }
    }

    // Encrypted but no AES header = ZipCrypto
    Some(EncryptionMethod::ZipCrypto)
}

/// Internal function to detect encryption from a ZipArchive.
/// Scans all files and returns Mixed if inconsistent methods are detected.
fn detect_encryption_from_archive<R: Read + std::io::Seek>(
    mut archive: ZipArchive<R>,
) -> Result<EncryptionMethod> {
    let mut found_aes = false;
    let mut found_zipcrypto = false;
    let mut found_unencrypted = false;

    for i in 0..archive.len() {
        // Use by_index_raw to access file metadata without requiring decryption
        let file = archive.by_index_raw(i)?;

        // Skip directories
        if file.is_dir() {
            continue;
        }

        match detect_single_file_encryption(&file) {
            Some(EncryptionMethod::Aes256) => found_aes = true,
            Some(EncryptionMethod::ZipCrypto) => found_zipcrypto = true,
            None => found_unencrypted = true,
            _ => {} // Mixed won't be returned from detect_single_file_encryption
        }

        // Early exit if we already know it's mixed
        if found_aes && found_zipcrypto {
            return Ok(EncryptionMethod::Mixed);
        }
    }

    // Determine result based on what we found
    match (found_aes, found_zipcrypto, found_unencrypted) {
        // Pure encryption types
        (true, false, false) => Ok(EncryptionMethod::Aes256),
        (false, true, false) => Ok(EncryptionMethod::ZipCrypto),
        (false, false, _) => Ok(EncryptionMethod::None),
        // Mixed: different encryption types found
        (true, true, _) => Ok(EncryptionMethod::Mixed),
        // Mixed: some files encrypted, some not - this is also considered mixed
        (true, false, true) | (false, true, true) => Ok(EncryptionMethod::Mixed),
    }
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

        // === SYMLINK HANDLING ===
        // Check if this is a symlink entry (Unix mode with S_IFLNK flag: 0o120000)
        // NOTE: This check runs on ALL platforms, not just Unix. A ZIP created on Unix
        // may contain symlinks, and we need to detect and skip them even on Windows
        // to prevent security issues. Without this check, a Windows build would extract
        // symlinks as plain text files containing the target path, which could be confusing
        // or exploited in certain scenarios.
        if let Some(mode) = file.unix_mode() {
            const S_IFLNK: u32 = 0o120000;
            if (mode & 0o170000) == S_IFLNK {
                // This is a symlink - skip it for security
                // Symlinks could point to arbitrary locations
                log::debug!("Skipping symlink entry: {}", file.name());
                continue;
            }
        }

        // === ZIP BOMB PROTECTION (PRE-CHECK) ===
        // Check declared size and compression ratio BEFORE extraction
        let declared_size = file.size();
        let file_compressed_size = file.compressed_size();

        // Early ratio check based on declared sizes
        if file_compressed_size > 0 {
            let ratio = declared_size / file_compressed_size;
            if ratio > max_ratio {
                return Err(RustyZipError::SuspiciousCompressionRatio(ratio, max_ratio));
            }
        }

        // Early size check based on declared size
        if total_decompressed.saturating_add(declared_size) > max_size {
            return Err(RustyZipError::ZipBomb(
                total_decompressed + declared_size,
                max_size,
            ));
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

        // === BOUNDED EXTRACTION (CRITICAL SECURITY) ===
        // Calculate the maximum bytes we can write for this file
        // This is the smaller of:
        // 1. The remaining quota (max_size - total_decompressed)
        // 2. A generous multiple of declared size to allow for header lies
        let remaining_quota = max_size.saturating_sub(total_decompressed);
        // Allow up to 10x declared size or remaining quota, whichever is smaller
        // This catches "lying header" bombs while allowing legitimate files
        let file_limit = std::cmp::min(
            remaining_quota,
            declared_size.saturating_mul(10).saturating_add(1024 * 1024), // declared * 10 + 1MB
        );

        // Create output file
        let mut outfile = File::create(&outpath)?;

        // Use bounded_copy to prevent disk exhaustion
        // This stops IMMEDIATELY if limit is exceeded, not after filling the disk
        let bytes_written = match bounded_copy(&mut file, &mut outfile, file_limit) {
            Ok(written) => written,
            Err(e) => {
                // Clean up the partial file on error
                drop(outfile); // Close file handle first
                let _ = fs::remove_file(&outpath);
                return Err(e);
            }
        };

        // Update total with actual bytes written
        total_decompressed = total_decompressed.saturating_add(bytes_written);

        // Final size check (should not fail due to bounded_copy, but be defensive)
        if total_decompressed > max_size {
            let _ = fs::remove_file(&outpath);
            return Err(RustyZipError::ZipBomb(total_decompressed, max_size));
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

        // Skip symlinks (check Unix mode if available)
        // NOTE: Check runs on all platforms to detect symlinks from Unix-created ZIPs
        if let Some(mode) = file.unix_mode() {
            const S_IFLNK: u32 = 0o120000;
            if (mode & 0o170000) == S_IFLNK {
                log::debug!("Skipping symlink entry: {}", file.name());
                continue;
            }
        }

        // === ZIP BOMB PROTECTION (PRE-CHECK) ===
        let declared_size = file.size();
        let file_compressed_size = file.compressed_size();

        // Early ratio check
        if file_compressed_size > 0 {
            let ratio = declared_size / file_compressed_size;
            if ratio > max_ratio {
                return Err(RustyZipError::SuspiciousCompressionRatio(ratio, max_ratio));
            }
        }

        // Early size check
        if total_decompressed.saturating_add(declared_size) > max_size {
            return Err(RustyZipError::ZipBomb(
                total_decompressed + declared_size,
                max_size,
            ));
        }

        let name = file.name().to_string();

        // === BOUNDED EXTRACTION ===
        // Calculate the maximum bytes we can read for this file
        let remaining_quota = max_size.saturating_sub(total_decompressed);
        let file_limit = std::cmp::min(
            remaining_quota,
            declared_size.saturating_mul(10).saturating_add(1024 * 1024),
        );

        // Pre-allocate with declared size (capped for sanity)
        let capacity = std::cmp::min(declared_size as usize, 64 * 1024 * 1024);
        let mut content = Vec::with_capacity(capacity);

        // Use bounded_copy to read into memory with limit
        let bytes_read = bounded_copy(&mut file, &mut content, file_limit)?;

        // Update total with actual bytes read
        total_decompressed = total_decompressed.saturating_add(bytes_read);

        results.push((name, content));
    }

    Ok(results)
}
