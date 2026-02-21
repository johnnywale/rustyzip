//! Internal utility functions for ZIP operations.

use super::types::{CompressionLevel, EncryptionMethod};
use crate::error::Result;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipWriter};

/// Convert a SystemTime to zip::DateTime
pub fn system_time_to_zip_datetime(system_time: std::time::SystemTime) -> Option<zip::DateTime> {
    use time::OffsetDateTime;

    let duration = system_time.duration_since(std::time::UNIX_EPOCH).ok()?;
    let datetime = OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64).ok()?;

    zip::DateTime::try_from(datetime).ok()
}

/// Add bytes directly to a ZIP writer
pub fn add_bytes_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    add_bytes_to_zip_with_time(
        zip,
        data,
        archive_name,
        password,
        encryption,
        compression_level,
        None,
    )
}

/// Add bytes directly to a ZIP writer with optional modification time
pub fn add_bytes_to_zip_with_time<W: Write + Seek>(
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

/// Add a single file to a ZIP writer using streaming (memory efficient)
pub fn add_file_to_zip<W: Write + Seek>(
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

/// Add data from a reader to the ZIP archive, streaming in chunks.
pub fn add_reader_to_zip<W, R>(
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
    add_reader_to_zip_with_time(
        zip,
        reader,
        archive_name,
        password,
        encryption,
        compression_level,
        None,
    )
}

/// Add data from a reader to the ZIP archive with optional modification time, streaming in chunks.
pub fn add_reader_to_zip_with_time<W, R>(
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
