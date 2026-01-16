//! Streaming compression and decompression functions.

use super::security::{DEFAULT_MAX_COMPRESSION_RATIO, DEFAULT_MAX_DECOMPRESSED_SIZE};
use super::types::{CompressionLevel, EncryptionMethod};
use super::utils::add_reader_to_zip;
use crate::error::{Result, RustyZipError};
use std::io::{Read, Seek, Write};
use zip::{ZipArchive, ZipWriter};

/// Compress data from a reader to a writer in streaming fashion.
///
/// This function reads data in chunks and writes compressed output,
/// avoiding loading the entire file into memory.
///
/// # Arguments
/// * `output` - A Write + Seek destination for the ZIP archive
/// * `files` - Iterator of (archive_name, reader) pairs
/// * `password` - Optional password for encryption
/// * `encryption` - Encryption method to use
/// * `compression_level` - Compression level (0-9)
pub fn compress_stream<W, R, I>(
    output: W,
    files: I,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()>
where
    W: Write + Seek,
    R: Read,
    I: IntoIterator<Item = (String, R)>,
{
    let mut zip = ZipWriter::new(output);

    for (archive_name, mut reader) in files {
        add_reader_to_zip(
            &mut zip,
            &mut reader,
            &archive_name,
            password,
            encryption,
            compression_level,
        )?;
    }

    zip.finish()?;
    Ok(())
}

/// Decompress a ZIP archive from a seekable reader, returning file info.
///
/// # Arguments
/// * `input` - A Read + Seek source containing the ZIP archive
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_stream_to_vec<R>(
    input: R,
    password: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>>
where
    R: Read + Seek,
{
    decompress_stream_to_vec_with_limits(
        input,
        password,
        DEFAULT_MAX_DECOMPRESSED_SIZE,
        DEFAULT_MAX_COMPRESSION_RATIO,
    )
}

/// Decompress a ZIP archive from a seekable reader with configurable security limits.
///
/// # Arguments
/// * `input` - A Read + Seek source containing the ZIP archive
/// * `password` - Optional password for encrypted archives
/// * `max_size` - Maximum total decompressed size in bytes
/// * `max_ratio` - Maximum allowed compression ratio
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_stream_to_vec_with_limits<R>(
    input: R,
    password: Option<&str>,
    max_size: u64,
    max_ratio: u64,
) -> Result<Vec<(String, Vec<u8>)>>
where
    R: Read + Seek,
{
    let mut archive = ZipArchive::new(input)?;
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
        let capacity = (uncompressed_size as usize).min(64 * 1024 * 1024);
        let mut content = Vec::with_capacity(capacity);
        file.read_to_end(&mut content)?;

        // Verify actual size
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
