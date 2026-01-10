use crate::error::{Result, RustyZipError};
use glob::Pattern;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

/// Encryption method for password-protected archives
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionMethod {
    /// AES-256 encryption (strong, requires 7-Zip/WinRAR to open)
    Aes256,
    /// ZipCrypto encryption (weak, Windows Explorer compatible)
    ZipCrypto,
    /// No encryption
    None,
}

impl Default for EncryptionMethod {
    fn default() -> Self {
        EncryptionMethod::Aes256
    }
}

impl EncryptionMethod {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes256" | "aes" | "aes-256" => Ok(EncryptionMethod::Aes256),
            "zipcrypto" | "zip_crypto" | "legacy" => Ok(EncryptionMethod::ZipCrypto),
            "none" | "" => Ok(EncryptionMethod::None),
            _ => Err(RustyZipError::UnsupportedEncryption(s.to_string())),
        }
    }
}

/// Compression level (0-9)
#[derive(Debug, Clone, Copy)]

pub struct CompressionLevel(pub u32);

impl Default for CompressionLevel {
    fn default() -> Self {
        CompressionLevel::DEFAULT
    }
}

impl CompressionLevel {
    #[allow(dead_code)]
    pub const STORE: CompressionLevel = CompressionLevel(0);
    #[allow(dead_code)]
    pub const FAST: CompressionLevel = CompressionLevel(1);
    #[allow(dead_code)]
    pub const DEFAULT: CompressionLevel = CompressionLevel(6);
    #[allow(dead_code)]
    pub const BEST: CompressionLevel = CompressionLevel(9);

    pub fn new(level: u32) -> Self {
        CompressionLevel(level.min(9))
    }
    #[allow(dead_code)]
    pub fn to_flate2_compression(self) -> flate2::Compression {
        flate2::Compression::new(self.0)
    }
}

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
        .ok_or_else(|| RustyZipError::InvalidPath(input_path.display().to_string()))?;

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

/// Compress multiple files to a ZIP archive
pub fn compress_files(
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
            .ok_or_else(|| RustyZipError::InvalidPath(input_path.display().to_string()))?;

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

/// Compress a directory to a ZIP archive
pub fn compress_directory(
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

/// Check if a file should be included based on include/exclude patterns
fn should_include_file(
    path: &Path,
    relative_path: &str,
    include_patterns: Option<&Vec<Pattern>>,
    exclude_patterns: Option<&Vec<Pattern>>,
) -> bool {
    // Check include patterns - file must match at least one
    if let Some(patterns) = include_patterns {
        let matches_relative = patterns.iter().any(|p| p.matches(relative_path));
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let matches_filename = patterns.iter().any(|p| p.matches(file_name));
        if !matches_relative && !matches_filename {
            return false;
        }
    }

    // Check exclude patterns - file must not match any
    if let Some(patterns) = exclude_patterns {
        // Check relative path
        if patterns.iter().any(|p| p.matches(relative_path)) {
            return false;
        }
        // Check filename
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if patterns.iter().any(|p| p.matches(file_name)) {
            return false;
        }
        // Check if any parent directory matches exclude pattern
        let ancestor_matches = path.ancestors().any(|ancestor| {
            ancestor
                .file_name()
                .and_then(|n| n.to_str())
                .map(|name| patterns.iter().any(|p| p.matches(name)))
                .unwrap_or(false)
        });
        if ancestor_matches {
            return false;
        }
    }

    true
}

/// Add bytes directly to a ZIP writer
fn add_bytes_to_zip<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    data: &[u8],
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    let (compression_method, level_option) = if compression_level.0 == 0 {
        (CompressionMethod::Stored, None)
    } else {
        (
            CompressionMethod::Deflated,
            Some(compression_level.0 as i64),
        )
    };

    let base_options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(level_option);

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

/// Add a single file to a ZIP writer
fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    archive_name: &str,
    password: Option<&str>,
    encryption: EncryptionMethod,
    compression_level: CompressionLevel,
) -> Result<()> {
    let mut input_file = File::open(file_path)?;
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    add_bytes_to_zip(
        zip,
        &data,
        archive_name,
        password,
        encryption,
        compression_level,
    )
}

/// Decompress a ZIP archive
pub fn decompress_file(
    input_path: &Path,
    output_path: &Path,
    password: Option<&str>,
) -> Result<()> {
    if !input_path.exists() {
        return Err(RustyZipError::FileNotFound(
            input_path.display().to_string(),
        ));
    }

    let file = File::open(input_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Create output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path)?;
    }

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

        let outpath = output_path.join(file.mangled_name());

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

/// Delete a file
pub fn delete_file(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
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

/// Decompress a ZIP archive from bytes in memory
///
/// # Arguments
/// * `data` - The ZIP archive data
/// * `password` - Optional password for encrypted archives
///
/// # Returns
/// A vector of (filename, content) tuples
pub fn decompress_bytes(data: &[u8], password: Option<&str>) -> Result<Vec<(String, Vec<u8>)>> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    let mut results = Vec::new();

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

        let name = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        results.push((name, content));
    }

    Ok(results)
}

// ============================================================================
// Streaming Compression Functions
// ============================================================================

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

/// Add data from a reader to the ZIP archive, streaming in chunks.
fn add_reader_to_zip<W, R>(
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
    let (compression_method, level_option) = if compression_level.0 == 0 {
        (CompressionMethod::Stored, None)
    } else {
        (
            CompressionMethod::Deflated,
            Some(compression_level.0 as i64),
        )
    };

    let base_options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(level_option);

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
    let mut archive = ZipArchive::new(input)?;
    let mut results = Vec::new();

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

        let name = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        results.push((name, content));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_compress_decompress_no_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_file = extract_path.join("test.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_compress_decompress_with_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("secret.txt");
        let output_path = temp_dir.path().join("secret.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Secret data").unwrap();

        // Compress with AES-256
        compress_file(
            &input_path,
            &output_path,
            Some("password123"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress with correct password
        decompress_file(&output_path, &extract_path, Some("password123")).unwrap();

        let extracted_file = extract_path.join("secret.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "Secret data");
    }

    #[test]
    fn test_encryption_method_from_str() {
        assert_eq!(
            EncryptionMethod::from_str("aes256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("zipcrypto").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("none").unwrap(),
            EncryptionMethod::None
        );
        assert!(EncryptionMethod::from_str("invalid").is_err());
    }

    #[test]
    fn test_encryption_method_from_str_case_insensitive() {
        assert_eq!(
            EncryptionMethod::from_str("AES256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("AES").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("aes-256").unwrap(),
            EncryptionMethod::Aes256
        );
        assert_eq!(
            EncryptionMethod::from_str("ZIPCRYPTO").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("zip_crypto").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("legacy").unwrap(),
            EncryptionMethod::ZipCrypto
        );
        assert_eq!(
            EncryptionMethod::from_str("NONE").unwrap(),
            EncryptionMethod::None
        );
        assert_eq!(
            EncryptionMethod::from_str("").unwrap(),
            EncryptionMethod::None
        );
    }

    #[test]
    fn test_compression_level_new() {
        assert_eq!(CompressionLevel::new(0).0, 0);
        assert_eq!(CompressionLevel::new(5).0, 5);
        assert_eq!(CompressionLevel::new(9).0, 9);
        // Should clamp to 9
        assert_eq!(CompressionLevel::new(10).0, 9);
        assert_eq!(CompressionLevel::new(100).0, 9);
    }

    #[test]
    fn test_compression_level_constants() {
        assert_eq!(CompressionLevel::STORE.0, 0);
        assert_eq!(CompressionLevel::FAST.0, 1);
        assert_eq!(CompressionLevel::DEFAULT.0, 6);
        assert_eq!(CompressionLevel::BEST.0, 9);
    }

    #[test]
    fn test_compress_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("test.zip");

        let result = compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_decompress_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.zip");
        let output_path = temp_dir.path().join("extracted");

        let result = decompress_file(&input_path, &output_path, None);

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_decompress_wrong_password() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("secret.txt");
        let output_path = temp_dir.path().join("secret.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"Secret data").unwrap();

        // Compress with password
        compress_file(
            &input_path,
            &output_path,
            Some("correct_password"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Try to decompress with wrong password
        let result = decompress_file(&output_path, &extract_path, Some("wrong_password"));

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPassword => {}
            e => panic!("Expected InvalidPassword error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_decompress_zipcrypto() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("zipcrypto.txt");
        let output_path = temp_dir.path().join("zipcrypto.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test file
        let mut file = File::create(&input_path).unwrap();
        file.write_all(b"ZipCrypto encrypted content").unwrap();

        // Compress with ZipCrypto
        compress_file(
            &input_path,
            &output_path,
            Some("password"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, Some("password")).unwrap();

        let extracted_file = extract_path.join("zipcrypto.txt");
        assert!(extracted_file.exists());

        let content = fs::read_to_string(extracted_file).unwrap();
        assert_eq!(content, "ZipCrypto encrypted content");
    }

    #[test]
    fn test_compress_multiple_files() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");
        let output_path = temp_dir.path().join("multi.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test files
        fs::write(&file1, "Content of file 1").unwrap();
        fs::write(&file2, "Content of file 2").unwrap();
        fs::write(&file3, "Content of file 3").unwrap();

        // Compress multiple files
        compress_files(
            &[file1.as_path(), file2.as_path(), file3.as_path()],
            &[None, None, None],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(output_path.exists());

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        // Verify all files
        assert_eq!(
            fs::read_to_string(extract_path.join("file1.txt")).unwrap(),
            "Content of file 1"
        );
        assert_eq!(
            fs::read_to_string(extract_path.join("file2.txt")).unwrap(),
            "Content of file 2"
        );
        assert_eq!(
            fs::read_to_string(extract_path.join("file3.txt")).unwrap(),
            "Content of file 3"
        );
    }

    #[test]
    fn test_compress_files_with_prefixes() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let output_path = temp_dir.path().join("prefixed.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create test files
        fs::write(&file1, "File 1").unwrap();
        fs::write(&file2, "File 2").unwrap();

        // Compress with prefixes
        compress_files(
            &[file1.as_path(), file2.as_path()],
            &[Some("dir1"), Some("dir2/subdir")],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        // Verify files are in correct directories
        assert!(extract_path.join("dir1").join("file1.txt").exists());
        assert!(extract_path
            .join("dir2")
            .join("subdir")
            .join("file2.txt")
            .exists());
    }

    #[test]
    fn test_compress_directory_basic() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files
        fs::write(src_dir.join("file1.txt"), "File 1").unwrap();
        fs::write(src_dir.join("file2.txt"), "File 2").unwrap();

        let subdir = src_dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file3.txt"), "File 3").unwrap();

        let output_path = temp_dir.path().join("dir.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress directory
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            None,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        // Verify structure
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file2.txt").exists());
        assert!(extract_path.join("subdir").join("file3.txt").exists());
    }

    #[test]
    fn test_compress_directory_with_include_patterns() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files with different extensions
        fs::write(src_dir.join("file1.txt"), "Text file").unwrap();
        fs::write(src_dir.join("file2.rs"), "Rust file").unwrap();
        fs::write(src_dir.join("file3.txt"), "Another text file").unwrap();
        fs::write(src_dir.join("file4.py"), "Python file").unwrap();

        let output_path = temp_dir.path().join("filtered.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress only .txt files
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            Some(&["*.txt".to_string()]),
            None,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        // Verify only .txt files are included
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file3.txt").exists());
        assert!(!extract_path.join("file2.rs").exists());
        assert!(!extract_path.join("file4.py").exists());
    }

    #[test]
    fn test_compress_directory_with_exclude_patterns() {
        let temp_dir = tempdir().unwrap();
        let src_dir = temp_dir.path().join("source");
        fs::create_dir(&src_dir).unwrap();

        // Create test files
        fs::write(src_dir.join("file1.txt"), "Keep").unwrap();
        fs::write(src_dir.join("file2.txt"), "Keep").unwrap();
        fs::write(src_dir.join("secret.key"), "Exclude").unwrap();
        fs::write(src_dir.join("data.tmp"), "Exclude").unwrap();

        let output_path = temp_dir.path().join("excluded.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Compress excluding .key and .tmp files
        compress_directory(
            &src_dir,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            Some(&["*.key".to_string(), "*.tmp".to_string()]),
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        // Verify excluded files are not included
        assert!(extract_path.join("file1.txt").exists());
        assert!(extract_path.join("file2.txt").exists());
        assert!(!extract_path.join("secret.key").exists());
        assert!(!extract_path.join("data.tmp").exists());
    }

    #[test]
    fn test_compress_directory_not_a_directory() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        fs::write(&file_path, "I'm a file, not a directory").unwrap();

        let output_path = temp_dir.path().join("output.zip");

        let result = compress_directory(
            &file_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
            None,
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPath(msg) => {
                assert!(msg.contains("is not a directory"));
            }
            e => panic!("Expected InvalidPath error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_empty_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("empty.txt");
        let output_path = temp_dir.path().join("empty.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create empty file
        File::create(&input_path).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_file = extract_path.join("empty.txt");
        assert!(extracted_file.exists());
        assert_eq!(fs::read_to_string(extracted_file).unwrap(), "");
    }

    #[test]
    fn test_compress_binary_data() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("binary.bin");
        let output_path = temp_dir.path().join("binary.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create binary file with various byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        fs::write(&input_path, &binary_data).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_data = fs::read(extract_path.join("binary.bin")).unwrap();
        assert_eq!(extracted_data, binary_data);
    }

    #[test]
    fn test_compression_level_store() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("stored.txt");
        let output_path = temp_dir.path().join("stored.zip");
        let extract_path = temp_dir.path().join("extracted");

        let content = "This content will be stored without compression";
        fs::write(&input_path, content).unwrap();

        // Compress with STORE level (no compression)
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::STORE,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_content = fs::read_to_string(extract_path.join("stored.txt")).unwrap();
        assert_eq!(extracted_content, content);
    }

    #[test]
    fn test_compression_level_best() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("best.txt");
        let output_path = temp_dir.path().join("best.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Repetitive content that compresses well
        let content = "AAAA".repeat(1000);
        fs::write(&input_path, &content).unwrap();

        // Compress with BEST level
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::BEST,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_content = fs::read_to_string(extract_path.join("best.txt")).unwrap();
        assert_eq!(extracted_content, content);
    }

    #[test]
    fn test_delete_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("to_delete.txt");

        fs::write(&file_path, "Delete me").unwrap();
        assert!(file_path.exists());

        delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_delete_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        let result = delete_file(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_files_one_not_found() {
        let temp_dir = tempdir().unwrap();
        let file1 = temp_dir.path().join("exists.txt");
        let file2 = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("output.zip");

        fs::write(&file1, "I exist").unwrap();

        let result = compress_files(
            &[file1.as_path(), file2.as_path()],
            &[None, None],
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_with_password_no_encryption() {
        // When password is provided but encryption is None, no encryption should be applied
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.zip");
        let extract_path = temp_dir.path().join("extracted");

        fs::write(&input_path, "Test content").unwrap();

        compress_file(
            &input_path,
            &output_path,
            Some("password"),
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Should be able to decompress without password
        decompress_file(&output_path, &extract_path, None).unwrap();

        let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
        assert_eq!(content, "Test content");
    }

    #[test]
    fn test_compress_decompress_large_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("large.bin");
        let output_path = temp_dir.path().join("large.zip");
        let extract_path = temp_dir.path().join("extracted");

        // Create a 1MB file with random-ish data
        let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        fs::write(&input_path, &data).unwrap();

        // Compress
        compress_file(
            &input_path,
            &output_path,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        decompress_file(&output_path, &extract_path, None).unwrap();

        let extracted_data = fs::read(extract_path.join("large.bin")).unwrap();
        assert_eq!(extracted_data.len(), data.len());
        assert_eq!(extracted_data, data);
    }

    // ========================================================================
    // In-Memory Compression Tests
    // ========================================================================

    #[test]
    fn test_compress_decompress_bytes_no_password() {
        let files = vec![
            ("hello.txt", b"Hello, World!".as_slice()),
            ("data.bin", &[0u8, 1, 2, 3, 4, 5]),
        ];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        assert!(!zip_data.is_empty());

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "hello.txt");
        assert_eq!(result[0].1, b"Hello, World!");
        assert_eq!(result[1].0, "data.bin");
        assert_eq!(result[1].1, &[0u8, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_compress_decompress_bytes_with_password_aes256() {
        let files = vec![("secret.txt", b"Secret data".as_slice())];

        // Compress with AES-256
        let zip_data = compress_bytes(
            &files,
            Some("password123"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with correct password
        let result = decompress_bytes(&zip_data, Some("password123")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "secret.txt");
        assert_eq!(result[0].1, b"Secret data");
    }

    #[test]
    fn test_compress_decompress_bytes_with_password_zipcrypto() {
        let files = vec![("legacy.txt", b"Legacy encrypted".as_slice())];

        // Compress with ZipCrypto
        let zip_data = compress_bytes(
            &files,
            Some("pass"),
            EncryptionMethod::ZipCrypto,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with correct password
        let result = decompress_bytes(&zip_data, Some("pass")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "legacy.txt");
        assert_eq!(result[0].1, b"Legacy encrypted");
    }

    #[test]
    fn test_decompress_bytes_wrong_password() {
        let files = vec![("test.txt", b"Test".as_slice())];

        // Compress with password
        let zip_data = compress_bytes(
            &files,
            Some("correct"),
            EncryptionMethod::Aes256,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress with wrong password
        let result = decompress_bytes(&zip_data, Some("wrong"));

        assert!(result.is_err());
        match result.unwrap_err() {
            RustyZipError::InvalidPassword => {}
            e => panic!("Expected InvalidPassword error, got {:?}", e),
        }
    }

    #[test]
    fn test_compress_bytes_empty_file() {
        let files = vec![("empty.txt", b"".as_slice())];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "empty.txt");
        assert_eq!(result[0].1, b"");
    }

    #[test]
    fn test_compress_bytes_with_subdirectory() {
        let files = vec![
            ("root.txt", b"Root file".as_slice()),
            ("subdir/nested.txt", b"Nested file".as_slice()),
            ("subdir/deep/file.txt", b"Deep nested".as_slice()),
        ];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "root.txt");
        assert_eq!(result[1].0, "subdir/nested.txt");
        assert_eq!(result[2].0, "subdir/deep/file.txt");
    }

    #[test]
    fn test_compress_bytes_binary_data() {
        // Binary data with all byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        let files = vec![("binary.bin", binary_data.as_slice())];

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, binary_data);
    }

    #[test]
    fn test_compress_bytes_compression_levels() {
        let data = b"AAAA".repeat(1000);
        let files = vec![("data.txt", data.as_slice())];

        // Test STORE (no compression)
        let zip_store = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::STORE,
        )
        .unwrap();

        // Test BEST compression
        let zip_best =
            compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

        // BEST should be smaller than STORE for repetitive data
        assert!(zip_best.len() < zip_store.len());

        // Both should decompress correctly
        let result_store = decompress_bytes(&zip_store, None).unwrap();
        let result_best = decompress_bytes(&zip_best, None).unwrap();

        assert_eq!(result_store[0].1, data);
        assert_eq!(result_best[0].1, data);
    }

    #[test]
    fn test_compress_bytes_multiple_files() {
        let files: Vec<(&str, &[u8])> = (0..10)
            .map(|i| {
                let name = format!("file{}.txt", i);
                let content = format!("Content {}", i);
                // Leak to get 'static lifetime for test
                (
                    Box::leak(name.into_boxed_str()) as &str,
                    Box::leak(content.into_bytes().into_boxed_slice()) as &[u8],
                )
            })
            .collect();

        // Compress
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::DEFAULT,
        )
        .unwrap();

        // Decompress
        let result = decompress_bytes(&zip_data, None).unwrap();

        assert_eq!(result.len(), 10);
        for (i, (name, content)) in result.iter().enumerate() {
            assert_eq!(name, &format!("file{}.txt", i));
            assert_eq!(content, format!("Content {}", i).as_bytes());
        }
    }
}
