use crate::error::{Result, RustyZipError};
use glob::Pattern;
use std::fs::{self, File};
use std::io::{Read, Write};
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

impl CompressionLevel {
    pub const STORE: CompressionLevel = CompressionLevel(0);
    pub const FAST: CompressionLevel = CompressionLevel(1);
    pub const DEFAULT: CompressionLevel = CompressionLevel(6);
    pub const BEST: CompressionLevel = CompressionLevel(9);

    pub fn new(level: u32) -> Self {
        CompressionLevel(level.min(9))
    }

    pub fn to_flate2_compression(&self) -> flate2::Compression {
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

    // Compile patterns
    let include_patterns: Option<Vec<Pattern>> = include_patterns.map(|patterns| {
        patterns
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect()
    });

    let exclude_patterns: Option<Vec<Pattern>> = exclude_patterns.map(|patterns| {
        patterns
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect()
    });

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

        // Check include patterns
        if let Some(ref patterns) = include_patterns {
            if !patterns.iter().any(|p| p.matches(&relative_path)) {
                // Also check just the filename
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !patterns.iter().any(|p| p.matches(file_name)) {
                    continue;
                }
            }
        }

        // Check exclude patterns
        if let Some(ref patterns) = exclude_patterns {
            if patterns.iter().any(|p| p.matches(&relative_path)) {
                continue;
            }
            // Also check just the filename and directory names
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if patterns.iter().any(|p| p.matches(file_name)) {
                continue;
            }
            // Check if any parent directory matches exclude pattern
            let should_exclude = path.ancestors().any(|ancestor| {
                if let Some(name) = ancestor.file_name().and_then(|n| n.to_str()) {
                    patterns.iter().any(|p| p.matches(name))
                } else {
                    false
                }
            });
            if should_exclude {
                continue;
            }
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

/// Add a single file to a ZIP writer
fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
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

    let mut input_file = File::open(file_path)?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;

    Ok(())
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
}
