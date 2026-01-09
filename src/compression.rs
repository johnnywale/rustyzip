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

    add_file_to_zip(&mut zip, input_path, file_name, password, encryption, compression_level)?;

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

        add_file_to_zip(&mut zip, input_path, &archive_name, password, encryption, compression_level)?;
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
        return Err(RustyZipError::FileNotFound(
            input_dir.display().to_string(),
        ));
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

    let base_path = input_dir.canonicalize()?;

    for entry in WalkDir::new(input_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_dir() {
            continue;
        }

        // Get relative path for archive
        let relative_path = path
            .strip_prefix(&base_path)
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

        add_file_to_zip(&mut zip, path, &relative_path, password, encryption, compression_level)?;
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
    let compression_method = if compression_level.0 == 0 {
        CompressionMethod::Stored
    } else {
        CompressionMethod::Deflated
    };

    let base_options = SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(Some(compression_level.0 as i64));

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
            Some(pwd) => {
                match archive.by_index_decrypt(i, pwd.as_bytes()) {
                    Ok(f) => f,
                    Err(zip::result::ZipError::InvalidPassword) => {
                        return Err(RustyZipError::InvalidPassword);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
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
}
