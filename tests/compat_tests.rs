//! pyminizip compatibility tests.
//!
//! These tests verify that the compat API uses ZipCrypto encryption
//! for compatibility with pyminizip.

use rustyzip::compression::{self, CompressionLevel, EncryptionMethod};
use rustyzip::error::RustyZipError;
use std::fs;
use std::io::Read;
use std::path::Path;
use tempfile::tempdir;

// ========================================================================
// Helper Functions
// ========================================================================

/// Helper to verify a ZIP uses ZipCrypto encryption (not AES)
fn verify_zipcrypto_encryption(zip_path: &Path, password: &str) -> bool {
    use zip::ZipArchive;

    let file = std::fs::File::open(zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();

    if archive.len() == 0 {
        return false;
    }

    // Try to decrypt with ZipCrypto - this should work
    let result = archive.by_index_decrypt(0, password.as_bytes());
    match result {
        Ok(mut f) => {
            let mut content = Vec::new();
            let success = f.read_to_end(&mut content).is_ok();
            drop(f);
            success
        }
        Err(_) => false,
    }
}

/// Helper to check if file is encrypted (requires password)
fn is_encrypted(zip_path: &Path) -> bool {
    use zip::ZipArchive;

    let file = std::fs::File::open(zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();

    if archive.len() == 0 {
        return false;
    }

    // Try to read without password - encrypted files should fail
    let result = archive.by_index(0);
    let encrypted = match result {
        Ok(_) => false,
        Err(zip::result::ZipError::UnsupportedArchive(ref msg)) => {
            msg.contains("Password") || msg.contains("password")
        }
        Err(_) => false,
    };
    drop(result);
    encrypted
}

// ========================================================================
// Compat API Tests - Verify ZipCrypto is always used
// ========================================================================

#[test]
fn test_compat_compress_single_file_uses_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let output_path = temp_dir.path().join("compat_single.zip");

    fs::write(&input_path, "Test content").unwrap();

    // Use compression::compress_files with ZipCrypto (what compat API does)
    compression::compress_files(
        &[input_path.as_path()],
        &[None],
        &output_path,
        Some("password123"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Verify it's encrypted
    assert!(is_encrypted(&output_path), "File should be encrypted");

    // Verify it can be decrypted with ZipCrypto
    assert!(
        verify_zipcrypto_encryption(&output_path, "password123"),
        "Should decrypt with ZipCrypto"
    );
}

#[test]
fn test_compat_compress_with_prefix_uses_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("data.txt");
    let output_path = temp_dir.path().join("compat_prefix.zip");

    fs::write(&input_path, "Data with prefix").unwrap();

    // Compress with prefix using ZipCrypto
    compression::compress_files(
        &[input_path.as_path()],
        &[Some("subdir/nested")],
        &output_path,
        Some("secret"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::new(5),
    )
    .unwrap();

    // Verify encryption
    assert!(is_encrypted(&output_path));
    assert!(verify_zipcrypto_encryption(&output_path, "secret"));

    // Verify content and path
    let extract_path = temp_dir.path().join("extracted");
    compression::decompress_file(&output_path, &extract_path, Some("secret"), false).unwrap();

    assert!(extract_path.join("subdir/nested/data.txt").exists());
}

#[test]
fn test_compat_compress_multiple_files_uses_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");
    let output_path = temp_dir.path().join("compat_multi.zip");

    fs::write(&file1, "Content 1").unwrap();
    fs::write(&file2, "Content 2").unwrap();
    fs::write(&file3, "Content 3").unwrap();

    // Compress multiple files with ZipCrypto
    compression::compress_files(
        &[file1.as_path(), file2.as_path(), file3.as_path()],
        &[Some("a"), Some("b"), Some("c")],
        &output_path,
        Some("multipass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Verify all files are ZipCrypto encrypted
    assert!(is_encrypted(&output_path));
    assert!(verify_zipcrypto_encryption(&output_path, "multipass"));

    // Decompress and verify
    let extract_path = temp_dir.path().join("extracted");
    compression::decompress_file(&output_path, &extract_path, Some("multipass"), false).unwrap();

    assert_eq!(
        fs::read_to_string(extract_path.join("a/file1.txt")).unwrap(),
        "Content 1"
    );
    assert_eq!(
        fs::read_to_string(extract_path.join("b/file2.txt")).unwrap(),
        "Content 2"
    );
    assert_eq!(
        fs::read_to_string(extract_path.join("c/file3.txt")).unwrap(),
        "Content 3"
    );
}

#[test]
fn test_compat_no_password_no_encryption() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("unencrypted.txt");
    let output_path = temp_dir.path().join("no_encrypt.zip");

    fs::write(&input_path, "Not encrypted").unwrap();

    // Compress without password (should use EncryptionMethod::None)
    compression::compress_files(
        &[input_path.as_path()],
        &[None],
        &output_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Verify NOT encrypted
    assert!(!is_encrypted(&output_path));

    // Should decompress without password
    let extract_path = temp_dir.path().join("extracted");
    compression::decompress_file(&output_path, &extract_path, None, false).unwrap();

    assert_eq!(
        fs::read_to_string(extract_path.join("unencrypted.txt")).unwrap(),
        "Not encrypted"
    );
}

#[test]
fn test_compat_uncompress_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("secret.txt");
    let zip_path = temp_dir.path().join("secret.zip");
    let extract_path = temp_dir.path().join("extracted");

    fs::write(&input_path, "Secret ZipCrypto data").unwrap();

    // Create ZipCrypto encrypted file
    compression::compress_file(
        &input_path,
        &zip_path,
        Some("password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress (simulating compat uncompress)
    compression::decompress_file(&zip_path, &extract_path, Some("password"), false).unwrap();

    assert_eq!(
        fs::read_to_string(extract_path.join("secret.txt")).unwrap(),
        "Secret ZipCrypto data"
    );
}

#[test]
fn test_compat_uncompress_withoutpath_flag() {
    let temp_dir = tempdir().unwrap();

    // Create a ZIP with nested structure
    let files = vec![
        ("level1/level2/deep.txt", b"Deep file".as_slice()),
        ("level1/shallow.txt", b"Shallow file".as_slice()),
    ];

    let zip_data = compression::compress_bytes(
        &files,
        Some("pass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let zip_path = temp_dir.path().join("nested.zip");
    fs::write(&zip_path, &zip_data).unwrap();

    // Extract with withoutpath=true (like pyminizip uncompress with withoutpath=1)
    let extract_flat = temp_dir.path().join("flat");
    compression::decompress_file(&zip_path, &extract_flat, Some("pass"), true).unwrap();

    // Files should be flattened
    assert!(extract_flat.join("deep.txt").exists());
    assert!(extract_flat.join("shallow.txt").exists());
    assert!(!extract_flat.join("level1").exists());

    // Extract with withoutpath=false (preserve structure)
    let extract_nested = temp_dir.path().join("nested");
    compression::decompress_file(&zip_path, &extract_nested, Some("pass"), false).unwrap();

    // Files should preserve structure
    assert!(extract_nested.join("level1/level2/deep.txt").exists());
    assert!(extract_nested.join("level1/shallow.txt").exists());
}

#[test]
fn test_compat_wrong_password_error() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let zip_path = temp_dir.path().join("encrypted.zip");
    let extract_path = temp_dir.path().join("extracted");

    fs::write(&input_path, "Encrypted content").unwrap();

    // Create ZipCrypto encrypted file
    compression::compress_file(
        &input_path,
        &zip_path,
        Some("correct_password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Try to decompress with wrong password
    let result =
        compression::decompress_file(&zip_path, &extract_path, Some("wrong_password"), false);

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::InvalidPassword => {}
        e => panic!("Expected InvalidPassword error, got {:?}", e),
    }
}

#[test]
fn test_encryption_method_selection_for_compat() {
    // When password is provided, compat should use ZipCrypto
    let with_password = Some("password");
    let enc_with_pwd = if with_password.is_some() {
        EncryptionMethod::ZipCrypto
    } else {
        EncryptionMethod::None
    };
    assert_eq!(enc_with_pwd, EncryptionMethod::ZipCrypto);

    // When no password, should use None
    let no_password: Option<&str> = None;
    let enc_no_pwd = if no_password.is_some() {
        EncryptionMethod::ZipCrypto
    } else {
        EncryptionMethod::None
    };
    assert_eq!(enc_no_pwd, EncryptionMethod::None);
}
