//! Unit tests for the compression module.

use super::*;
use crate::error::RustyZipError;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, Some("password123"), false).unwrap();

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

    let result = decompress_file(&input_path, &output_path, None, false);

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
    let result = decompress_file(&output_path, &extract_path, Some("wrong_password"), false);

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
    decompress_file(&output_path, &extract_path, Some("password"), false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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
    decompress_file(&output_path, &extract_path, None, false).unwrap();

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

// ========================================================================
// Error Handling Tests
// ========================================================================

#[test]
fn test_error_io_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test io error");
    let err: RustyZipError = io_err.into();
    match err {
        RustyZipError::Io(_) => {}
        e => panic!("Expected Io error, got {:?}", e),
    }
    assert!(err.to_string().contains("IO error"));
}

#[test]
fn test_error_file_not_found() {
    let err = RustyZipError::FileNotFound("/path/to/file.txt".to_string());
    assert!(err.to_string().contains("File not found"));
    assert!(err.to_string().contains("/path/to/file.txt"));
}

#[test]
fn test_error_invalid_path() {
    let err = RustyZipError::InvalidPath("bad/path".to_string());
    assert!(err.to_string().contains("Invalid path"));
}

#[test]
fn test_error_invalid_password() {
    let err = RustyZipError::InvalidPassword;
    assert!(err.to_string().contains("Invalid password"));
}

#[test]
fn test_error_unsupported_encryption() {
    let err = RustyZipError::UnsupportedEncryption("unknown".to_string());
    assert!(err.to_string().contains("Unsupported encryption"));
    assert!(err.to_string().contains("unknown"));
}

#[test]
fn test_error_pattern_error() {
    let err = RustyZipError::PatternError("invalid pattern [".to_string());
    assert!(err.to_string().contains("Pattern error"));
}

#[test]
fn test_error_path_traversal() {
    let err = RustyZipError::PathTraversal("../../../etc/passwd".to_string());
    assert!(err.to_string().contains("Path traversal"));
    assert!(err.to_string().contains("../../../etc/passwd"));
}

#[test]
fn test_error_zip_bomb() {
    let err = RustyZipError::ZipBomb(100_000_000_000, 10_000_000_000);
    assert!(err.to_string().contains("ZIP bomb"));
    assert!(err.to_string().contains("100000000000"));
    assert!(err.to_string().contains("10000000000"));
}

#[test]
fn test_error_suspicious_compression_ratio() {
    let err = RustyZipError::SuspiciousCompressionRatio(5000, 1000);
    assert!(err.to_string().contains("compression ratio"));
    assert!(err.to_string().contains("5000"));
    assert!(err.to_string().contains("1000"));
}

#[test]
fn test_error_glob_pattern_conversion() {
    // Test invalid glob pattern error conversion
    let result = glob::Pattern::new("[invalid");
    assert!(result.is_err());
    let err: RustyZipError = result.unwrap_err().into();
    match err {
        RustyZipError::PatternError(_) => {}
        e => panic!("Expected PatternError, got {:?}", e),
    }
}

#[test]
fn test_encryption_method_from_str_invalid() {
    let result = EncryptionMethod::from_str("invalid_method");
    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::UnsupportedEncryption(msg) => {
            assert!(msg.contains("invalid_method"));
        }
        e => panic!("Expected UnsupportedEncryption error, got {:?}", e),
    }
}

#[test]
fn test_compress_directory_invalid_pattern() {
    let temp_dir = tempdir().unwrap();
    let src_dir = temp_dir.path().join("source");
    fs::create_dir(&src_dir).unwrap();
    fs::write(src_dir.join("test.txt"), "test").unwrap();

    let output_path = temp_dir.path().join("output.zip");

    // Invalid glob pattern should return error
    let result = compress_directory(
        &src_dir,
        &output_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&["[invalid".to_string()]),
        None,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::PatternError(_) => {}
        e => panic!("Expected PatternError, got {:?}", e),
    }
}

// ========================================================================
// Security Tests - Path Traversal
// ========================================================================

#[test]
fn test_path_traversal_validation() {
    let output_base = Path::new("/tmp/extract");

    // Test that parent dir (..) is rejected
    let result = validate_output_path(output_base, Path::new("../etc/passwd"));
    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::PathTraversal(_) => {}
        e => panic!("Expected PathTraversal error, got {:?}", e),
    }

    // Test that absolute path components are handled
    let result = validate_output_path(output_base, Path::new("foo/../../../bar"));
    assert!(result.is_err());
}

#[test]
fn test_path_traversal_safe_paths() {
    let temp_dir = tempdir().unwrap();
    let output_base = temp_dir.path();

    // Safe relative paths should pass
    assert!(validate_output_path(output_base, Path::new("file.txt")).is_ok());
    assert!(validate_output_path(output_base, Path::new("subdir/file.txt")).is_ok());
    assert!(validate_output_path(output_base, Path::new("a/b/c/file.txt")).is_ok());
}

// ========================================================================
// Security Tests - ZIP Bomb Protection
// ========================================================================

#[test]
fn test_decompress_with_size_limit() {
    // Create a ZIP with a known file
    let files = vec![("test.txt", b"Hello World".as_slice())];
    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Should succeed with reasonable limit
    let result = decompress_bytes_with_limits(&zip_data, None, 1024 * 1024, 1000);
    assert!(result.is_ok());

    // Should fail with very small limit
    let result = decompress_bytes_with_limits(&zip_data, None, 5, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::ZipBomb(_, _) => {}
        e => panic!("Expected ZipBomb error, got {:?}", e),
    }
}

#[test]
fn test_decompress_file_with_limits() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let output_path = temp_dir.path().join("test.zip");
    let extract_path = temp_dir.path().join("extracted");

    // Create a test file
    fs::write(&input_path, "Hello, World!").unwrap();

    // Compress
    compress_file(
        &input_path,
        &output_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Should succeed with reasonable limit
    let result =
        decompress_file_with_limits(&output_path, &extract_path, None, false, 1024 * 1024, 1000);
    assert!(result.is_ok());

    // Clean up for next test
    fs::remove_dir_all(&extract_path).unwrap();

    // Should fail with very small limit
    let result = decompress_file_with_limits(&output_path, &extract_path, None, false, 5, 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::ZipBomb(_, _) => {}
        e => panic!("Expected ZipBomb error, got {:?}", e),
    }
}

// ========================================================================
// Compat API Tests - ZipCrypto Verification
// ========================================================================

/// Helper to check if a ZIP file uses ZipCrypto encryption
fn is_zipcrypto_encrypted(zip_data: &[u8]) -> bool {
    use std::io::Cursor;
    use zip::ZipArchive;

    let cursor = Cursor::new(zip_data);
    let archive = ZipArchive::new(cursor).unwrap();

    // Check the first file's encryption
    if archive.len() > 0 {
        // Try to read without password - should fail if encrypted
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let result = archive.by_index(0);
        let is_encrypted = match result {
            Ok(_) => false, // Not encrypted or AES
            Err(zip::result::ZipError::UnsupportedArchive(ref msg)) => {
                // ZipCrypto shows as "Password required to decrypt file"
                msg.contains("Password")
            }
            Err(_) => false,
        };
        drop(result);
        is_encrypted
    } else {
        false
    }
}

/// Helper to verify a file can be decrypted with ZipCrypto
fn can_decrypt_with_zipcrypto(zip_data: &[u8], password: &str) -> bool {
    use std::io::Cursor;
    use zip::ZipArchive;

    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor).unwrap();

    if archive.len() > 0 {
        match archive.by_index_decrypt(0, password.as_bytes()) {
            Ok(mut file) => {
                let mut content = Vec::new();
                file.read_to_end(&mut content).is_ok()
            }
            Err(_) => false,
        }
    } else {
        false
    }
}

#[test]
fn test_zipcrypto_vs_aes256_encryption() {
    let files = vec![("secret.txt", b"Secret data".as_slice())];

    // Compress with ZipCrypto
    let zip_crypto = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Compress with AES256
    let zip_aes = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Both should decrypt successfully
    let result_crypto = decompress_bytes(&zip_crypto, Some("password"));
    let result_aes = decompress_bytes(&zip_aes, Some("password"));

    assert!(result_crypto.is_ok());
    assert!(result_aes.is_ok());

    // Verify content is correct
    assert_eq!(result_crypto.unwrap()[0].1, b"Secret data");
    assert_eq!(result_aes.unwrap()[0].1, b"Secret data");

    // ZipCrypto and AES256 produce different file sizes (AES has more overhead)
    // AES256 adds extra headers for encryption
    assert_ne!(zip_crypto.len(), zip_aes.len());
}

#[test]
fn test_compat_compress_uses_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let output_path = temp_dir.path().join("compat.zip");

    // Create test file
    fs::write(&input_path, "Test content for compat API").unwrap();

    // Use the files compression with ZipCrypto (simulating compat behavior)
    compress_files(
        &[input_path.as_path()],
        &[None],
        &output_path,
        Some("password123"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Read the ZIP file
    let zip_data = fs::read(&output_path).unwrap();

    // Verify it's encrypted
    assert!(is_zipcrypto_encrypted(&zip_data));

    // Verify it can be decrypted with the password
    assert!(can_decrypt_with_zipcrypto(&zip_data, "password123"));

    // Verify wrong password fails
    assert!(!can_decrypt_with_zipcrypto(&zip_data, "wrongpassword"));
}

#[test]
fn test_compat_compress_multiple_files_uses_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let output_path = temp_dir.path().join("multi_compat.zip");

    // Create test files
    fs::write(&file1, "Content 1").unwrap();
    fs::write(&file2, "Content 2").unwrap();

    // Compress with ZipCrypto (compat API behavior)
    compress_files(
        &[file1.as_path(), file2.as_path()],
        &[Some("dir1"), Some("dir2")],
        &output_path,
        Some("testpass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Read and verify
    let zip_data = fs::read(&output_path).unwrap();

    // Verify encryption
    assert!(is_zipcrypto_encrypted(&zip_data));
    assert!(can_decrypt_with_zipcrypto(&zip_data, "testpass"));

    // Decompress and verify contents
    let extract_path = temp_dir.path().join("extracted");
    decompress_file(&output_path, &extract_path, Some("testpass"), false).unwrap();

    assert!(extract_path.join("dir1").join("file1.txt").exists());
    assert!(extract_path.join("dir2").join("file2.txt").exists());
}

#[test]
fn test_compat_no_password_no_encryption() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let output_path = temp_dir.path().join("no_encrypt.zip");

    fs::write(&input_path, "Unencrypted content").unwrap();

    // Compress without password (compat API uses None encryption)
    compress_files(
        &[input_path.as_path()],
        &[None],
        &output_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Read and verify it's NOT encrypted
    let zip_data = fs::read(&output_path).unwrap();
    assert!(!is_zipcrypto_encrypted(&zip_data));

    // Should decompress without password
    let extract_path = temp_dir.path().join("extracted");
    decompress_file(&output_path, &extract_path, None, false).unwrap();

    let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
    assert_eq!(content, "Unencrypted content");
}

#[test]
fn test_compat_decompress_zipcrypto() {
    let temp_dir = tempdir().unwrap();
    let input_path = temp_dir.path().join("test.txt");
    let output_path = temp_dir.path().join("zipcrypto.zip");
    let extract_path = temp_dir.path().join("extracted");

    fs::write(&input_path, "ZipCrypto encrypted file").unwrap();

    // Compress with ZipCrypto
    compress_file(
        &input_path,
        &output_path,
        Some("password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress (simulating compat uncompress)
    decompress_file(&output_path, &extract_path, Some("password"), false).unwrap();

    let content = fs::read_to_string(extract_path.join("test.txt")).unwrap();
    assert_eq!(content, "ZipCrypto encrypted file");
}

#[test]
fn test_compat_decompress_withoutpath() {
    let temp_dir = tempdir().unwrap();

    // Create ZIP with nested structure using ZipCrypto
    let files = vec![
        ("dir1/file1.txt", b"File 1".as_slice()),
        ("dir1/dir2/file2.txt", b"File 2".as_slice()),
    ];

    let zip_data = compress_bytes(
        &files,
        Some("pass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let zip_path = temp_dir.path().join("nested.zip");
    fs::write(&zip_path, &zip_data).unwrap();

    // Extract with withoutpath=true (flatten structure)
    let extract_path = temp_dir.path().join("flat");
    decompress_file(&zip_path, &extract_path, Some("pass"), true).unwrap();

    // Files should be flattened (no subdirectories)
    assert!(extract_path.join("file1.txt").exists());
    assert!(extract_path.join("file2.txt").exists());
    assert!(!extract_path.join("dir1").exists());
}
