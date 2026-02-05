//! Sequential compression tests to achieve 80%+ coverage.
//!
//! This test suite focuses on testing sequential-only code paths:
//! - compress_file function (always sequential)
//! - compress_bytes function (always sequential)
//! - compress_files_sequential (internal, tested indirectly)
//! - compress_directory_sequential (internal, tested indirectly)
//!
//! Note: Some functions are only called when parallel feature is disabled.
//! We test them through small files and direct function calls.

use rustyzip::compression::{
    compress_bytes, compress_file, compress_files, decompress_bytes, decompress_file, list_archive,
    CompressionLevel, EncryptionMethod,
};
use rustyzip::error::RustyZipError;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn create_small_files(dir: &Path, count: usize) -> Vec<std::path::PathBuf> {
    (0..count)
        .map(|i| {
            let name = format!("file{}.txt", i);
            create_test_file(dir, &name, &format!("Content for file {}", i))
        })
        .collect()
}

// ============================================================================
// compress_file Tests (Always Sequential)
// ============================================================================

#[test]
fn test_compress_file_basic() {
    let tmp_dir = TempDir::new().unwrap();
    let input = create_test_file(&tmp_dir.path(), "input.txt", "Hello, World!");
    let output = tmp_dir.path().join("output.zip");

    compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify we can list the file
    let files = list_archive(&output).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0], "input.txt");
}

#[test]
fn test_compress_file_with_password() {
    let tmp_dir = TempDir::new().unwrap();
    let input = create_test_file(&tmp_dir.path(), "secret.txt", "Secret data");
    let output = tmp_dir.path().join("encrypted.zip");

    compress_file(
        &input,
        &output,
        Some("password123"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify we can decompress with correct password
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, Some("password123"), false).unwrap();

    let decompressed_file = extract_dir.join("secret.txt");
    let content = fs::read_to_string(&decompressed_file).unwrap();
    assert_eq!(content, "Secret data");
}

#[test]
fn test_compress_file_different_compression_levels() {
    let tmp_dir = TempDir::new().unwrap();
    let content = "A".repeat(1000); // Compressible content
    let input = create_test_file(&tmp_dir.path(), "test.txt", &content);

    // Test STORE (no compression)
    let store_zip = tmp_dir.path().join("store.zip");
    compress_file(
        &input,
        &store_zip,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();
    let store_size = fs::metadata(&store_zip).unwrap().len();

    // Test FAST
    let fast_zip = tmp_dir.path().join("fast.zip");
    compress_file(
        &input,
        &fast_zip,
        None,
        EncryptionMethod::None,
        CompressionLevel::FAST,
    )
    .unwrap();
    let fast_size = fs::metadata(&fast_zip).unwrap().len();

    // Test BEST
    let best_zip = tmp_dir.path().join("best.zip");
    compress_file(
        &input,
        &best_zip,
        None,
        EncryptionMethod::None,
        CompressionLevel::BEST,
    )
    .unwrap();
    let best_size = fs::metadata(&best_zip).unwrap().len();

    // STORE should be larger than compressed versions
    assert!(store_size > fast_size);
    // BEST should be smaller or equal to FAST
    assert!(best_size <= fast_size);
}

#[test]
fn test_compress_file_not_found() {
    let tmp_dir = TempDir::new().unwrap();
    let input = tmp_dir.path().join("nonexistent.txt");
    let output = tmp_dir.path().join("output.zip");

    let result = compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::FileNotFound(_) => {}
        e => panic!("Expected FileNotFound, got {:?}", e),
    }
}

#[test]
fn test_compress_file_with_special_characters() {
    let tmp_dir = TempDir::new().unwrap();
    let input = create_test_file(&tmp_dir.path(), "file with spaces.txt", "Content");
    let output = tmp_dir.path().join("output.zip");

    compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let files = list_archive(&output).unwrap();
    assert_eq!(files[0], "file with spaces.txt");
}

#[test]
fn test_compress_file_empty() {
    let tmp_dir = TempDir::new().unwrap();
    let input = create_test_file(&tmp_dir.path(), "empty.txt", "");
    let output = tmp_dir.path().join("output.zip");

    compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());
}

#[test]
fn test_compress_file_large_content() {
    let tmp_dir = TempDir::new().unwrap();
    // Use less compressible content to avoid ZIP bomb detection
    let large_content: String = (0..10_000).map(|i| format!("Line{} ", i)).collect();
    let input = create_test_file(&tmp_dir.path(), "large.txt", &large_content);
    let output = tmp_dir.path().join("output.zip");

    compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Verify decompression
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    let decompressed_file = extract_dir.join("large.txt");
    let content = fs::read_to_string(&decompressed_file).unwrap();
    assert_eq!(content.len(), large_content.len());
}

#[test]
fn test_compress_file_all_encryption_methods() {
    let tmp_dir = TempDir::new().unwrap();
    let input = create_test_file(&tmp_dir.path(), "test.txt", "Test content");

    // None
    let none_zip = tmp_dir.path().join("none.zip");
    let none_extract = tmp_dir.path().join("none_extract");
    fs::create_dir(&none_extract).unwrap();
    compress_file(
        &input,
        &none_zip,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
    decompress_file(&none_zip, &none_extract, None, false).unwrap();

    // ZipCrypto
    let zipcrypto_zip = tmp_dir.path().join("zipcrypto.zip");
    let zipcrypto_extract = tmp_dir.path().join("zipcrypto_extract");
    fs::create_dir(&zipcrypto_extract).unwrap();
    compress_file(
        &input,
        &zipcrypto_zip,
        Some("pass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
    decompress_file(&zipcrypto_zip, &zipcrypto_extract, Some("pass"), false).unwrap();

    // Aes256
    let aes_zip = tmp_dir.path().join("aes.zip");
    let aes_extract = tmp_dir.path().join("aes_extract");
    fs::create_dir(&aes_extract).unwrap();
    compress_file(
        &input,
        &aes_zip,
        Some("pass"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
    decompress_file(&aes_zip, &aes_extract, Some("pass"), false).unwrap();
}

// ============================================================================
// compress_bytes Tests (Always Sequential)
// ============================================================================

#[test]
fn test_compress_bytes_single_file() {
    let files = vec![("test.txt", b"Hello, bytes!" as &[u8])];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(!zip_bytes.is_empty());

    // Verify by decompressing
    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "test.txt");
    assert_eq!(result[0].1, b"Hello, bytes!");
}

#[test]
fn test_compress_bytes_multiple_files() {
    let files = vec![
        ("file1.txt", b"Content 1" as &[u8]),
        ("file2.txt", b"Content 2" as &[u8]),
        ("file3.txt", b"Content 3" as &[u8]),
    ];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn test_compress_bytes_with_password() {
    let files = vec![("secret.txt", b"Secret data" as &[u8])];

    let zip_bytes = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress with correct password
    let result = decompress_bytes(&zip_bytes, Some("password")).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, b"Secret data");
}

#[test]
fn test_compress_bytes_empty_array() {
    let files: Vec<(&str, &[u8])> = vec![];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Should create empty ZIP
    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn test_compress_bytes_empty_content() {
    let files = vec![("empty.txt", b"" as &[u8])];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, b"");
}

#[test]
fn test_compress_bytes_with_subdirectories() {
    let files = vec![
        ("file.txt", b"Root file" as &[u8]),
        ("dir/file.txt", b"In directory" as &[u8]),
        ("dir/subdir/file.txt", b"In subdirectory" as &[u8]),
    ];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 3);

    // Verify names preserved
    let names: Vec<&str> = result.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"file.txt"));
    assert!(names.contains(&"dir/file.txt"));
    assert!(names.contains(&"dir/subdir/file.txt"));
}

#[test]
fn test_compress_bytes_large_data() {
    // Use less compressible data to avoid ZIP bomb detection
    let large_data: Vec<u8> = (0..10_000_u16).flat_map(|i| i.to_le_bytes()).collect();
    let files = vec![("large.bin", large_data.as_slice())];

    let zip_bytes =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

    // Should be compressed (but not too much)
    assert!(zip_bytes.len() < large_data.len() + 1000); // Allow some overhead

    // Verify decompression
    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result[0].1, large_data);
}

#[test]
fn test_compress_bytes_different_compression_levels() {
    let content = b"AAAAAAAAAA".repeat(100);
    let files = vec![("test.txt", content.as_slice())];

    // STORE
    let store_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();

    // FAST
    let fast_bytes =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::FAST).unwrap();

    // BEST
    let best_bytes =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

    // STORE should be largest
    assert!(store_bytes.len() > fast_bytes.len());
    // BEST should be smallest or equal to FAST
    assert!(best_bytes.len() <= fast_bytes.len());
}

#[test]
fn test_compress_bytes_special_characters_in_name() {
    let files = vec![
        ("file with spaces.txt", b"Content 1" as &[u8]),
        ("file-with-dashes.txt", b"Content 2" as &[u8]),
        ("file_with_underscores.txt", b"Content 3" as &[u8]),
    ];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn test_compress_bytes_binary_data() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let files = vec![("binary.dat", binary_data.as_slice())];

    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let result = decompress_bytes(&zip_bytes, None).unwrap();
    assert_eq!(result[0].1, binary_data);
}

// ============================================================================
// Small File Tests (May Use Sequential Path)
// ============================================================================

#[test]
fn test_compress_files_very_small_files() {
    let tmp_dir = TempDir::new().unwrap();

    // Create 3 very small files (more likely to use sequential path)
    let file1 = create_test_file(&tmp_dir.path(), "small1.txt", "A");
    let file2 = create_test_file(&tmp_dir.path(), "small2.txt", "B");
    let file3 = create_test_file(&tmp_dir.path(), "small3.txt", "C");

    let files: Vec<&Path> = vec![&file1, &file2, &file3];
    let prefixes = vec![None, None, None];
    let output = tmp_dir.path().join("output.zip");

    compress_files(
        &files,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE, // STORE level may prefer sequential
    )
    .unwrap();

    let listed = list_archive(&output).unwrap();
    assert_eq!(listed.len(), 3);
}

#[test]
fn test_compress_files_with_store_level() {
    let tmp_dir = TempDir::new().unwrap();
    let files = create_small_files(&tmp_dir.path(), 5);
    let file_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
    let prefixes = vec![None; 5];
    let output = tmp_dir.path().join("output.zip");

    compress_files(
        &file_refs,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();

    let listed = list_archive(&output).unwrap();
    assert_eq!(listed.len(), 5);
}

#[test]
fn test_compress_files_with_prefixes() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = create_test_file(&tmp_dir.path(), "file1.txt", "Content 1");
    let file2 = create_test_file(&tmp_dir.path(), "file2.txt", "Content 2");

    let files: Vec<&Path> = vec![&file1, &file2];
    let prefixes = vec![Some("prefix1"), Some("prefix2")];
    let output = tmp_dir.path().join("output.zip");

    compress_files(
        &files,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let listed = list_archive(&output).unwrap();
    assert!(listed.contains(&"prefix1/file1.txt".to_string()));
    assert!(listed.contains(&"prefix2/file2.txt".to_string()));
}

#[test]
fn test_compress_files_mixed_prefixes() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = create_test_file(&tmp_dir.path(), "file1.txt", "Content 1");
    let file2 = create_test_file(&tmp_dir.path(), "file2.txt", "Content 2");

    let files: Vec<&Path> = vec![&file1, &file2];
    let prefixes = vec![Some("dir"), None]; // One with prefix, one without
    let output = tmp_dir.path().join("output.zip");

    compress_files(
        &files,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let listed = list_archive(&output).unwrap();
    assert!(listed.contains(&"dir/file1.txt".to_string()));
    assert!(listed.contains(&"file2.txt".to_string()));
}

// ============================================================================
// Error Path Tests
// ============================================================================

#[test]
fn test_compress_files_missing_file() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = create_test_file(&tmp_dir.path(), "exists.txt", "Content");
    let file2 = tmp_dir.path().join("missing.txt"); // Doesn't exist

    let files: Vec<&Path> = vec![&file1, &file2];
    let prefixes = vec![None, None];
    let output = tmp_dir.path().join("output.zip");

    let result = compress_files(
        &files,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::FileNotFound(_) => {}
        e => panic!("Expected FileNotFound, got {:?}", e),
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_compress_decompress_roundtrip_file() {
    let tmp_dir = TempDir::new().unwrap();
    let original_content = "Test content for roundtrip";
    let input = create_test_file(&tmp_dir.path(), "test.txt", original_content);
    let zip_path = tmp_dir.path().join("test.zip");

    // Compress
    compress_file(
        &input,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&zip_path, &extract_dir, None, false).unwrap();

    // Verify
    let decompressed_file = extract_dir.join("test.txt");
    let content = fs::read_to_string(&decompressed_file).unwrap();
    assert_eq!(content, original_content);
}

#[test]
fn test_compress_decompress_roundtrip_bytes() {
    let files = vec![
        ("file1.txt", b"Content 1" as &[u8]),
        ("file2.txt", b"Content 2" as &[u8]),
    ];

    // Compress
    let zip_bytes = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress
    let result = decompress_bytes(&zip_bytes, None).unwrap();

    // Verify
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "file1.txt");
    assert_eq!(result[0].1, b"Content 1");
    assert_eq!(result[1].0, "file2.txt");
    assert_eq!(result[1].1, b"Content 2");
}

#[test]
fn test_compress_file_unicode_content() {
    let tmp_dir = TempDir::new().unwrap();
    let unicode_content = "Hello 世界 🌍 مرحبا привет";
    let input = create_test_file(&tmp_dir.path(), "unicode.txt", unicode_content);
    let output = tmp_dir.path().join("output.zip");

    compress_file(
        &input,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Verify by decompressing
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    let decompressed_file = extract_dir.join("unicode.txt");
    let content = fs::read_to_string(&decompressed_file).unwrap();
    assert_eq!(content, unicode_content);
}
