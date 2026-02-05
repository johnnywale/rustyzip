//! Integration tests for error types and conversions
//! These tests ensure error types work correctly through the public API

use rustyzip::compression::{
    compress_directory, compress_file, decompress_file, CompressionLevel, EncryptionMethod,
};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_file_not_found_error() {
    let temp_dir = tempdir().unwrap();
    let nonexistent = temp_dir.path().join("nonexistent.txt");
    let zip_path = temp_dir.path().join("output.zip");

    let result = compress_file(
        &nonexistent,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    );

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(!err_str.is_empty());
}

#[test]
fn test_invalid_password_error() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("test.txt");
    let zip_path = temp_dir.path().join("test.zip");
    let output_dir = temp_dir.path().join("output");

    // Create and compress with password
    File::create(&input_file)
        .unwrap()
        .write_all(b"secret")
        .unwrap();
    compress_file(
        &input_file,
        &zip_path,
        Some("correct"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Try to decompress with wrong password
    let result = decompress_file(&zip_path, &output_dir, Some("wrong"), false);

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(!err_str.is_empty());
}

#[test]
fn test_invalid_glob_pattern_error() {
    let temp_dir = tempdir().unwrap();
    let input_dir = temp_dir.path().join("input");
    std::fs::create_dir(&input_dir).unwrap();
    let zip_path = temp_dir.path().join("output.zip");

    // Invalid glob pattern
    let result = compress_directory(
        &input_dir,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&["[".to_string()]),
        None,
    );

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(!err_str.is_empty());
}

#[test]
fn test_directory_not_found_error() {
    let temp_dir = tempdir().unwrap();
    let nonexistent_dir = temp_dir.path().join("nonexistent_dir");
    let zip_path = temp_dir.path().join("output.zip");

    let result = compress_directory(
        &nonexistent_dir,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    );

    assert!(result.is_err());
}

#[test]
fn test_compress_non_directory_as_directory() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("file.txt");
    File::create(&file_path)
        .unwrap()
        .write_all(b"content")
        .unwrap();
    let zip_path = temp_dir.path().join("output.zip");

    // Try to compress a file as if it were a directory
    let result = compress_directory(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    );

    assert!(result.is_err());
}

#[test]
fn test_decompress_corrupt_zip() {
    let temp_dir = tempdir().unwrap();
    let corrupt_zip = temp_dir.path().join("corrupt.zip");
    let output_dir = temp_dir.path().join("output");

    // Create a file that's not a valid ZIP
    File::create(&corrupt_zip)
        .unwrap()
        .write_all(b"Not a ZIP file!")
        .unwrap();

    let result = decompress_file(&corrupt_zip, &output_dir, None, false);

    assert!(result.is_err());
}

#[test]
fn test_error_messages_are_descriptive() {
    let temp_dir = tempdir().unwrap();
    let nonexistent = temp_dir.path().join("does_not_exist.txt");
    let zip_path = temp_dir.path().join("output.zip");

    let result = compress_file(
        &nonexistent,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    );

    if let Err(e) = result {
        let error_msg = format!("{}", e);
        // Error message should be descriptive
        assert!(!error_msg.is_empty());
        assert!(error_msg.len() > 10); // Should have meaningful content
    }
}

#[test]
fn test_error_debug_format() {
    let temp_dir = tempdir().unwrap();
    let nonexistent = temp_dir.path().join("missing.txt");
    let zip_path = temp_dir.path().join("output.zip");

    let result = compress_file(
        &nonexistent,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    );

    if let Err(e) = result {
        let debug_msg = format!("{:?}", e);
        assert!(!debug_msg.is_empty());
    }
}
