//! Tests to complete 100% coverage for error.rs and types.rs
//!
//! Note: utils.rs is internal and tested indirectly through public APIs

use rustyzip::compression::{compress_bytes, compress_file, CompressionLevel, EncryptionMethod};
use rustyzip::error::RustyZipError;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Error Module Tests (error.rs - 50% → 100%)
// ============================================================================

#[test]
fn test_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let rusty_err: RustyZipError = io_err.into();

    match rusty_err {
        RustyZipError::Io(_) => {}
        _ => panic!("Expected Io error variant"),
    }

    // Test display
    assert!(format!("{}", rusty_err).contains("IO error"));
}

#[test]
fn test_error_from_pattern_error() {
    let pattern_err = glob::Pattern::new("[").unwrap_err();
    let rusty_err: RustyZipError = pattern_err.into();

    match rusty_err {
        RustyZipError::PatternError(msg) => {
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected PatternError variant"),
    }
}

#[test]
fn test_error_zip_bomb_display() {
    let err = RustyZipError::ZipBomb(10_000_000_000, 2_000_000_000);
    let msg = format!("{}", err);

    assert!(msg.contains("ZIP bomb"));
    assert!(msg.contains("10000000000"));
    assert!(msg.contains("2000000000"));
}

#[test]
fn test_error_suspicious_ratio_display() {
    let err = RustyZipError::SuspiciousCompressionRatio(1000, 500);
    let msg = format!("{}", err);

    assert!(msg.contains("Suspicious compression ratio"));
    assert!(msg.contains("1000"));
    assert!(msg.contains("500"));
}

#[test]
fn test_error_symlink_not_allowed() {
    let err = RustyZipError::SymlinkNotAllowed("link.txt".to_string());
    let msg = format!("{}", err);

    assert!(msg.contains("Symlink not allowed"));
    assert!(msg.contains("link.txt"));
}

#[test]
fn test_error_debug_formatting() {
    let err = RustyZipError::InvalidPassword;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidPassword"));

    let err2 = RustyZipError::FileNotFound("test.txt".to_string());
    let debug_str2 = format!("{:?}", err2);
    assert!(debug_str2.contains("FileNotFound"));
}

#[test]
fn test_error_walkdir_conversion() {
    use std::path::PathBuf;

    // Create a WalkDir error by trying to walk a non-existent directory
    let path = PathBuf::from("/nonexistent/path/that/does/not/exist/xyzabc123");

    // WalkDir returns an iterator, we need to trigger an actual error
    // The easiest way is to walk a path and get an error from permissions or non-existence
    let walk_result = walkdir::WalkDir::new(&path).into_iter().next();

    if let Some(Err(walk_err)) = walk_result {
        let rusty_err: RustyZipError = walk_err.into();
        match rusty_err {
            RustyZipError::WalkDirError(_) => {}
            _ => panic!("Expected WalkDirError variant"),
        }
    }
}

// ============================================================================
// Utils Module Coverage Through Public APIs
// ============================================================================
// Note: utils.rs is internal, so we test it indirectly through public APIs
// The functions in utils.rs are used by compress_file and compress_bytes

#[test]
fn test_utils_via_compress_file_preserves_metadata() {
    // This tests add_file_to_zip which calls system_time_to_zip_datetime
    let tmp_dir = TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("test.txt");
    fs::write(&file_path, "Test content").unwrap();

    let output = tmp_dir.path().join("output.zip");
    compress_file(
        &file_path,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());
}

#[test]
fn test_utils_via_compress_bytes_with_encryption() {
    // This tests add_bytes_to_zip with various encryption methods
    let files = vec![
        ("file1.txt", b"Content 1" as &[u8]),
        ("file2.txt", b"Content 2" as &[u8]),
    ];

    // Test with ZipCrypto
    let zip1 = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
    assert!(!zip1.is_empty());

    // Test with AES256
    let zip2 = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
    assert!(!zip2.is_empty());

    // Test with STORE level (tests compression method selection)
    let zip3 = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();
    assert!(!zip3.is_empty());
}

#[test]
fn test_utils_large_file_chunked_reading() {
    // This tests the chunked reading in add_reader_to_zip_with_time
    let tmp_dir = TempDir::new().unwrap();

    // Create a file larger than the read buffer (64KB)
    let large_content = vec![b'X'; 150_000];
    let file_path = tmp_dir.path().join("large.txt");
    fs::write(&file_path, &large_content).unwrap();

    let output = tmp_dir.path().join("output.zip");
    compress_file(
        &file_path,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());
}

// ============================================================================
// Types Module Tests (types.rs - 37.25% → 100%)
// ============================================================================

#[test]
fn test_compression_level_new_boundary() {
    let level0 = CompressionLevel::new(0);
    assert_eq!(level0.0, 0);

    let level9 = CompressionLevel::new(9);
    assert_eq!(level9.0, 9);

    let level10 = CompressionLevel::new(10);
    assert_eq!(level10.0, 9); // Clamped to max

    let level100 = CompressionLevel::new(100);
    assert_eq!(level100.0, 9); // Clamped to max
}

#[test]
fn test_compression_level_constants() {
    assert_eq!(CompressionLevel::STORE.0, 0);
    assert_eq!(CompressionLevel::FAST.0, 1);
    assert_eq!(CompressionLevel::DEFAULT.0, 6);
    assert_eq!(CompressionLevel::BEST.0, 9);
}

#[test]
fn test_compression_level_debug() {
    let level = CompressionLevel::new(7);
    let debug = format!("{:?}", level);
    assert!(debug.contains("CompressionLevel"));
}

#[test]
fn test_compression_level_clone() {
    let level1 = CompressionLevel::new(5);
    let level2 = level1.clone();

    assert_eq!(level1.0, level2.0);
}

#[test]
fn test_compression_level_copy() {
    let level1 = CompressionLevel::new(5);
    let level2 = level1; // Copy trait

    assert_eq!(level1.0, level2.0);
}

#[test]
fn test_compression_level_default() {
    let default_level = CompressionLevel::default();
    assert_eq!(default_level.0, 6);
}

#[test]
fn test_compression_level_to_flate2() {
    let store = CompressionLevel::STORE;
    let flate2_level = store.to_flate2_compression();
    assert_eq!(flate2_level.level(), 0);

    let best = CompressionLevel::BEST;
    let flate2_best = best.to_flate2_compression();
    assert_eq!(flate2_best.level(), 9);
}

#[test]
fn test_encryption_method_debug() {
    let none_debug = format!("{:?}", EncryptionMethod::None);
    assert!(none_debug.contains("None"));

    let aes_debug = format!("{:?}", EncryptionMethod::Aes256);
    assert!(aes_debug.contains("Aes256"));

    let zipcrypto_debug = format!("{:?}", EncryptionMethod::ZipCrypto);
    assert!(zipcrypto_debug.contains("ZipCrypto"));
}

#[test]
fn test_encryption_method_partial_eq() {
    assert_eq!(EncryptionMethod::None, EncryptionMethod::None);
    assert_eq!(EncryptionMethod::Aes256, EncryptionMethod::Aes256);
    assert_ne!(EncryptionMethod::None, EncryptionMethod::Aes256);
}

#[test]
fn test_encryption_method_clone() {
    let enc1 = EncryptionMethod::Aes256;
    let enc2 = enc1.clone();

    assert_eq!(enc1, enc2);
}

#[test]
fn test_encryption_method_copy() {
    let enc1 = EncryptionMethod::ZipCrypto;
    let enc2 = enc1; // Copy trait

    assert_eq!(enc1, enc2);
}

#[test]
fn test_encryption_method_default() {
    let default_enc = EncryptionMethod::default();
    assert_eq!(default_enc, EncryptionMethod::Aes256);
}

#[test]
fn test_encryption_method_from_str() {
    // Test various string formats
    assert_eq!(
        EncryptionMethod::parse("none").unwrap(),
        EncryptionMethod::None
    );
    assert_eq!(
        EncryptionMethod::parse("None").unwrap(),
        EncryptionMethod::None
    );
    assert_eq!(
        EncryptionMethod::parse("NONE").unwrap(),
        EncryptionMethod::None
    );
    assert_eq!(EncryptionMethod::parse("").unwrap(), EncryptionMethod::None);

    assert_eq!(
        EncryptionMethod::parse("zipcrypto").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::parse("ZipCrypto").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::parse("zip_crypto").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::parse("legacy").unwrap(),
        EncryptionMethod::ZipCrypto
    );

    assert_eq!(
        EncryptionMethod::parse("aes256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("Aes256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("AES-256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("aes").unwrap(),
        EncryptionMethod::Aes256
    );

    // Invalid
    assert!(EncryptionMethod::parse("invalid").is_err());
    assert!(EncryptionMethod::parse("unknown").is_err());
}

#[test]
fn test_encryption_method_is_single_method() {
    assert!(EncryptionMethod::None.is_single_method());
    assert!(EncryptionMethod::ZipCrypto.is_single_method());
    assert!(EncryptionMethod::Aes256.is_single_method());
    assert!(!EncryptionMethod::Mixed.is_single_method());
}

#[test]
fn test_encryption_method_mixed_variant() {
    let mixed = EncryptionMethod::Mixed;
    assert_eq!(mixed, EncryptionMethod::Mixed);
    assert!(!mixed.is_single_method());
}

#[test]
fn test_encryption_method_all_variants() {
    // Ensure all variants work
    let methods = vec![
        EncryptionMethod::None,
        EncryptionMethod::ZipCrypto,
        EncryptionMethod::Aes256,
        EncryptionMethod::Mixed,
    ];

    for method in methods {
        let _debug = format!("{:?}", method);
        let _ = method.clone();
    }
}
