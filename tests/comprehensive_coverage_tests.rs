//! Comprehensive tests to achieve 100% Rust code coverage
//! This file targets modules with low coverage to reach 100%

use rustyzip::compression::{
    compress_directory, compress_file, decompress_file, CompressionLevel, EncryptionMethod,
};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

// =============================================================================
// CompressionLevel Tests (types.rs - currently 37.25%)
// =============================================================================

#[test]
fn test_compression_level_intermediate_values() {
    // Test all levels 0-9
    for level in 0..=9 {
        let cl = CompressionLevel::new(level);
        assert_eq!(cl.0, level);
    }
}

#[test]
fn test_compression_level_clamping_edge_cases() {
    assert_eq!(CompressionLevel::new(10).0, 9);
    assert_eq!(CompressionLevel::new(255).0, 9);
    assert_eq!(CompressionLevel::new(u32::MAX).0, 9);
}

#[test]
fn test_compression_level_default_trait() {
    let default = CompressionLevel::default();
    assert_eq!(default.0, 6);
}

#[test]
fn test_compression_level_to_flate2() {
    for level in 0..=9 {
        let cl = CompressionLevel::new(level);
        let _ = cl.to_flate2_compression(); // Just ensure it doesn't panic
    }
}

// =============================================================================
// EncryptionMethod Tests (types.rs)
// =============================================================================

#[test]
fn test_encryption_method_from_str_all_variants() {
    // Test all valid inputs
    assert_eq!(
        EncryptionMethod::parse("aes256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("aes").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("aes-256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::parse("AES256").unwrap(),
        EncryptionMethod::Aes256
    );

    assert_eq!(
        EncryptionMethod::parse("zipcrypto").unwrap(),
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
        EncryptionMethod::parse("none").unwrap(),
        EncryptionMethod::None
    );
    assert_eq!(EncryptionMethod::parse("").unwrap(), EncryptionMethod::None);
}

#[test]
fn test_encryption_method_invalid_strings() {
    assert!(EncryptionMethod::parse("invalid").is_err());
    assert!(EncryptionMethod::parse("aes128").is_err());
    assert!(EncryptionMethod::parse("des").is_err());
    assert!(EncryptionMethod::parse("rsa").is_err());
    assert!(EncryptionMethod::parse("mixed").is_err());
}

#[test]
fn test_encryption_method_is_single_method() {
    assert!(EncryptionMethod::None.is_single_method());
    assert!(EncryptionMethod::ZipCrypto.is_single_method());
    assert!(EncryptionMethod::Aes256.is_single_method());
    assert!(!EncryptionMethod::Mixed.is_single_method());
}

#[test]
fn test_encryption_method_default_is_aes256() {
    let default = EncryptionMethod::default();
    assert_eq!(default, EncryptionMethod::Aes256);
}

// =============================================================================
// Sequential Compression Tests (sequential.rs - currently 28.40%)
// =============================================================================

#[test]
fn test_sequential_compression_no_password() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("test.txt");
    let zip_file = temp_dir.path().join("test.zip");
    let output_dir = temp_dir.path().join("output");

    // Create test file
    File::create(&input_file)
        .unwrap()
        .write_all(b"sequential test")
        .unwrap();

    // Compress using sequential path (disable parallel feature conceptually)
    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE, // STORE level uses sequential path
    )
    .unwrap();

    // Decompress and verify
    decompress_file(&zip_file, &output_dir, None, false).unwrap();
    let content = fs::read_to_string(output_dir.join("test.txt")).unwrap();
    assert_eq!(content, "sequential test");
}

#[test]
fn test_sequential_with_all_compression_levels() {
    let temp_dir = tempdir().unwrap();

    for level in 0..=9 {
        let input_file = temp_dir.path().join(format!("test_{}.txt", level));
        let zip_file = temp_dir.path().join(format!("test_{}.zip", level));

        File::create(&input_file)
            .unwrap()
            .write_all(b"test data for levels")
            .unwrap();

        compress_file(
            &input_file,
            &zip_file,
            None,
            EncryptionMethod::None,
            CompressionLevel::new(level),
        )
        .unwrap();

        assert!(zip_file.exists());
    }
}

#[test]
fn test_sequential_directory_compression() {
    let temp_dir = tempdir().unwrap();
    let input_dir = temp_dir.path().join("input");
    let zip_file = temp_dir.path().join("dir.zip");

    fs::create_dir(&input_dir).unwrap();
    File::create(input_dir.join("file1.txt"))
        .unwrap()
        .write_all(b"content1")
        .unwrap();
    File::create(input_dir.join("file2.txt"))
        .unwrap()
        .write_all(b"content2")
        .unwrap();

    compress_directory(
        &input_dir,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::FAST, // Fast level might use sequential
        None,
        None,
    )
    .unwrap();

    assert!(zip_file.exists());
}

// =============================================================================
// Error Handling Tests (error.rs - currently 50.00%)
// =============================================================================

#[test]
fn test_error_display_and_debug() {
    use rustyzip::error::RustyZipError;
    use std::io;

    let errors = vec![
        RustyZipError::Io(io::Error::new(io::ErrorKind::NotFound, "test")),
        RustyZipError::InvalidPassword,
        RustyZipError::FileNotFound("test.txt".to_string()),
        RustyZipError::UnsupportedEncryption("AES512".to_string()),
        RustyZipError::InvalidPath("/invalid".to_string()),
        RustyZipError::PatternError("[bad".to_string()),
        RustyZipError::PathTraversal("../etc/passwd".to_string()),
        RustyZipError::ZipBomb(1000, 10000),
        RustyZipError::SuspiciousCompressionRatio(1000, 10),
        RustyZipError::SymlinkNotAllowed("link".to_string()),
    ];

    for err in errors {
        // Test Display
        let display = format!("{}", err);
        assert!(!display.is_empty());

        // Test Debug
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }
}

#[test]
fn test_error_source_trait() {
    use rustyzip::error::RustyZipError;
    use std::error::Error;
    use std::io;

    let io_err = io::Error::new(io::ErrorKind::NotFound, "source error");
    let zip_err = RustyZipError::Io(io_err);

    // Test source() method
    assert!(zip_err.source().is_some());

    // Test errors without source
    let simple_err = RustyZipError::InvalidPassword;
    assert!(simple_err.source().is_none());
}

// =============================================================================
// All Encryption Methods with All Compression Levels
// =============================================================================

#[test]
fn test_all_encryption_and_compression_combinations() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("test.txt");
    File::create(&input_file)
        .unwrap()
        .write_all(b"combination test")
        .unwrap();

    let encryption_methods = vec![
        EncryptionMethod::None,
        EncryptionMethod::ZipCrypto,
        EncryptionMethod::Aes256,
    ];

    let compression_levels = vec![
        CompressionLevel::STORE,
        CompressionLevel::FAST,
        CompressionLevel::DEFAULT,
        CompressionLevel::BEST,
    ];

    for (i, encryption) in encryption_methods.iter().enumerate() {
        for (j, &level) in compression_levels.iter().enumerate() {
            let zip_file = temp_dir.path().join(format!("combo_{}_{}.zip", i, j));
            let password = match encryption {
                EncryptionMethod::None => None,
                _ => Some("test_password"),
            };

            let result = compress_file(&input_file, &zip_file, password, *encryption, level);

            assert!(
                result.is_ok(),
                "Failed for {:?} with level {:?}",
                encryption,
                level
            );
            assert!(zip_file.exists());
        }
    }
}

// =============================================================================
// Edge Cases and Error Conditions
// =============================================================================

#[test]
fn test_compress_empty_file() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("empty.txt");
    let zip_file = temp_dir.path().join("empty.zip");

    File::create(&input_file).unwrap(); // Create empty file

    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(zip_file.exists());
}

#[test]
fn test_compress_very_small_file() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("tiny.txt");
    let zip_file = temp_dir.path().join("tiny.zip");

    File::create(&input_file).unwrap().write_all(b"a").unwrap();

    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::BEST,
    )
    .unwrap();

    assert!(zip_file.exists());
}

#[test]
fn test_decompress_with_withoutpath_flag() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("test.txt");
    let zip_file = temp_dir.path().join("test.zip");
    let output_dir = temp_dir.path().join("output");

    File::create(&input_file)
        .unwrap()
        .write_all(b"test content")
        .unwrap();

    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Decompress with withoutpath = true
    decompress_file(&zip_file, &output_dir, None, true).unwrap();

    // File should be extracted directly to output_dir without subdirectories
    assert!(output_dir.join("test.txt").exists());
}

#[test]
fn test_compress_directory_with_empty_patterns() {
    let temp_dir = tempdir().unwrap();
    let input_dir = temp_dir.path().join("input");
    let zip_file = temp_dir.path().join("output.zip");

    fs::create_dir(&input_dir).unwrap();
    File::create(input_dir.join("file.txt"))
        .unwrap()
        .write_all(b"content")
        .unwrap();

    // Test with empty include/exclude patterns
    compress_directory(
        &input_dir,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&[]), // Empty include
        Some(&[]), // Empty exclude
    )
    .unwrap();

    assert!(zip_file.exists());
}

#[test]
fn test_compression_with_special_characters_in_filename() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("file-with_special.chars.txt");
    let zip_file = temp_dir.path().join("special.zip");

    File::create(&input_file)
        .unwrap()
        .write_all(b"special content")
        .unwrap();

    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(zip_file.exists());
}

#[test]
fn test_multiple_files_different_sizes() {
    let temp_dir = tempdir().unwrap();
    let input_dir = temp_dir.path().join("input");
    let zip_file = temp_dir.path().join("sizes.zip");

    fs::create_dir(&input_dir).unwrap();

    // Create files of different sizes
    File::create(input_dir.join("small.txt"))
        .unwrap()
        .write_all(b"small")
        .unwrap();
    File::create(input_dir.join("medium.txt"))
        .unwrap()
        .write_all(&vec![b'M'; 1024])
        .unwrap();
    File::create(input_dir.join("large.txt"))
        .unwrap()
        .write_all(&vec![b'L'; 10240])
        .unwrap();

    compress_directory(
        &input_dir,
        &zip_file,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(zip_file.exists());
}

#[test]
fn test_compress_deeply_nested_directory() {
    let temp_dir = tempdir().unwrap();
    let input_dir = temp_dir.path().join("input");
    let zip_file = temp_dir.path().join("nested.zip");

    // Create nested directory structure
    let deep_dir = input_dir.join("a").join("b").join("c").join("d");
    fs::create_dir_all(&deep_dir).unwrap();
    File::create(deep_dir.join("deep.txt"))
        .unwrap()
        .write_all(b"deep content")
        .unwrap();

    compress_directory(
        &input_dir,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(zip_file.exists());
}
