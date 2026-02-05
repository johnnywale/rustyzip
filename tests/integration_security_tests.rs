//! Integration tests for security features
//! These tests focus on achieving 100% coverage of security.rs

use rustyzip::compression::{compress_file, CompressionLevel, EncryptionMethod};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_zip_bomb_high_compression_ratio() {
    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("large.txt");
    let zip_file = temp_dir.path().join("large.zip");

    // Create a file with highly compressible data (5MB of zeros)
    let mut file = File::create(&input_file).unwrap();
    let data = vec![0u8; 5 * 1024 * 1024];
    file.write_all(&data).unwrap();

    // Compress the file
    compress_file(
        &input_file,
        &zip_file,
        None,
        EncryptionMethod::None,
        CompressionLevel::BEST,
    )
    .unwrap();

    // Verify high compression was achieved
    let original_size = std::fs::metadata(&input_file).unwrap().len();
    let compressed_size = std::fs::metadata(&zip_file).unwrap().len();
    let ratio = original_size as f64 / compressed_size as f64;

    assert!(ratio > 10.0, "Should achieve high compression ratio");
}

#[test]
fn test_various_compression_levels_with_security() {
    let temp_dir = tempdir().unwrap();

    for level in [
        CompressionLevel::STORE,
        CompressionLevel::FAST,
        CompressionLevel::DEFAULT,
        CompressionLevel::BEST,
    ] {
        let input_file = temp_dir.path().join(format!("test_{}.txt", level.0));
        let zip_file = temp_dir.path().join(format!("test_{}.zip", level.0));

        // Create test data
        let mut file = File::create(&input_file).unwrap();
        file.write_all(b"Test data for compression levels").unwrap();

        // Compress with different levels
        compress_file(&input_file, &zip_file, None, EncryptionMethod::None, level).unwrap();

        assert!(zip_file.exists());
    }
}
