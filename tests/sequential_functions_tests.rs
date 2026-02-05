//! Direct tests for compress_files_sequential and compress_directory_sequential
//! These functions are normally only called when parallel feature is disabled,
//! but we can test them directly to ensure complete coverage.

use rustyzip::compression::sequential::{compress_directory_sequential, compress_files_sequential};
use rustyzip::compression::{decompress_file, CompressionLevel, EncryptionMethod};
use rustyzip::error::RustyZipError;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// compress_files_sequential Tests
// ============================================================================

#[test]
fn test_compress_files_sequential_single_file() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    fs::write(&file1, b"Content 1").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path()];
    let prefixes = vec![None];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());
}

#[test]
fn test_compress_files_sequential_multiple_files() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    let file2 = tmp_dir.path().join("file2.txt");
    let file3 = tmp_dir.path().join("file3.txt");

    fs::write(&file1, b"Content 1").unwrap();
    fs::write(&file2, b"Content 2").unwrap();
    fs::write(&file3, b"Content 3").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path(), file2.as_path(), file3.as_path()];
    let prefixes = vec![None, None, None];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify by decompressing
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file1.txt").exists());
    assert!(extract_dir.join("file2.txt").exists());
    assert!(extract_dir.join("file3.txt").exists());
}

#[test]
fn test_compress_files_sequential_with_prefixes() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    let file2 = tmp_dir.path().join("file2.txt");

    fs::write(&file1, b"Content 1").unwrap();
    fs::write(&file2, b"Content 2").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path(), file2.as_path()];
    let prefixes = vec![Some("dir1"), Some("dir2")];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify structure
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("dir1/file1.txt").exists());
    assert!(extract_dir.join("dir2/file2.txt").exists());
}

#[test]
fn test_compress_files_sequential_with_mixed_prefixes() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    let file2 = tmp_dir.path().join("file2.txt");
    let file3 = tmp_dir.path().join("file3.txt");

    fs::write(&file1, b"Content 1").unwrap();
    fs::write(&file2, b"Content 2").unwrap();
    fs::write(&file3, b"Content 3").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path(), file2.as_path(), file3.as_path()];
    let prefixes = vec![Some("prefix/"), None, Some("/trimmed/")];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify structure - prefixes with slashes should be trimmed
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("prefix/file1.txt").exists());
    assert!(extract_dir.join("file2.txt").exists());
    assert!(extract_dir.join("trimmed/file3.txt").exists());
}

#[test]
fn test_compress_files_sequential_with_encryption_zipcrypto() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    fs::write(&file1, b"Secret content").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path()];
    let prefixes = vec![None];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        Some("password123"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify can decrypt
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, Some("password123"), false).unwrap();

    let content = fs::read_to_string(extract_dir.join("file1.txt")).unwrap();
    assert_eq!(content, "Secret content");
}

#[test]
fn test_compress_files_sequential_with_encryption_aes256() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    fs::write(&file1, b"Secret AES content").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path()];
    let prefixes = vec![None];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        Some("password456"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify can decrypt
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, Some("password456"), false).unwrap();

    let content = fs::read_to_string(extract_dir.join("file1.txt")).unwrap();
    assert_eq!(content, "Secret AES content");
}

#[test]
fn test_compress_files_sequential_all_compression_levels() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    fs::write(&file1, b"A".repeat(1000)).unwrap();

    let levels = [
        CompressionLevel::STORE,
        CompressionLevel::FAST,
        CompressionLevel::DEFAULT,
        CompressionLevel::BEST,
    ];

    for level in levels {
        let output = tmp_dir.path().join(format!("output_{}.zip", level.0));
        let input_paths = vec![file1.as_path()];
        let prefixes = vec![None];

        compress_files_sequential(
            &input_paths,
            &prefixes,
            &output,
            None,
            EncryptionMethod::None,
            level,
        )
        .unwrap();

        assert!(output.exists());
    }
}

#[test]
fn test_compress_files_sequential_file_not_found() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    let nonexistent = tmp_dir.path().join("nonexistent.txt");

    fs::write(&file1, b"Content 1").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path(), nonexistent.as_path()];
    let prefixes = vec![None, None];

    let result = compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
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
fn test_compress_files_sequential_empty_prefix() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("file1.txt");
    fs::write(&file1, b"Content 1").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path()];
    let prefixes = vec![Some("")]; // Empty prefix

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());

    // Verify file is at root
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file1.txt").exists());
}

#[test]
fn test_compress_files_sequential_large_file() {
    let tmp_dir = TempDir::new().unwrap();
    let file1 = tmp_dir.path().join("large.bin");

    // Create a larger file (200KB)
    let large_data = vec![b'X'; 200_000];
    fs::write(&file1, &large_data).unwrap();

    let output = tmp_dir.path().join("output.zip");
    let input_paths = vec![file1.as_path()];
    let prefixes = vec![None];

    compress_files_sequential(
        &input_paths,
        &prefixes,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    assert!(output.exists());
}

// ============================================================================
// compress_directory_sequential Tests
// ============================================================================

#[test]
fn test_compress_directory_sequential_basic() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file1.txt"), b"Content 1").unwrap();
    fs::write(input_dir.join("file2.txt"), b"Content 2").unwrap();

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify contents
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file1.txt").exists());
    assert!(extract_dir.join("file2.txt").exists());
}

#[test]
fn test_compress_directory_sequential_nested() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("root.txt"), b"Root file").unwrap();

    let subdir = input_dir.join("subdir");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("nested.txt"), b"Nested file").unwrap();

    let deepdir = subdir.join("deep");
    fs::create_dir(&deepdir).unwrap();
    fs::write(deepdir.join("deep.txt"), b"Deep file").unwrap();

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify structure
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("root.txt").exists());
    assert!(extract_dir.join("subdir/nested.txt").exists());
    assert!(extract_dir.join("subdir/deep/deep.txt").exists());
}

#[test]
fn test_compress_directory_sequential_with_include_patterns() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file1.txt"), b"Text file 1").unwrap();
    fs::write(input_dir.join("file2.txt"), b"Text file 2").unwrap();
    fs::write(input_dir.join("data.json"), b"{}").unwrap();
    fs::write(input_dir.join("script.py"), b"print('hello')").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let include_patterns = vec!["*.txt".to_string()];

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&include_patterns),
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify only .txt files are included
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file1.txt").exists());
    assert!(extract_dir.join("file2.txt").exists());
    assert!(!extract_dir.join("data.json").exists());
    assert!(!extract_dir.join("script.py").exists());
}

#[test]
fn test_compress_directory_sequential_with_exclude_patterns() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file1.txt"), b"Text file 1").unwrap();
    fs::write(input_dir.join("file2.txt"), b"Text file 2").unwrap();
    fs::write(input_dir.join("temp.tmp"), b"Temp file").unwrap();
    fs::write(input_dir.join("cache.log"), b"Log file").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let exclude_patterns = vec!["*.tmp".to_string(), "*.log".to_string()];

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        Some(&exclude_patterns),
    )
    .unwrap();

    assert!(output.exists());

    // Verify .tmp and .log files are excluded
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file1.txt").exists());
    assert!(extract_dir.join("file2.txt").exists());
    assert!(!extract_dir.join("temp.tmp").exists());
    assert!(!extract_dir.join("cache.log").exists());
}

#[test]
fn test_compress_directory_sequential_with_both_patterns() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("doc1.txt"), b"Doc 1").unwrap();
    fs::write(input_dir.join("doc2.txt"), b"Doc 2").unwrap();
    fs::write(input_dir.join("draft.txt"), b"Draft").unwrap();
    fs::write(input_dir.join("data.json"), b"{}").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let include_patterns = vec!["*.txt".to_string()];
    let exclude_patterns = vec!["draft*".to_string()];

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&include_patterns),
        Some(&exclude_patterns),
    )
    .unwrap();

    assert!(output.exists());

    // Verify only .txt files (except draft.txt) are included
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("doc1.txt").exists());
    assert!(extract_dir.join("doc2.txt").exists());
    assert!(!extract_dir.join("draft.txt").exists());
    assert!(!extract_dir.join("data.json").exists());
}

#[test]
fn test_compress_directory_sequential_with_encryption() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("secret.txt"), b"Secret data").unwrap();

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        Some("password789"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify can decrypt
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, Some("password789"), false).unwrap();

    let content = fs::read_to_string(extract_dir.join("secret.txt")).unwrap();
    assert_eq!(content, "Secret data");
}

#[test]
fn test_compress_directory_sequential_empty_directory() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("empty");
    fs::create_dir(&input_dir).unwrap();

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());
}

#[test]
fn test_compress_directory_sequential_dir_not_found() {
    let tmp_dir = TempDir::new().unwrap();
    let nonexistent = tmp_dir.path().join("nonexistent");

    let output = tmp_dir.path().join("output.zip");

    let result = compress_directory_sequential(
        &nonexistent,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::FileNotFound(_) => {}
        e => panic!("Expected FileNotFound error, got {:?}", e),
    }
}

#[test]
fn test_compress_directory_sequential_path_is_file() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("file.txt");
    fs::write(&file_path, b"Not a directory").unwrap();

    let output = tmp_dir.path().join("output.zip");

    let result = compress_directory_sequential(
        &file_path,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::InvalidPath(msg) => {
            assert!(msg.contains("not a directory"));
        }
        e => panic!("Expected InvalidPath error, got {:?}", e),
    }
}

#[test]
fn test_compress_directory_sequential_invalid_pattern() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file.txt"), b"Content").unwrap();

    let output = tmp_dir.path().join("output.zip");
    let invalid_patterns = vec!["[invalid".to_string()]; // Invalid glob pattern

    let result = compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        Some(&invalid_patterns),
        None,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::PatternError(_) => {}
        e => panic!("Expected PatternError, got {:?}", e),
    }
}

#[test]
fn test_compress_directory_sequential_all_compression_levels() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file.txt"), b"A".repeat(1000)).unwrap();

    let levels = [
        CompressionLevel::STORE,
        CompressionLevel::FAST,
        CompressionLevel::DEFAULT,
        CompressionLevel::BEST,
    ];

    for level in levels {
        let output = tmp_dir.path().join(format!("output_{}.zip", level.0));

        compress_directory_sequential(
            &input_dir,
            &output,
            None,
            EncryptionMethod::None,
            level,
            None,
            None,
        )
        .unwrap();

        assert!(output.exists());
    }
}

#[test]
fn test_compress_directory_sequential_large_directory() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    // Create multiple files
    for i in 0..20 {
        fs::write(
            input_dir.join(format!("file{}.txt", i)),
            format!("Content {}", i),
        )
        .unwrap();
    }

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify all files are present
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    for i in 0..20 {
        assert!(extract_dir.join(format!("file{}.txt", i)).exists());
    }
}

#[test]
fn test_compress_directory_sequential_skips_directories() {
    let tmp_dir = TempDir::new().unwrap();
    let input_dir = tmp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();

    fs::write(input_dir.join("file.txt"), b"File content").unwrap();

    let empty_subdir = input_dir.join("empty_subdir");
    fs::create_dir(&empty_subdir).unwrap();

    let output = tmp_dir.path().join("output.zip");

    compress_directory_sequential(
        &input_dir,
        &output,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
        None,
        None,
    )
    .unwrap();

    assert!(output.exists());

    // Verify only file is in archive, not empty directory
    let extract_dir = tmp_dir.path().join("extracted");
    fs::create_dir(&extract_dir).unwrap();
    decompress_file(&output, &extract_dir, None, false).unwrap();

    assert!(extract_dir.join("file.txt").exists());
    // Empty directories are not stored in ZIP
}
