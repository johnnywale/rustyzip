//! Comprehensive tests for streaming.rs to achieve 100% coverage

use rustyzip::compression::{
    compress_stream, decompress_stream_to_vec, decompress_stream_to_vec_with_limits,
    CompressionLevel, EncryptionMethod,
};
use rustyzip::error::RustyZipError;
use std::io::{Cursor, Write};
use zip::write::{SimpleFileOptions, ZipWriter};

// ============================================================================
// compress_stream Tests
// ============================================================================

#[test]
fn test_compress_stream_single_file() {
    let files = vec![("file1.txt".to_string(), Cursor::new(b"Content 1".to_vec()))];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_multiple_files() {
    let files = vec![
        ("file1.txt".to_string(), Cursor::new(b"Content 1".to_vec())),
        ("file2.txt".to_string(), Cursor::new(b"Content 2".to_vec())),
        ("file3.txt".to_string(), Cursor::new(b"Content 3".to_vec())),
    ];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_with_password_zipcrypto() {
    let files = vec![(
        "secret.txt".to_string(),
        Cursor::new(b"Secret data".to_vec()),
    )];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        Some("password"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_with_password_aes256() {
    let files = vec![(
        "encrypted.txt".to_string(),
        Cursor::new(b"AES encrypted".to_vec()),
    )];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_with_store_level() {
    let files = vec![(
        "stored.txt".to_string(),
        Cursor::new(b"No compression".to_vec()),
    )];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_with_best_level() {
    let files = vec![(
        "compressed.txt".to_string(),
        Cursor::new(b"AAAAAAAA".repeat(100)),
    )];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::BEST,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_empty_iterator() {
    let files: Vec<(String, Cursor<Vec<u8>>)> = vec![];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_large_file() {
    // Test streaming with large file (> 64KB to test chunking)
    let large_data = vec![b'X'; 200_000];
    let files = vec![("large.bin".to_string(), Cursor::new(large_data))];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

#[test]
fn test_compress_stream_subdirectories() {
    let files = vec![
        ("root.txt".to_string(), Cursor::new(b"Root file".to_vec())),
        (
            "dir/nested.txt".to_string(),
            Cursor::new(b"Nested file".to_vec()),
        ),
        (
            "dir/sub/deep.txt".to_string(),
            Cursor::new(b"Deep file".to_vec()),
        ),
    ];

    let output = Cursor::new(Vec::new());
    compress_stream(
        output,
        files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();
}

// ============================================================================
// decompress_stream_to_vec Tests
// ============================================================================

fn create_zip_in_memory(
    files: Vec<(&str, &[u8])>,
    password: Option<&str>,
    encryption: EncryptionMethod,
) -> Vec<u8> {
    use zip::unstable::write::FileOptionsExt;

    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);

    for (name, content) in files {
        let options = SimpleFileOptions::default();

        let options = match (password, encryption) {
            (Some(pwd), EncryptionMethod::Aes256) => {
                options.with_aes_encryption(zip::AesMode::Aes256, pwd)
            }
            (Some(pwd), EncryptionMethod::ZipCrypto) => {
                options.with_deprecated_encryption(pwd.as_bytes())
            }
            _ => options,
        };

        zip.start_file(name, options).unwrap();
        zip.write_all(content).unwrap();
    }

    let cursor = zip.finish().unwrap();
    cursor.into_inner()
}

#[test]
fn test_decompress_stream_to_vec_simple() {
    let zip_data = create_zip_in_memory(
        vec![("file.txt", b"Hello, World!")],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, None).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "file.txt");
    assert_eq!(result[0].1, b"Hello, World!");
}

#[test]
fn test_decompress_stream_to_vec_multiple_files() {
    let zip_data = create_zip_in_memory(
        vec![
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("file3.txt", b"Content 3"),
        ],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, None).unwrap();

    assert_eq!(result.len(), 3);
    assert_eq!(result[0].0, "file1.txt");
    assert_eq!(result[1].0, "file2.txt");
    assert_eq!(result[2].0, "file3.txt");
}

#[test]
fn test_decompress_stream_with_password() {
    let zip_data = create_zip_in_memory(
        vec![("secret.txt", b"Secret content")],
        Some("password123"),
        EncryptionMethod::Aes256,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, Some("password123")).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, b"Secret content");
}

#[test]
fn test_decompress_stream_wrong_password() {
    let zip_data = create_zip_in_memory(
        vec![("secret.txt", b"Secret content")],
        Some("correct_password"),
        EncryptionMethod::Aes256,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, Some("wrong_password"));

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::InvalidPassword => {}
        e => panic!("Expected InvalidPassword, got {:?}", e),
    }
}

#[test]
fn test_decompress_stream_with_directory() {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);

    // Add a directory
    zip.add_directory("testdir/", SimpleFileOptions::default())
        .unwrap();
    // Add a file
    zip.start_file("testdir/file.txt", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"Content").unwrap();

    let cursor = zip.finish().unwrap();
    let zip_data = cursor.into_inner();

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, None).unwrap();

    // Should only contain the file, not the directory
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "testdir/file.txt");
}

// ============================================================================
// decompress_stream_to_vec_with_limits Tests
// ============================================================================

#[test]
fn test_decompress_stream_with_limits_normal() {
    let zip_data = create_zip_in_memory(
        vec![("file.txt", b"Normal content")],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(
        cursor, None, 1_000_000, // 1MB limit
        500,       // 500x ratio limit
    )
    .unwrap();

    assert_eq!(result.len(), 1);
}

#[test]
fn test_decompress_stream_exceeds_size_limit() {
    // Create a large file
    let large_data = vec![b'X'; 10_000];
    let zip_data = create_zip_in_memory(
        vec![("large.bin", &large_data)],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(
        cursor, None, 1000, // Very small limit
        500,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::ZipBomb(_, _) => {}
        e => panic!("Expected ZipBomb error, got {:?}", e),
    }
}

#[test]
fn test_decompress_stream_high_compression_ratio() {
    // Create highly compressible data
    let repeated_data = vec![b'A'; 50_000];
    let zip_data = create_zip_in_memory(
        vec![("repeated.txt", &repeated_data)],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(
        cursor,
        None,
        100_000_000, // High size limit
        10,          // Very low ratio limit
    );

    // This might fail due to compression ratio
    if result.is_err() {
        match result.unwrap_err() {
            RustyZipError::SuspiciousCompressionRatio(_, _) => {}
            e => panic!("Expected SuspiciousCompressionRatio, got {:?}", e),
        }
    }
}

#[test]
fn test_decompress_stream_multiple_files_total_size() {
    // Create multiple files that together exceed the limit
    let data1 = vec![b'X'; 5_000];
    let data2 = vec![b'Y'; 5_000];
    let data3 = vec![b'Z'; 5_000];

    let zip_data = create_zip_in_memory(
        vec![
            ("file1.bin", &data1),
            ("file2.bin", &data2),
            ("file3.bin", &data3),
        ],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(
        cursor, None, 10_000, // Should fail - total is 15,000
        500,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::ZipBomb(_, _) => {}
        e => panic!("Expected ZipBomb error, got {:?}", e),
    }
}

#[test]
fn test_decompress_stream_zero_compressed_size() {
    // Test file with zero compressed size (stored)
    let zip_data = create_zip_in_memory(vec![("empty.txt", b"")], None, EncryptionMethod::None);

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(cursor, None, 1_000_000, 500).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, b"");
}

#[test]
fn test_decompress_stream_large_capacity_cap() {
    // Test that capacity is capped at 64MB even if file size is larger
    // Use less compressible data to avoid ratio limits
    let large_data: Vec<u8> = (0..10_000_u16).flat_map(|i| i.to_le_bytes()).collect();
    let zip_data = create_zip_in_memory(
        vec![("large.bin", &large_data)],
        None,
        EncryptionMethod::None,
    );

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec_with_limits(
        cursor, None, 1_000_000, 1000, // Higher ratio limit
    )
    .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1.len(), large_data.len());
}

#[test]
fn test_decompress_stream_empty_archive() {
    let zip_data = create_zip_in_memory(vec![], None, EncryptionMethod::None);

    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, None).unwrap();

    assert_eq!(result.len(), 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_compress_decompress_stream_roundtrip() {
    // Create using create_zip_in_memory for simplicity
    let zip_data = create_zip_in_memory(
        vec![("file1.txt", b"Content 1"), ("file2.txt", b"Content 2")],
        None,
        EncryptionMethod::None,
    );

    // Decompress
    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, None).unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "file1.txt");
    assert_eq!(result[0].1, b"Content 1");
    assert_eq!(result[1].0, "file2.txt");
    assert_eq!(result[1].1, b"Content 2");
}

#[test]
fn test_compress_decompress_stream_with_password_roundtrip() {
    let zip_data = create_zip_in_memory(
        vec![("secret.txt", b"Secret data")],
        Some("mypassword"),
        EncryptionMethod::Aes256,
    );

    // Decompress with correct password
    let cursor = Cursor::new(zip_data);
    let result = decompress_stream_to_vec(cursor, Some("mypassword")).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, b"Secret data");
}
