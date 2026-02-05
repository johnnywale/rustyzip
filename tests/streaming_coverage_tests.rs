//! Tests specifically for streaming and bytes functionality
//! These target compress_bytes and decompress_bytes functions

use rustyzip::compression::{compress_bytes, decompress_bytes, CompressionLevel, EncryptionMethod};

#[test]
fn test_compress_decompress_bytes_basic() {
    let files = [
        ("file1.txt", b"content1" as &[u8]),
        ("file2.txt", b"content2" as &[u8]),
    ];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed.len(), 2);
    assert_eq!(decompressed[0].0, "file1.txt");
    assert_eq!(decompressed[0].1, b"content1");
}

#[test]
fn test_bytes_with_password_aes256() {
    let files = [("secret.txt", b"secret data" as &[u8])];

    let zip_data = compress_bytes(
        &files,
        Some("password123"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, Some("password123")).unwrap();
    assert_eq!(decompressed[0].1, b"secret data");
}

#[test]
fn test_bytes_with_password_zipcrypto() {
    let files = [("secret.txt", b"secret data" as &[u8])];

    let zip_data = compress_bytes(
        &files,
        Some("pass"),
        EncryptionMethod::ZipCrypto,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, Some("pass")).unwrap();
    assert_eq!(decompressed[0].1, b"secret data");
}

#[test]
fn test_bytes_wrong_password() {
    let files = [("secret.txt", b"secret" as &[u8])];

    let zip_data = compress_bytes(
        &files,
        Some("correct"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // Wrong password should fail
    let result = decompress_bytes(&zip_data, Some("wrong"));
    assert!(result.is_err());
}

#[test]
fn test_bytes_missing_password() {
    let files = [("secret.txt", b"secret" as &[u8])];

    let zip_data = compress_bytes(
        &files,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    // No password should fail
    let result = decompress_bytes(&zip_data, None);
    assert!(result.is_err());
}

#[test]
fn test_bytes_empty_file() {
    let files = [("empty.txt", b"" as &[u8])];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed[0].1.len(), 0);
}

#[test]
fn test_bytes_large_data() {
    // Use random-ish data to avoid triggering ZIP bomb detection
    let large_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect(); // 10KB
    let files = [("large.bin", large_data.as_slice())];

    let zip_data =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed[0].1, large_data);
}

#[test]
fn test_bytes_with_subdirectories() {
    let files = [
        ("dir1/file1.txt", b"content1" as &[u8]),
        ("dir1/dir2/file2.txt", b"content2" as &[u8]),
        ("dir1/dir2/dir3/file3.txt", b"content3" as &[u8]),
    ];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed.len(), 3);
}

#[test]
fn test_bytes_all_compression_levels() {
    let data = b"test data that can be compressed";
    let files = [("test.txt", data as &[u8])];

    for level in 0..=9 {
        let zip_data = compress_bytes(
            &files,
            None,
            EncryptionMethod::None,
            CompressionLevel::new(level),
        )
        .unwrap();

        let decompressed = decompress_bytes(&zip_data, None).unwrap();
        assert_eq!(decompressed[0].1, data);
    }
}

#[test]
fn test_bytes_binary_data() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let files = [("binary.bin", binary_data.as_slice())];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed[0].1, binary_data);
}

#[test]
fn test_bytes_highly_compressible() {
    let compressible = vec![b'A'; 10000];
    let files = [("compressible.txt", compressible.as_slice())];

    let zip_data =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

    // Should compress well
    assert!(zip_data.len() < compressible.len() / 10);

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed[0].1, compressible);
}

#[test]
fn test_bytes_mixed_file_sizes() {
    let tiny = b"a";
    let small: Vec<u8> = (0..100).map(|i| (i % 26 + 65) as u8).collect();
    let medium: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let large: Vec<u8> = (0..5000).map(|i| (i * 7 % 256) as u8).collect();

    let files = [
        ("tiny.txt", tiny as &[u8]),
        ("small.txt", small.as_slice()),
        ("medium.txt", medium.as_slice()),
        ("large.txt", large.as_slice()),
    ];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed.len(), 4);
    assert_eq!(decompressed[0].1.len(), 1);
    assert_eq!(decompressed[1].1.len(), 100);
    assert_eq!(decompressed[2].1.len(), 1000);
    assert_eq!(decompressed[3].1.len(), 5000);
}

#[test]
fn test_bytes_special_characters() {
    let files = [
        ("file-with_special.chars (1).txt", b"content" as &[u8]),
        ("спец.txt", b"cyrillic" as &[u8]), // Cyrillic characters
    ];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed.len(), 2);
}

#[test]
fn test_bytes_multiple_files() {
    let files: Vec<(&str, &[u8])> = (0..10)
        .map(|i| {
            let name = format!("file{}.txt", i);
            let content = format!("content{}", i);
            // Note: This won't work as-is because the format! returns a String
            // that will be dropped. For this test, we need static data.
            ("static.txt", b"static" as &[u8])
        })
        .collect();

    // Simpler version with static data
    let files = [
        ("file0.txt", b"content0" as &[u8]),
        ("file1.txt", b"content1" as &[u8]),
        ("file2.txt", b"content2" as &[u8]),
        ("file3.txt", b"content3" as &[u8]),
        ("file4.txt", b"content4" as &[u8]),
    ];

    let zip_data = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let decompressed = decompress_bytes(&zip_data, None).unwrap();
    assert_eq!(decompressed.len(), 5);
}

#[test]
fn test_bytes_store_level_no_compression() {
    let data = vec![b'T'; 1000];
    let files = [("test.txt", data.as_slice())];

    let zip_store = compress_bytes(
        &files,
        None,
        EncryptionMethod::None,
        CompressionLevel::STORE,
    )
    .unwrap();

    let zip_best =
        compress_bytes(&files, None, EncryptionMethod::None, CompressionLevel::BEST).unwrap();

    // STORE should be larger than BEST for compressible data
    assert!(zip_store.len() > zip_best.len());
}
