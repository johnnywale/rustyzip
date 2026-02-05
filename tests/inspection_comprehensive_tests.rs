//! Comprehensive tests for the inspection module to achieve 95%+ coverage.
//!
//! This test suite covers:
//! - Bytes variant functions (list_archive_bytes, get_file_info_bytes, etc.)
//! - ArchiveIterator (all methods)
//! - CachedArchive (all methods and features)
//! - Error paths and edge cases

use rustyzip::compression::{
    compress_file, get_all_file_info_bytes, get_archive_info_bytes, get_file_info_bytes,
    has_file_bytes, iter_archive, iter_archive_bytes, list_archive_bytes, open_cached,
    ArchiveIterator, CachedArchive, CompressionLevel, EncryptionMethod,
};
use rustyzip::error::RustyZipError;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::TempDir;
use zip::write::{SimpleFileOptions, ZipWriter};

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_zip_bytes(files: Vec<(&str, &[u8])>) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut cursor);

    for (name, content) in files {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(content).unwrap();
    }

    zip.finish().unwrap();
    cursor.into_inner()
}

fn create_test_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

// ============================================================================
// Bytes Variant Tests
// ============================================================================

#[test]
fn test_list_archive_bytes_single_file() {
    let zip_bytes = create_test_zip_bytes(vec![("test.txt", b"Hello")]);
    let files = list_archive_bytes(&zip_bytes).unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0], "test.txt");
}

#[test]
fn test_list_archive_bytes_multiple_files() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("dir/file3.txt", b"Content 3"),
    ]);
    let files = list_archive_bytes(&zip_bytes).unwrap();

    assert_eq!(files.len(), 3);
    assert!(files.contains(&"file1.txt".to_string()));
    assert!(files.contains(&"file2.txt".to_string()));
    assert!(files.contains(&"dir/file3.txt".to_string()));
}

#[test]
fn test_list_archive_bytes_empty() {
    let zip_bytes = create_test_zip_bytes(vec![]);
    let files = list_archive_bytes(&zip_bytes).unwrap();

    assert_eq!(files.len(), 0);
}

#[test]
fn test_list_archive_bytes_corrupt() {
    let corrupt_bytes = b"This is not a ZIP file";
    let result = list_archive_bytes(corrupt_bytes);

    assert!(result.is_err());
}

#[test]
fn test_get_file_info_bytes_found() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("test.txt", b"Hello, World!"),
        ("other.txt", b"Other content"),
    ]);

    let info = get_file_info_bytes(&zip_bytes, "test.txt").unwrap();

    assert_eq!(info.name, "test.txt");
    assert_eq!(info.size, 13);
    assert!(!info.is_dir);
    assert!(!info.is_encrypted);
}

#[test]
fn test_get_file_info_bytes_not_found() {
    let zip_bytes = create_test_zip_bytes(vec![("test.txt", b"Hello")]);

    let result = get_file_info_bytes(&zip_bytes, "nonexistent.txt");

    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::FileNotFound(msg) => {
            assert!(msg.contains("not found in archive"));
        }
        e => panic!("Expected FileNotFound, got {:?}", e),
    }
}

#[test]
fn test_get_archive_info_bytes_basic() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content one"),
        ("file2.txt", b"Content two"),
    ]);

    let info = get_archive_info_bytes(&zip_bytes).unwrap();

    assert_eq!(info.total_entries, 2);
    assert_eq!(info.file_count, 2);
    assert_eq!(info.dir_count, 0);
    assert!(!info.has_encrypted_files);
    assert_eq!(info.encryption, EncryptionMethod::None);
}

#[test]
fn test_get_archive_info_bytes_empty() {
    let zip_bytes = create_test_zip_bytes(vec![]);

    let info = get_archive_info_bytes(&zip_bytes).unwrap();

    assert_eq!(info.total_entries, 0);
    assert_eq!(info.file_count, 0);
    assert_eq!(info.dir_count, 0);
}

#[test]
fn test_get_archive_info_bytes_with_dirs() {
    let mut cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut cursor);

    // Add a directory
    zip.add_directory("testdir/", SimpleFileOptions::default())
        .unwrap();
    zip.start_file("testdir/file.txt", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"content").unwrap();
    zip.finish().unwrap();

    let zip_bytes = cursor.into_inner();
    let info = get_archive_info_bytes(&zip_bytes).unwrap();

    assert_eq!(info.total_entries, 2);
    assert_eq!(info.file_count, 1);
    assert_eq!(info.dir_count, 1);
}

#[test]
fn test_get_all_file_info_bytes() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"First"),
        ("file2.txt", b"Second"),
        ("file3.txt", b"Third"),
    ]);

    let infos = get_all_file_info_bytes(&zip_bytes).unwrap();

    assert_eq!(infos.len(), 3);
    assert_eq!(infos[0].name, "file1.txt");
    assert_eq!(infos[1].name, "file2.txt");
    assert_eq!(infos[2].name, "file3.txt");
}

#[test]
fn test_has_file_bytes_exists() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("exists.txt", b"Content"),
        ("also_exists.txt", b"More content"),
    ]);

    assert!(has_file_bytes(&zip_bytes, "exists.txt").unwrap());
    assert!(has_file_bytes(&zip_bytes, "also_exists.txt").unwrap());
}

#[test]
fn test_has_file_bytes_not_exists() {
    let zip_bytes = create_test_zip_bytes(vec![("exists.txt", b"Content")]);

    assert!(!has_file_bytes(&zip_bytes, "nonexistent.txt").unwrap());
}

#[test]
fn test_has_file_bytes_empty_archive() {
    let zip_bytes = create_test_zip_bytes(vec![]);

    assert!(!has_file_bytes(&zip_bytes, "any.txt").unwrap());
}

// ============================================================================
// ArchiveIterator Tests
// ============================================================================

#[test]
fn test_archive_iterator_from_path() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = create_test_file(&tmp_dir.path(), "test.txt", "Test content");
    let zip_path = tmp_dir.path().join("test.zip");

    compress_file(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let iter = ArchiveIterator::from_path(&zip_path).unwrap();

    assert_eq!(iter.len(), 1);
    assert!(!iter.is_empty());
    assert_eq!(iter.remaining(), 1);
}

#[test]
fn test_archive_iterator_from_path_nonexistent() {
    let result = ArchiveIterator::from_path(Path::new("/nonexistent/file.zip"));

    assert!(result.is_err());
    if let Err(e) = result {
        match e {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound, got {:?}", e),
        }
    }
}

#[test]
fn test_archive_iterator_from_reader() {
    let zip_bytes = create_test_zip_bytes(vec![("file.txt", b"Content")]);
    let cursor = Cursor::new(zip_bytes);

    let iter = ArchiveIterator::from_reader(cursor).unwrap();

    assert_eq!(iter.len(), 1);
    assert!(!iter.is_empty());
}

#[test]
fn test_archive_iterator_next() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    assert_eq!(iter.len(), 2);
    assert_eq!(iter.remaining(), 2);

    let info1 = iter.next().unwrap().unwrap();
    assert_eq!(info1.name, "file1.txt");
    assert_eq!(iter.remaining(), 1);

    let info2 = iter.next().unwrap().unwrap();
    assert_eq!(info2.name, "file2.txt");
    assert_eq!(iter.remaining(), 0);

    assert!(iter.next().is_none());
}

#[test]
fn test_archive_iterator_size_hint() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 3"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    assert_eq!(iter.size_hint(), (3, Some(3)));

    iter.next();
    assert_eq!(iter.size_hint(), (2, Some(2)));

    iter.next();
    assert_eq!(iter.size_hint(), (1, Some(1)));

    iter.next();
    assert_eq!(iter.size_hint(), (0, Some(0)));
}

#[test]
fn test_archive_iterator_count() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 3"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let iter = ArchiveIterator::from_reader(cursor).unwrap();
    let count = iter.count();

    assert_eq!(count, 3);
}

#[test]
fn test_archive_iterator_is_empty() {
    let empty_bytes = create_test_zip_bytes(vec![]);
    let cursor = Cursor::new(empty_bytes);

    let iter = ArchiveIterator::from_reader(cursor).unwrap();

    assert!(iter.is_empty());
    assert_eq!(iter.len(), 0);
}

#[test]
fn test_archive_iterator_skip_entries() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 3"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    assert_eq!(iter.remaining(), 3);

    iter.skip_entries(1);
    assert_eq!(iter.remaining(), 2);

    let info = iter.next().unwrap().unwrap();
    assert_eq!(info.name, "file2.txt"); // Should get second file

    iter.skip_entries(10); // Skip more than available
    assert_eq!(iter.remaining(), 0);
    assert!(iter.next().is_none());
}

#[test]
fn test_archive_iterator_reset() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    // Consume one item
    iter.next().unwrap();
    assert_eq!(iter.remaining(), 1);

    // Reset
    iter.reset();
    assert_eq!(iter.remaining(), 2);

    // Should start from beginning again
    let info = iter.next().unwrap().unwrap();
    assert_eq!(info.name, "file1.txt");
}

#[test]
fn test_iter_archive_convenience() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = create_test_file(&tmp_dir.path(), "test.txt", "Content");
    let zip_path = tmp_dir.path().join("test.zip");

    compress_file(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let mut iter = iter_archive(&zip_path).unwrap();
    let info = iter.next().unwrap().unwrap();

    assert_eq!(info.name, "test.txt");
}

#[test]
fn test_iter_archive_bytes_convenience() {
    let zip_bytes = create_test_zip_bytes(vec![("file.txt", b"Content")]);

    let mut iter = iter_archive_bytes(&zip_bytes).unwrap();
    let info = iter.next().unwrap().unwrap();

    assert_eq!(info.name, "file.txt");
}

#[test]
fn test_archive_iterator_filter_map() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("small.txt", b"Hi"),
        ("large.txt", b"This is a longer content string"),
        ("medium.txt", b"Medium size"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let iter = ArchiveIterator::from_reader(cursor).unwrap();
    let large_files: Vec<_> = iter
        .filter_map(|r| r.ok())
        .filter(|info| info.size > 10)
        .collect();

    assert_eq!(large_files.len(), 2);
}

// ============================================================================
// CachedArchive Tests
// ============================================================================

#[test]
fn test_cached_archive_open() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = create_test_file(&tmp_dir.path(), "test.txt", "Test content");
    let zip_path = tmp_dir.path().join("test.zip");

    compress_file(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let cached = CachedArchive::open(&zip_path).unwrap();

    assert_eq!(cached.len(), 1);
    assert!(!cached.is_empty());
}

#[test]
fn test_cached_archive_open_nonexistent() {
    let result = CachedArchive::open(Path::new("/nonexistent/file.zip"));

    assert!(result.is_err());
    if let Err(e) = result {
        match e {
            RustyZipError::FileNotFound(_) => {}
            e => panic!("Expected FileNotFound, got {:?}", e),
        }
    }
}

#[test]
fn test_cached_archive_from_bytes() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    assert_eq!(cached.len(), 2);
    assert!(!cached.is_empty());
}

#[test]
fn test_cached_archive_get_by_index() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let info0 = cached.get_by_index(0).unwrap();
    assert_eq!(info0.name, "file1.txt");

    let info1 = cached.get_by_index(1).unwrap();
    assert_eq!(info1.name, "file2.txt");

    assert!(cached.get_by_index(2).is_none());
}

#[test]
fn test_cached_archive_get() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let info = cached.get("file1.txt").unwrap();
    assert_eq!(info.name, "file1.txt");
    assert_eq!(info.size, 9); // "Content 1" is 9 bytes

    assert!(cached.get("nonexistent.txt").is_none());
}

#[test]
fn test_cached_archive_contains() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("exists.txt", b"Content"),
        ("also_exists.txt", b"More"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    assert!(cached.contains("exists.txt"));
    assert!(cached.contains("also_exists.txt"));
    assert!(!cached.contains("nonexistent.txt"));
}

#[test]
fn test_cached_archive_file_names() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 3"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let names: Vec<&str> = cached.file_names().collect();

    assert_eq!(names.len(), 3);
    assert!(names.contains(&"file1.txt"));
    assert!(names.contains(&"file2.txt"));
    assert!(names.contains(&"file3.txt"));
}

#[test]
fn test_cached_archive_iter() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let infos: Vec<_> = cached.iter().collect();

    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].name, "file1.txt");
    assert_eq!(infos[1].name, "file2.txt");
}

#[test]
fn test_cached_archive_archive_info() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();
    let archive_info = cached.archive_info();

    assert_eq!(archive_info.total_entries, 2);
    assert_eq!(archive_info.file_count, 2);
    assert!(!archive_info.has_encrypted_files);
}

#[test]
fn test_cached_archive_find() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file1.rs", b"Rust code"),
        ("file2.rs", b"More Rust"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let txt_files = cached.find("*.txt").unwrap();
    assert_eq!(txt_files.len(), 2);

    let rs_files = cached.find("*.rs").unwrap();
    assert_eq!(rs_files.len(), 2);

    let file1_any = cached.find("file1.*").unwrap();
    assert_eq!(file1_any.len(), 2);
}

#[test]
fn test_cached_archive_find_invalid_pattern() {
    let zip_bytes = create_test_zip_bytes(vec![("file.txt", b"Content")]);
    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let result = cached.find("[");

    assert!(result.is_err());
}

#[test]
fn test_cached_archive_files_larger_than() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("small.txt", b"Hi"),
        ("large.txt", b"This is much longer content"),
        ("medium.txt", b"Medium size text"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let large_files: Vec<_> = cached.files_larger_than(10).collect();

    assert_eq!(large_files.len(), 2);
    assert!(large_files.iter().all(|f| f.size > 10));
}

#[test]
fn test_cached_archive_files_with_extension() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.TXT", b"Content 2"), // Different case
        ("file3.rs", b"Rust code"),
        ("file4.txt", b"Content 4"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let txt_files: Vec<_> = cached.files_with_extension("txt").collect();

    assert_eq!(txt_files.len(), 3); // Should match case-insensitively

    let rs_files: Vec<_> = cached.files_with_extension("rs").collect();
    assert_eq!(rs_files.len(), 1);
}

#[test]
fn test_cached_archive_files_with_extension_no_match() {
    let zip_bytes = create_test_zip_bytes(vec![("file.txt", b"Content")]);
    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    let md_files: Vec<_> = cached.files_with_extension("md").collect();

    assert_eq!(md_files.len(), 0);
}

#[test]
fn test_open_cached_convenience() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = create_test_file(&tmp_dir.path(), "test.txt", "Content");
    let zip_path = tmp_dir.path().join("test.zip");

    compress_file(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let cached = open_cached(&zip_path).unwrap();

    assert_eq!(cached.len(), 1);
}

// ============================================================================
// Edge Cases and Error Paths
// ============================================================================

#[test]
fn test_bytes_variant_with_encrypted_archive() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = create_test_file(&tmp_dir.path(), "test.txt", "Secret content");
    let zip_path = tmp_dir.path().join("encrypted.zip");

    compress_file(
        &file_path,
        &zip_path,
        Some("password"),
        EncryptionMethod::Aes256,
        CompressionLevel::DEFAULT,
    )
    .unwrap();

    let zip_bytes = fs::read(&zip_path).unwrap();
    let info = get_archive_info_bytes(&zip_bytes).unwrap();

    assert!(info.has_encrypted_files);
    assert_eq!(info.encryption, EncryptionMethod::Aes256);
}

#[test]
fn test_cached_archive_empty() {
    let zip_bytes = create_test_zip_bytes(vec![]);
    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    assert!(cached.is_empty());
    assert_eq!(cached.len(), 0);
    assert!(cached.get("anything").is_none());

    let names: Vec<_> = cached.file_names().collect();
    assert_eq!(names.len(), 0);
}

#[test]
fn test_archive_iterator_exhaustion() {
    let zip_bytes = create_test_zip_bytes(vec![("file.txt", b"Content")]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    // Exhaust iterator
    iter.next();
    assert!(iter.next().is_none());
    assert!(iter.next().is_none()); // Multiple calls should be safe
}

#[test]
fn test_get_all_file_info_bytes_empty() {
    let zip_bytes = create_test_zip_bytes(vec![]);
    let infos = get_all_file_info_bytes(&zip_bytes).unwrap();

    assert_eq!(infos.len(), 0);
}

#[test]
fn test_archive_info_compression_ratio() {
    let tmp_dir = TempDir::new().unwrap();

    // Create a file with compressible content
    let content = "A".repeat(10000);
    let file_path = create_test_file(&tmp_dir.path(), "compressible.txt", &content);
    let zip_path = tmp_dir.path().join("test.zip");

    compress_file(
        &file_path,
        &zip_path,
        None,
        EncryptionMethod::None,
        CompressionLevel::BEST,
    )
    .unwrap();

    let zip_bytes = fs::read(&zip_path).unwrap();
    let info = get_archive_info_bytes(&zip_bytes).unwrap();

    let ratio = info.compression_ratio();
    assert!(ratio > 10.0); // Should be highly compressed
}

#[test]
fn test_file_info_compression_ratio_directory() {
    let mut cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut cursor);

    zip.add_directory("testdir/", SimpleFileOptions::default())
        .unwrap();
    zip.finish().unwrap();

    let zip_bytes = cursor.into_inner();
    let infos = get_all_file_info_bytes(&zip_bytes).unwrap();

    assert_eq!(infos.len(), 1);
    let dir_info = &infos[0];
    assert!(dir_info.is_dir);
    assert_eq!(dir_info.compression_ratio(), 1.0); // Directories return 1.0
}

#[test]
fn test_cached_archive_multiple_access() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
    ]);

    let cached = CachedArchive::from_bytes(&zip_bytes).unwrap();

    // Access same file multiple times - should use cache
    let info1 = cached.get("file1.txt").unwrap();
    let info2 = cached.get("file1.txt").unwrap();

    assert_eq!(info1.name, info2.name);
    assert_eq!(info1.size, info2.size);
}

#[test]
fn test_archive_iterator_exact_size_iterator() {
    let zip_bytes = create_test_zip_bytes(vec![
        ("file1.txt", b"Content 1"),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 3"),
    ]);
    let cursor = Cursor::new(zip_bytes);

    let mut iter = ArchiveIterator::from_reader(cursor).unwrap();

    // ExactSizeIterator trait should provide accurate len() which is total_entries
    assert_eq!(iter.len(), 3);

    iter.next();
    // len() returns total entries, not remaining (that's what remaining() is for)
    assert_eq!(iter.len(), 3);
    assert_eq!(iter.remaining(), 2);

    iter.next();
    assert_eq!(iter.len(), 3);
    assert_eq!(iter.remaining(), 1);

    iter.next();
    assert_eq!(iter.len(), 3);
    assert_eq!(iter.remaining(), 0);
}
