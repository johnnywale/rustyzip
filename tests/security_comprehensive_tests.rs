//! Comprehensive tests for the security module to achieve 95%+ coverage.
//!
//! This test suite covers:
//! - Password struct operations
//! - SecurityPolicy builder methods
//! - Path validation (traversal, absolute paths, special characters)
//! - File inclusion/exclusion patterns
//! - Archive validation (ZIP bombs, symlinks, malicious paths)
//! - Edge cases and error paths

use rustyzip::compression::{
    should_include_file, validate_archive, validate_archive_bytes, validate_archive_entry_name,
    validate_output_path, Password, SecurityPolicy, ValidationIssue, ValidationReport,
    ValidationSeverity, DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION, DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_DECOMPRESSED_SIZE,
};
use rustyzip::error::RustyZipError;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;
use zip::write::{SimpleFileOptions, ZipWriter};

// ============================================================================
// Password Struct Tests
// ============================================================================

#[test]
fn test_password_new() {
    let pwd = Password::new("secret123");
    assert_eq!(pwd.as_str(), "secret123");
}

#[test]
fn test_password_from_string() {
    let pwd = Password::from("hello".to_string());
    assert_eq!(pwd.as_str(), "hello");
}

#[test]
fn test_password_from_str() {
    let pwd: Password = "test_password".into();
    assert_eq!(pwd.as_str(), "test_password");
}

#[test]
fn test_password_special_characters() {
    let pwd = Password::new("p@ssw0rd!#$%^&*()");
    assert_eq!(pwd.as_str(), "p@ssw0rd!#$%^&*()");
    assert_eq!(pwd.as_bytes(), b"p@ssw0rd!#$%^&*()");
}

#[test]
fn test_password_empty() {
    let pwd = Password::new("");
    assert_eq!(pwd.as_str(), "");
}

#[test]
fn test_password_unicode() {
    let pwd = Password::new("пароль🔒");
    assert_eq!(pwd.as_str(), "пароль🔒");
}

// ============================================================================
// SecurityPolicy Builder Tests
// ============================================================================

#[test]
fn test_security_policy_default() {
    let policy = SecurityPolicy::default();
    assert_eq!(policy.max_decompressed_size, DEFAULT_MAX_DECOMPRESSED_SIZE);
    assert_eq!(policy.max_compression_ratio, DEFAULT_MAX_COMPRESSION_RATIO);
    assert!(!policy.allow_symlinks);
    assert!(policy.sandbox_root.is_none());
    assert_eq!(
        policy.max_archive_size_for_modification,
        DEFAULT_MAX_ARCHIVE_SIZE_FOR_MODIFICATION
    );
    assert!(!policy.allow_symlinks_in_input);
}

#[test]
fn test_security_policy_new() {
    let policy = SecurityPolicy::new();
    assert_eq!(policy.max_decompressed_size, DEFAULT_MAX_DECOMPRESSED_SIZE);
    assert_eq!(policy.max_compression_ratio, DEFAULT_MAX_COMPRESSION_RATIO);
}

#[test]
fn test_security_policy_permissive() {
    let policy = SecurityPolicy::permissive();
    assert_eq!(policy.max_decompressed_size, 0);
    assert_eq!(policy.max_compression_ratio, 0);
    assert!(policy.allow_symlinks);
    assert!(policy.allow_symlinks_in_input);
    assert_eq!(policy.max_archive_size_for_modification, 0);
}

#[test]
fn test_security_policy_with_max_size() {
    let policy = SecurityPolicy::new().with_max_size(1_000_000);
    assert_eq!(policy.max_decompressed_size, 1_000_000);
}

#[test]
fn test_security_policy_with_max_size_zero() {
    let policy = SecurityPolicy::new().with_max_size(0);
    assert_eq!(policy.max_decompressed_size, 0);
    assert!(!policy.size_limit_enabled());
}

#[test]
fn test_security_policy_with_max_ratio() {
    let policy = SecurityPolicy::new().with_max_ratio(1000);
    assert_eq!(policy.max_compression_ratio, 1000);
}

#[test]
fn test_security_policy_with_max_ratio_zero() {
    let policy = SecurityPolicy::new().with_max_ratio(0);
    assert_eq!(policy.max_compression_ratio, 0);
    assert!(!policy.ratio_limit_enabled());
}

#[test]
fn test_security_policy_with_allow_symlinks() {
    let policy = SecurityPolicy::new().with_allow_symlinks(true);
    assert!(policy.allow_symlinks);
}

#[test]
fn test_security_policy_with_sandbox_root() {
    let path = PathBuf::from("/safe/directory");
    let policy = SecurityPolicy::new().with_sandbox_root(Some(path.clone()));
    assert_eq!(policy.sandbox_root, Some(path));
}

#[test]
fn test_security_policy_with_sandbox_root_none() {
    let policy = SecurityPolicy::new().with_sandbox_root(None);
    assert!(policy.sandbox_root.is_none());
}

#[test]
fn test_security_policy_with_max_modification_size() {
    let policy = SecurityPolicy::new().with_max_modification_size(50_000_000);
    assert_eq!(policy.max_archive_size_for_modification, 50_000_000);
}

#[test]
fn test_security_policy_with_allow_symlinks_in_input() {
    let policy = SecurityPolicy::new().with_allow_symlinks_in_input(true);
    assert!(policy.allow_symlinks_in_input);
}

#[test]
fn test_security_policy_size_limit_enabled() {
    let policy = SecurityPolicy::new();
    assert!(policy.size_limit_enabled());

    let disabled = SecurityPolicy::new().with_max_size(0);
    assert!(!disabled.size_limit_enabled());
}

#[test]
fn test_security_policy_ratio_limit_enabled() {
    let policy = SecurityPolicy::new();
    assert!(policy.ratio_limit_enabled());

    let disabled = SecurityPolicy::new().with_max_ratio(0);
    assert!(!disabled.ratio_limit_enabled());
}

#[test]
fn test_security_policy_modification_size_limit_enabled() {
    let policy = SecurityPolicy::new();
    assert!(policy.modification_size_limit_enabled());

    let disabled = SecurityPolicy::new().with_max_modification_size(0);
    assert!(!disabled.modification_size_limit_enabled());
}

#[test]
fn test_security_policy_builder_chaining() {
    let policy = SecurityPolicy::new()
        .with_max_size(4_000_000_000)
        .with_max_ratio(1000)
        .with_allow_symlinks(true)
        .with_sandbox_root(Some(PathBuf::from("/tmp")))
        .with_max_modification_size(200_000_000)
        .with_allow_symlinks_in_input(false);

    assert_eq!(policy.max_decompressed_size, 4_000_000_000);
    assert_eq!(policy.max_compression_ratio, 1000);
    assert!(policy.allow_symlinks);
    assert_eq!(policy.sandbox_root, Some(PathBuf::from("/tmp")));
    assert_eq!(policy.max_archive_size_for_modification, 200_000_000);
    assert!(!policy.allow_symlinks_in_input);
}

// ============================================================================
// Path Validation Tests (validate_archive_entry_name)
// ============================================================================

#[test]
fn test_validate_entry_name_valid_simple() {
    assert!(validate_archive_entry_name("file.txt").is_ok());
}

#[test]
fn test_validate_entry_name_valid_subdir() {
    assert!(validate_archive_entry_name("subdir/file.txt").is_ok());
}

#[test]
fn test_validate_entry_name_valid_deep_path() {
    assert!(validate_archive_entry_name("a/b/c/d/file.txt").is_ok());
}

#[test]
fn test_validate_entry_name_empty() {
    let result = validate_archive_entry_name("");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_null_byte() {
    let result = validate_archive_entry_name("file\0.txt");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_control_characters() {
    // Test newline
    let result = validate_archive_entry_name("file\nname.txt");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));

    // Test tab
    let result = validate_archive_entry_name("file\tname.txt");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));

    // Test carriage return
    let result = validate_archive_entry_name("file\rname.txt");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
}

#[test]
fn test_validate_entry_name_windows_reserved_chars() {
    for &ch in &['<', '>', ':', '"', '|', '?', '*'] {
        let name = format!("file{}name.txt", ch);
        let result = validate_archive_entry_name(&name);
        assert!(result.is_err(), "Should reject '{}'", ch);
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));
    }
}

#[test]
fn test_validate_entry_name_absolute_unix() {
    let result = validate_archive_entry_name("/etc/passwd");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_absolute_windows_backslash() {
    let result = validate_archive_entry_name("\\Windows\\System32");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_absolute_windows_drive() {
    let result = validate_archive_entry_name("C:\\Windows\\System32");
    assert!(result.is_err());
    match result.unwrap_err() {
        RustyZipError::PathTraversal(_) => {}
        RustyZipError::InvalidPath(_) => {} // Also acceptable for Windows reserved chars
        e => panic!("Unexpected error type: {:?}", e),
    }

    let result2 = validate_archive_entry_name("D:\\data\\file.txt");
    assert!(result2.is_err());
    match result2.unwrap_err() {
        RustyZipError::PathTraversal(_) => {}
        RustyZipError::InvalidPath(_) => {} // Also acceptable for Windows reserved chars
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn test_validate_entry_name_parent_dir_simple() {
    let result = validate_archive_entry_name("../etc/passwd");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_parent_dir_nested() {
    let result = validate_archive_entry_name("dir/../../../etc/passwd");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_parent_dir_windows() {
    let result = validate_archive_entry_name("dir\\..\\..\\file.txt");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_entry_name_windows_reserved_names() {
    let reserved = vec![
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for name in reserved {
        // Test with various case variations
        let result = validate_archive_entry_name(name);
        assert!(result.is_err(), "Should reject '{}'", name);
        assert!(matches!(result.unwrap_err(), RustyZipError::InvalidPath(_)));

        let result = validate_archive_entry_name(&name.to_lowercase());
        assert!(result.is_err(), "Should reject '{}'", name.to_lowercase());

        // Test with extension
        let with_ext = format!("{}.txt", name);
        let result = validate_archive_entry_name(&with_ext);
        assert!(result.is_err(), "Should reject '{}'", with_ext);

        // Test in subdirectory
        let in_dir = format!("dir/{}", name);
        let result = validate_archive_entry_name(&in_dir);
        assert!(result.is_err(), "Should reject '{}'", in_dir);
    }
}

// ============================================================================
// File Inclusion Tests (should_include_file)
// ============================================================================

#[test]
fn test_should_include_no_patterns() {
    let path = std::path::Path::new("/tmp/test.txt");
    assert!(should_include_file(path, "test.txt", None, None));
}

#[test]
fn test_should_include_with_include_pattern_matching() {
    use glob::Pattern;
    let patterns = vec![Pattern::new("*.txt").unwrap()];
    let path = std::path::Path::new("/tmp/file.txt");
    assert!(should_include_file(path, "file.txt", Some(&patterns), None));
}

#[test]
fn test_should_include_with_include_pattern_not_matching() {
    use glob::Pattern;
    let patterns = vec![Pattern::new("*.txt").unwrap()];
    let path = std::path::Path::new("/tmp/file.rs");
    assert!(!should_include_file(path, "file.rs", Some(&patterns), None));
}

#[test]
fn test_should_include_with_exclude_pattern_matching() {
    use glob::Pattern;
    let patterns = vec![Pattern::new("*.log").unwrap()];
    let path = std::path::Path::new("/tmp/test.log");
    assert!(!should_include_file(
        path,
        "test.log",
        None,
        Some(&patterns)
    ));
}

#[test]
fn test_should_include_with_exclude_pattern_not_matching() {
    use glob::Pattern;
    let patterns = vec![Pattern::new("*.log").unwrap()];
    let path = std::path::Path::new("/tmp/test.txt");
    assert!(should_include_file(path, "test.txt", None, Some(&patterns)));
}

#[test]
fn test_should_include_multiple_patterns() {
    use glob::Pattern;
    let include = vec![
        Pattern::new("*.txt").unwrap(),
        Pattern::new("*.md").unwrap(),
    ];
    let path = std::path::Path::new("/tmp/README.md");
    assert!(should_include_file(path, "README.md", Some(&include), None));
}

#[test]
fn test_should_include_exclude_directory() {
    use glob::Pattern;
    let exclude = vec![Pattern::new("node_modules").unwrap()];
    let path = std::path::Path::new("/tmp/node_modules/package.json");
    assert!(!should_include_file(
        path,
        "node_modules/package.json",
        None,
        Some(&exclude)
    ));
}

#[test]
fn test_should_include_relative_path_matching() {
    use glob::Pattern;
    let include = vec![Pattern::new("src/*.rs").unwrap()];
    let path = std::path::Path::new("/project/src/main.rs");
    assert!(should_include_file(
        path,
        "src/main.rs",
        Some(&include),
        None
    ));
}

// ============================================================================
// Archive Validation Tests
// ============================================================================

fn create_test_zip(tmp_dir: &TempDir, name: &str, files: Vec<(&str, Vec<u8>)>) -> PathBuf {
    let zip_path = tmp_dir.path().join(name);
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = ZipWriter::new(file);

    for (file_name, content) in files {
        zip.start_file(file_name, SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&content).unwrap();
    }

    zip.finish().unwrap();
    zip_path
}

#[test]
fn test_validate_archive_normal() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = create_test_zip(
        &tmp_dir,
        "normal.zip",
        vec![("file.txt", b"Hello, world!".to_vec())],
    );

    let policy = SecurityPolicy::default();
    let report = validate_archive(&zip_path, &policy).unwrap();

    assert!(report.is_safe());
    assert_eq!(report.total_files, 1);
    assert!(!report.has_encrypted_files);
    assert!(!report.has_symlinks);
}

#[test]
fn test_validate_archive_bytes_variant() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = create_test_zip(
        &tmp_dir,
        "test.zip",
        vec![("file.txt", b"Content".to_vec())],
    );

    let bytes = fs::read(&zip_path).unwrap();
    let policy = SecurityPolicy::default();
    let report = validate_archive_bytes(&bytes, &policy).unwrap();

    assert!(report.is_safe());
    assert_eq!(report.total_files, 1);
}

#[test]
fn test_validate_archive_oversized_total() {
    let tmp_dir = TempDir::new().unwrap();

    // Create a file with large content (3GB uncompressed)
    let large_data = vec![0u8; 3_000_000_000];
    let zip_path = create_test_zip(&tmp_dir, "large.zip", vec![("big.bin", large_data)]);

    let policy = SecurityPolicy::default(); // 2GB limit
    let report = validate_archive(&zip_path, &policy).unwrap();

    assert!(!report.is_safe());
    assert!(report.errors().count() > 0);
}

#[test]
fn test_validate_archive_high_compression_ratio() {
    let tmp_dir = TempDir::new().unwrap();

    // Create highly compressible data (repeated pattern)
    let repeated_data = vec![b'A'; 100_000_000]; // 100MB of 'A's
    let zip_path = create_test_zip(
        &tmp_dir,
        "compressed.zip",
        vec![("repeated.txt", repeated_data)],
    );

    // Use a very restrictive policy
    let policy = SecurityPolicy::new().with_max_ratio(10); // Only 10x allowed
    let report = validate_archive(&zip_path, &policy).unwrap();

    // This should trigger a compression ratio warning
    assert!(!report.is_safe() || report.has_warnings());
}

#[test]
fn test_validate_archive_path_traversal_in_name() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = tmp_dir.path().join("malicious.zip");
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = ZipWriter::new(file);

    // Try to add a file with path traversal (Note: zip crate may sanitize, but we test validation)
    zip.start_file("../../../etc/passwd", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"malicious").unwrap();
    zip.finish().unwrap();

    let policy = SecurityPolicy::default();
    let report = validate_archive(&zip_path, &policy).unwrap();

    // Should detect the path traversal attempt
    assert!(!report.is_safe());
    assert!(report.errors().count() > 0);
}

#[test]
fn test_validate_archive_nonexistent_file() {
    let policy = SecurityPolicy::default();
    let result = validate_archive(std::path::Path::new("/nonexistent/file.zip"), &policy);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::FileNotFound(_)
    ));
}

#[test]
fn test_validate_archive_corrupt_zip() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = tmp_dir.path().join("corrupt.zip");

    // Write invalid ZIP data
    fs::write(&zip_path, b"This is not a ZIP file").unwrap();

    let policy = SecurityPolicy::default();
    let result = validate_archive(&zip_path, &policy);

    assert!(result.is_err());
}

#[test]
fn test_validation_report_new() {
    let report = ValidationReport::new();
    assert_eq!(report.total_files, 0);
    assert_eq!(report.total_uncompressed_size, 0);
    assert_eq!(report.total_compressed_size, 0);
    assert!(!report.has_encrypted_files);
    assert!(!report.has_symlinks);
    assert_eq!(report.max_compression_ratio, 0.0);
    assert!(report.is_safe());
}

#[test]
fn test_validation_report_add_error() {
    let mut report = ValidationReport::new();
    report.add_error("Test error");

    assert!(!report.is_safe());
    assert_eq!(report.errors().count(), 1);
}

#[test]
fn test_validation_report_add_warning() {
    let mut report = ValidationReport::new();
    report.add_warning("Test warning");

    assert!(report.is_safe()); // Warnings don't make it unsafe
    assert!(report.has_warnings());
    assert_eq!(report.warnings().count(), 1);
}

#[test]
fn test_validation_report_add_info() {
    let mut report = ValidationReport::new();
    report.add_info("Test info");

    assert!(report.is_safe());
    assert!(!report.has_warnings());
}

#[test]
fn test_validation_report_overall_compression_ratio() {
    let mut report = ValidationReport::new();
    report.total_uncompressed_size = 1000;
    report.total_compressed_size = 100;

    assert_eq!(report.overall_compression_ratio(), 10.0);
}

#[test]
fn test_validation_report_overall_compression_ratio_zero() {
    let report = ValidationReport::new();
    assert_eq!(report.overall_compression_ratio(), 1.0);
}

#[test]
fn test_validation_issue_new() {
    let issue = ValidationIssue::new(ValidationSeverity::Error, "Test message");
    assert_eq!(issue.severity, ValidationSeverity::Error);
    assert_eq!(issue.message, "Test message");
    assert!(issue.file_name.is_none());
}

#[test]
fn test_validation_issue_for_file() {
    let issue = ValidationIssue::for_file(ValidationSeverity::Warning, "File issue", "test.txt");
    assert_eq!(issue.severity, ValidationSeverity::Warning);
    assert_eq!(issue.message, "File issue");
    assert_eq!(issue.file_name, Some("test.txt".to_string()));
}

#[test]
fn test_validation_severity_ordering() {
    assert!(ValidationSeverity::Info < ValidationSeverity::Warning);
    assert!(ValidationSeverity::Warning < ValidationSeverity::Error);
}

// ============================================================================
// validate_output_path Tests
// ============================================================================

#[test]
fn test_validate_output_path_valid_relative() {
    let tmp_dir = TempDir::new().unwrap();
    let base = tmp_dir.path();
    let target = std::path::Path::new("subdir/file.txt");

    assert!(validate_output_path(base, target).is_ok());
}

#[test]
fn test_validate_output_path_parent_dir() {
    let tmp_dir = TempDir::new().unwrap();
    let base = tmp_dir.path();
    let target = std::path::Path::new("../outside.txt");

    let result = validate_output_path(base, target);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RustyZipError::PathTraversal(_)
    ));
}

#[test]
fn test_validate_output_path_null_byte() {
    let tmp_dir = TempDir::new().unwrap();
    let _base = tmp_dir.path();

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let bytes = b"file\0name";
        let os_str = OsStr::from_bytes(bytes);
        let target = std::path::Path::new(os_str);

        let result = validate_output_path(_base, target);
        assert!(result.is_err());
    }
}

#[test]
#[cfg(windows)]
fn test_validate_output_path_windows_reserved() {
    let tmp_dir = TempDir::new().unwrap();
    let base = tmp_dir.path();
    let target = std::path::Path::new("CON");

    let result = validate_output_path(base, target);
    assert!(result.is_err());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_security_policy_all_limits_disabled() {
    let policy = SecurityPolicy::new()
        .with_max_size(0)
        .with_max_ratio(0)
        .with_max_modification_size(0);

    assert!(!policy.size_limit_enabled());
    assert!(!policy.ratio_limit_enabled());
    assert!(!policy.modification_size_limit_enabled());
}

#[test]
fn test_security_policy_very_restrictive() {
    let policy = SecurityPolicy::new()
        .with_max_size(1024) // 1KB
        .with_max_ratio(2) // 2x
        .with_allow_symlinks(false)
        .with_max_modification_size(1024);

    assert_eq!(policy.max_decompressed_size, 1024);
    assert_eq!(policy.max_compression_ratio, 2);
}

#[test]
fn test_validate_empty_archive() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = create_test_zip(&tmp_dir, "empty.zip", vec![]);

    let policy = SecurityPolicy::default();
    let report = validate_archive(&zip_path, &policy).unwrap();

    assert!(report.is_safe());
    assert_eq!(report.total_files, 0);
    assert_eq!(report.total_uncompressed_size, 0);
}

#[test]
fn test_validate_archive_with_many_files() {
    let tmp_dir = TempDir::new().unwrap();
    let zip_path = tmp_dir.path().join("many.zip");
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = ZipWriter::new(file);

    for i in 0..100 {
        zip.start_file(format!("file{}.txt", i), SimpleFileOptions::default())
            .unwrap();
        zip.write_all(format!("Content {}", i).as_bytes()).unwrap();
    }
    zip.finish().unwrap();

    let policy = SecurityPolicy::default();
    let report = validate_archive(&zip_path, &policy).unwrap();

    assert!(report.is_safe());
    assert_eq!(report.total_files, 100);
}

#[test]
fn test_password_as_bytes() {
    let pwd = Password::new("test123");
    assert_eq!(pwd.as_bytes(), b"test123");
}

#[test]
fn test_validate_entry_name_valid_with_dots() {
    // Single dot is not parent directory
    assert!(validate_archive_entry_name("file.name.txt").is_ok());
    assert!(validate_archive_entry_name(".hidden").is_ok());
    assert!(validate_archive_entry_name("dir/.hidden").is_ok());
}
