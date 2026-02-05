//! Integration tests for type definitions and conversions
//! These tests focus on achieving 100% coverage of types.rs

use rustyzip::compression::{CompressionLevel, EncryptionMethod};

// ============================================================================
// CompressionLevel Tests
// ============================================================================

#[test]
fn test_compression_level_constants() {
    assert_eq!(CompressionLevel::STORE.0, 0);
    assert_eq!(CompressionLevel::FAST.0, 1);
    assert_eq!(CompressionLevel::DEFAULT.0, 6);
    assert_eq!(CompressionLevel::BEST.0, 9);
}

#[test]
fn test_compression_level_new_valid() {
    assert_eq!(CompressionLevel::new(0).0, 0);
    assert_eq!(CompressionLevel::new(1).0, 1);
    assert_eq!(CompressionLevel::new(6).0, 6);
    assert_eq!(CompressionLevel::new(9).0, 9);
}

#[test]
fn test_compression_level_new_clamping() {
    // Values > 9 are clamped to 9
    assert_eq!(CompressionLevel::new(10).0, 9);
    assert_eq!(CompressionLevel::new(100).0, 9);
    assert_eq!(CompressionLevel::new(255).0, 9);
}

#[test]
fn test_compression_level_default() {
    let default = CompressionLevel::default();
    assert_eq!(default.0, 6);
}

#[test]
fn test_compression_level_clone() {
    let level = CompressionLevel::DEFAULT;
    let cloned = level;
    assert_eq!(level.0, cloned.0);
}

#[test]
fn test_compression_level_debug() {
    let level = CompressionLevel::DEFAULT;
    let debug_str = format!("{:?}", level);
    assert!(debug_str.contains("6"));
}

#[test]
fn test_compression_level_to_flate2() {
    let level = CompressionLevel::DEFAULT;
    let flate2_level = level.to_flate2_compression();
    // Just verify it returns something
    let _ = flate2_level;
}

// ============================================================================
// EncryptionMethod Tests
// ============================================================================

#[test]
fn test_encryption_method_from_str_none() {
    assert_eq!(
        EncryptionMethod::from_str("none").unwrap(),
        EncryptionMethod::None
    );
    assert_eq!(
        EncryptionMethod::from_str("").unwrap(),
        EncryptionMethod::None
    );
}

#[test]
fn test_encryption_method_from_str_zipcrypto() {
    assert_eq!(
        EncryptionMethod::from_str("zipcrypto").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::from_str("zip_crypto").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::from_str("legacy").unwrap(),
        EncryptionMethod::ZipCrypto
    );
}

#[test]
fn test_encryption_method_from_str_aes256() {
    assert_eq!(
        EncryptionMethod::from_str("aes256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::from_str("aes").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::from_str("aes-256").unwrap(),
        EncryptionMethod::Aes256
    );
}

#[test]
fn test_encryption_method_from_str_case_insensitive() {
    assert_eq!(
        EncryptionMethod::from_str("AES256").unwrap(),
        EncryptionMethod::Aes256
    );
    assert_eq!(
        EncryptionMethod::from_str("ZIPCRYPTO").unwrap(),
        EncryptionMethod::ZipCrypto
    );
    assert_eq!(
        EncryptionMethod::from_str("NONE").unwrap(),
        EncryptionMethod::None
    );
}

#[test]
fn test_encryption_method_from_str_invalid() {
    assert!(EncryptionMethod::from_str("invalid").is_err());
    assert!(EncryptionMethod::from_str("aes128").is_err());
    assert!(EncryptionMethod::from_str("des").is_err());
}

#[test]
fn test_encryption_method_equality() {
    assert_eq!(EncryptionMethod::None, EncryptionMethod::None);
    assert_eq!(EncryptionMethod::ZipCrypto, EncryptionMethod::ZipCrypto);
    assert_eq!(EncryptionMethod::Aes256, EncryptionMethod::Aes256);
    assert_eq!(EncryptionMethod::Mixed, EncryptionMethod::Mixed);
}

#[test]
fn test_encryption_method_default() {
    let default = EncryptionMethod::default();
    assert_eq!(default, EncryptionMethod::Aes256);
}

#[test]
fn test_encryption_method_clone() {
    let method = EncryptionMethod::Aes256;
    let cloned = method;
    assert_eq!(method, cloned);
}

#[test]
fn test_encryption_method_debug() {
    let method = EncryptionMethod::Aes256;
    let debug_str = format!("{:?}", method);
    assert!(debug_str.contains("Aes256"));
}

#[test]
fn test_encryption_method_is_single_method() {
    assert!(EncryptionMethod::None.is_single_method());
    assert!(EncryptionMethod::ZipCrypto.is_single_method());
    assert!(EncryptionMethod::Aes256.is_single_method());
    assert!(!EncryptionMethod::Mixed.is_single_method());
}

#[test]
fn test_encryption_method_mixed_cannot_be_parsed() {
    // Mixed is only for detection results, not input
    assert!(EncryptionMethod::from_str("mixed").is_err());
}

// ============================================================================
// Cross-type interaction tests
// ============================================================================

#[test]
fn test_all_combinations() {
    let levels = [
        CompressionLevel::STORE,
        CompressionLevel::FAST,
        CompressionLevel::DEFAULT,
        CompressionLevel::BEST,
    ];

    let methods = [
        EncryptionMethod::None,
        EncryptionMethod::ZipCrypto,
        EncryptionMethod::Aes256,
    ];

    // Verify we can create all combinations
    for level in &levels {
        for method in &methods {
            let _ = (*level, *method);
        }
    }
}

#[test]
fn test_compression_level_all_values() {
    // Test all values 0-9
    for i in 0..=9 {
        let level = CompressionLevel::new(i);
        assert_eq!(level.0, i);
    }
}
