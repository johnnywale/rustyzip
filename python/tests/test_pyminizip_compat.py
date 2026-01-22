"""Tests for pyminizip compatibility layer."""

import os
import tempfile
import shutil
import zipfile
import struct

import pytest

from rustyzipper.compat import pyminizip
import rustyzipper


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample file for testing."""
    path = os.path.join(temp_dir, "sample.txt")
    with open(path, "w") as f:
        f.write("Hello from pyminizip compatibility test!")
    return path


class TestPyminizipCompat:
    """Tests for pyminizip compatibility functions."""

    def test_compress_single_file_no_password(self, temp_dir, sample_file):
        """Test compressing a single file without password."""
        output = os.path.join(temp_dir, "output.zip")

        pyminizip.compress(sample_file, None, output, None, 5)

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

    def test_compress_single_file_with_password(self, temp_dir, sample_file):
        """Test compressing a single file with password."""
        output = os.path.join(temp_dir, "output.zip")

        pyminizip.compress(sample_file, None, output, "password123", 5)

        assert os.path.exists(output)

    def test_compress_single_file_with_prefix(self, temp_dir, sample_file):
        """Test compressing a single file with archive prefix."""
        output = os.path.join(temp_dir, "output.zip")

        pyminizip.compress(sample_file, "subdir", output, None, 5)

        assert os.path.exists(output)

    def test_compress_multiple_files(self, temp_dir):
        """Test compressing multiple files."""
        # Create test files
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file{i}.txt")
            with open(path, "w") as f:
                f.write(f"Content {i}")
            files.append(path)

        output = os.path.join(temp_dir, "multi.zip")

        pyminizip.compress(files, [None, None, None], output, "password", 5)

        assert os.path.exists(output)

    def test_compress_multiple_files_with_prefixes(self, temp_dir):
        """Test compressing multiple files with different prefixes."""
        # Create test files
        file1 = os.path.join(temp_dir, "a.txt")
        file2 = os.path.join(temp_dir, "b.txt")

        with open(file1, "w") as f:
            f.write("File A")
        with open(file2, "w") as f:
            f.write("File B")

        output = os.path.join(temp_dir, "prefixed.zip")

        pyminizip.compress([file1, file2], ["dir1", "dir2"], output, None, 5)

        assert os.path.exists(output)

    def test_uncompress_no_password(self, temp_dir, sample_file):
        """Test extracting without password."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)
        pyminizip.uncompress(zip_file, None, extract_dir, 0)

        extracted = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted)

    def test_uncompress_with_password(self, temp_dir, sample_file):
        """Test extracting with password."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "secret"

        pyminizip.compress(sample_file, None, zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        extracted = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted)

    def test_uncompress_to_cwd(self, temp_dir, sample_file):
        """Test extracting with dst=None (extract to current working directory)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Save current directory and change to extract_dir
        original_cwd = os.getcwd()
        try:
            os.chdir(extract_dir)
            pyminizip.uncompress(zip_file, None, None, 0)
            assert os.path.exists(os.path.join(extract_dir, "sample.txt"))
        finally:
            os.chdir(original_cwd)

    def test_uncompress_withoutpath_preserves_paths(self, temp_dir):
        """Test that withoutpath=0 preserves directory structure."""
        # Create a file in a subdirectory
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir)
        nested_file = os.path.join(subdir, "nested.txt")
        with open(nested_file, "w") as f:
            f.write("Nested content")

        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with a prefix to create nested structure in zip
        pyminizip.compress(nested_file, "deep/path", zip_file, None, 5)

        # Extract with withoutpath=0 (preserve paths)
        pyminizip.uncompress(zip_file, None, extract_dir, 0)

        # File should be at the nested path
        assert os.path.exists(os.path.join(extract_dir, "deep", "path", "nested.txt"))

    def test_uncompress_withoutpath_flattens(self, temp_dir):
        """Test that withoutpath=1 extracts files without directory structure."""
        # Create a file in a subdirectory
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir)
        nested_file = os.path.join(subdir, "nested.txt")
        with open(nested_file, "w") as f:
            f.write("Nested content")

        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with a prefix to create nested structure in zip
        pyminizip.compress(nested_file, "deep/path", zip_file, None, 5)

        # Extract with withoutpath=1 (flatten)
        pyminizip.uncompress(zip_file, None, extract_dir, 1)

        # File should be directly in extract_dir, not in nested path
        assert os.path.exists(os.path.join(extract_dir, "nested.txt"))
        # The nested path should NOT exist
        assert not os.path.exists(os.path.join(extract_dir, "deep"))

    def test_uncompress_wrong_password(self, temp_dir, sample_file):
        """Test extracting with wrong password fails."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "correct", 5)

        with pytest.raises((ValueError, IOError)):
            pyminizip.uncompress(zip_file, "wrong", extract_dir, 0)

    def test_compress_different_levels(self, temp_dir, sample_file):
        """Test compression with different levels."""
        for level in [1, 5, 9]:
            output = os.path.join(temp_dir, f"level{level}.zip")
            pyminizip.compress(sample_file, None, output, None, level)
            assert os.path.exists(output)


class TestMigrationScenarios:
    """Test common migration scenarios from pyminizip."""

    def test_basic_migration_pattern(self, temp_dir, sample_file):
        """Test the basic migration pattern described in docs."""
        # This is exactly how existing pyminizip code would work
        # after changing: import pyminizip -> from rustyzipper.compat import pyminizip

        output = os.path.join(temp_dir, "migrated.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress
        pyminizip.compress(sample_file, None, output, "password", 5)

        # Uncompress
        pyminizip.uncompress(output, "password", extract_dir, 0)

        # Verify
        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_batch_compression(self, temp_dir):
        """Test batch compression scenario."""
        # Create multiple files
        files = []
        for name in ["report.txt", "data.csv", "config.ini"]:
            path = os.path.join(temp_dir, name)
            with open(path, "w") as f:
                f.write(f"Content of {name}")
            files.append(path)

        output = os.path.join(temp_dir, "batch.zip")

        # Batch compress with prefixes
        prefixes = ["reports", "data", "config"]
        pyminizip.compress(files, prefixes, output, "batch_password", 6)

        assert os.path.exists(output)


class TestZipCryptoEncryption:
    """Tests to verify compat API always uses ZipCrypto encryption."""

    def _is_zipcrypto_encrypted(self, zip_path: str) -> bool:
        """Check if a ZIP file uses ZipCrypto encryption.

        ZipCrypto sets the encryption bit (bit 0) in the general purpose bit flag
        but does NOT use the AES extra field.
        """
        with open(zip_path, 'rb') as f:
            # Read local file header
            sig = f.read(4)
            if sig != b'PK\x03\x04':
                return False

            # Skip version needed (2 bytes)
            f.read(2)

            # Read general purpose bit flag (2 bytes)
            flags = struct.unpack('<H', f.read(2))[0]

            # Bit 0 indicates encryption
            is_encrypted = (flags & 0x0001) != 0

            # For ZipCrypto, bit 0 is set but we don't have AES extra field
            # AES encrypted files have extra field with signature 0x9901
            return is_encrypted

    def _can_decrypt_with_standard_zipfile(self, zip_path: str, password: str) -> bool:
        """Check if Python's zipfile module can decrypt (ZipCrypto only)."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Get first file
                names = zf.namelist()
                if not names:
                    return False
                # Try to read with password
                zf.setpassword(password.encode('utf-8'))
                _ = zf.read(names[0])
                return True
        except (RuntimeError, zipfile.BadZipFile):
            return False

    def test_compat_compress_uses_zipcrypto_not_aes(self, temp_dir, sample_file):
        """Verify compat API uses ZipCrypto, not AES256."""
        zip_compat = os.path.join(temp_dir, "compat.zip")
        zip_aes = os.path.join(temp_dir, "aes.zip")
        password = "testpassword"

        # Compress with compat API (should use ZipCrypto)
        pyminizip.compress(sample_file, None, zip_compat, password, 5)

        # Compress with modern API using AES256
        rustyzipper.compress_file(
            sample_file,
            zip_aes,
            password=password,
            encryption=rustyzipper.EncryptionMethod.AES256
        )

        # Both should exist
        assert os.path.exists(zip_compat)
        assert os.path.exists(zip_aes)

        # Compat should be readable by Python's zipfile (ZipCrypto)
        assert self._can_decrypt_with_standard_zipfile(zip_compat, password), \
            "Compat API should produce ZipCrypto-encrypted files readable by Python zipfile"

        # AES should NOT be readable by Python's zipfile (it doesn't support AES)
        assert not self._can_decrypt_with_standard_zipfile(zip_aes, password), \
            "AES256 encrypted files should NOT be readable by Python zipfile"

    def test_compat_compress_single_file_zipcrypto(self, temp_dir, sample_file):
        """Test single file compression uses ZipCrypto."""
        output = os.path.join(temp_dir, "single.zip")
        password = "singlepass"

        pyminizip.compress(sample_file, None, output, password, 5)

        assert self._is_zipcrypto_encrypted(output)
        assert self._can_decrypt_with_standard_zipfile(output, password)

    def test_compat_compress_multiple_files_zipcrypto(self, temp_dir):
        """Test multiple files compression uses ZipCrypto."""
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file{i}.txt")
            with open(path, "w") as f:
                f.write(f"Content {i}")
            files.append(path)

        output = os.path.join(temp_dir, "multi.zip")
        password = "multipass"

        pyminizip.compress(files, [None, None, None], output, password, 5)

        assert self._is_zipcrypto_encrypted(output)
        assert self._can_decrypt_with_standard_zipfile(output, password)

    def test_compat_compress_with_prefix_zipcrypto(self, temp_dir, sample_file):
        """Test compression with prefix uses ZipCrypto."""
        output = os.path.join(temp_dir, "prefixed.zip")
        password = "prefixpass"

        pyminizip.compress(sample_file, "subdir/nested", output, password, 5)

        assert self._is_zipcrypto_encrypted(output)
        assert self._can_decrypt_with_standard_zipfile(output, password)

    def test_compat_compress_multiple_uses_zipcrypto(self, temp_dir):
        """Test compress_multiple function uses ZipCrypto."""
        files = []
        for i in range(2):
            path = os.path.join(temp_dir, f"batch{i}.txt")
            with open(path, "w") as f:
                f.write(f"Batch content {i}")
            files.append(path)

        output = os.path.join(temp_dir, "batch.zip")
        password = "batchpass"

        pyminizip.compress_multiple(files, [], output, password, 5)

        assert self._is_zipcrypto_encrypted(output)
        assert self._can_decrypt_with_standard_zipfile(output, password)

    def test_compat_no_password_no_encryption(self, temp_dir, sample_file):
        """Test that no password means no encryption."""
        output = os.path.join(temp_dir, "nopass.zip")

        pyminizip.compress(sample_file, None, output, None, 5)

        # Should NOT be encrypted
        assert not self._is_zipcrypto_encrypted(output)

        # Should be readable without password
        with zipfile.ZipFile(output, 'r') as zf:
            content = zf.read("sample.txt")
            assert b"Hello from pyminizip" in content

    def test_compat_uncompress_zipcrypto_works(self, temp_dir, sample_file):
        """Test that uncompress works with ZipCrypto encrypted files."""
        zip_file = os.path.join(temp_dir, "encrypted.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "decryptme"

        # Compress with compat (ZipCrypto)
        pyminizip.compress(sample_file, None, zip_file, password, 5)

        # Uncompress with compat
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        extracted = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted)
        with open(extracted, 'r') as f:
            content = f.read()
            assert "Hello from pyminizip" in content

    def test_zipcrypto_vs_aes_file_size_difference(self, temp_dir, sample_file):
        """Verify ZipCrypto and AES produce different file sizes (AES has more overhead)."""
        zip_crypto = os.path.join(temp_dir, "zipcrypto.zip")
        zip_aes = os.path.join(temp_dir, "aes.zip")
        password = "compare"

        # Create ZipCrypto via compat
        pyminizip.compress(sample_file, None, zip_crypto, password, 5)

        # Create AES256 via modern API
        rustyzipper.compress_file(
            sample_file,
            zip_aes,
            password=password,
            encryption=rustyzipper.EncryptionMethod.AES256
        )

        size_crypto = os.path.getsize(zip_crypto)
        size_aes = os.path.getsize(zip_aes)

        # AES256 adds more overhead (salt, MAC, etc.)
        # They should be different sizes
        assert size_crypto != size_aes, \
            f"ZipCrypto ({size_crypto}) and AES ({size_aes}) should produce different file sizes"


class TestErrorHandling:
    """Tests for error handling in compat API."""

    def test_compress_file_not_found(self, temp_dir):
        """Test that compressing non-existent file raises error."""
        output = os.path.join(temp_dir, "output.zip")

        with pytest.raises(IOError):
            pyminizip.compress("/nonexistent/file.txt", None, output, None, 5)

    def test_compress_multiple_one_file_not_found(self, temp_dir, sample_file):
        """Test that one missing file in list raises error."""
        output = os.path.join(temp_dir, "output.zip")

        with pytest.raises(IOError):
            pyminizip.compress(
                [sample_file, "/nonexistent/file.txt"],
                [None, None],
                output,
                None,
                5
            )

    def test_uncompress_file_not_found(self, temp_dir):
        """Test that extracting non-existent ZIP raises error."""
        extract_dir = os.path.join(temp_dir, "extracted")

        with pytest.raises(IOError):
            pyminizip.uncompress("/nonexistent/archive.zip", None, extract_dir, 0)

    def test_uncompress_wrong_password(self, temp_dir, sample_file):
        """Test that wrong password raises ValueError."""
        zip_file = os.path.join(temp_dir, "encrypted.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "correct", 5)

        with pytest.raises((ValueError, IOError)):
            pyminizip.uncompress(zip_file, "wrong", extract_dir, 0)

    def test_uncompress_no_password_on_encrypted(self, temp_dir, sample_file):
        """Test that no password on encrypted file raises error."""
        zip_file = os.path.join(temp_dir, "encrypted.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "secret", 5)

        with pytest.raises((ValueError, IOError)):
            pyminizip.uncompress(zip_file, None, extract_dir, 0)

    def test_compress_invalid_output_path(self, temp_dir, sample_file):
        """Test that invalid output path raises error."""
        # Try to write to a non-existent directory
        output = "/nonexistent/directory/output.zip"

        with pytest.raises(IOError):
            pyminizip.compress(sample_file, None, output, None, 5)


class TestContentIntegrity:
    """Tests to verify content integrity through compress/decompress cycle."""

    def test_binary_content_integrity(self, temp_dir):
        """Test that binary content is preserved correctly."""
        binary_file = os.path.join(temp_dir, "binary.bin")
        # Create binary content with all byte values
        binary_data = bytes(range(256)) * 100
        with open(binary_file, 'wb') as f:
            f.write(binary_data)

        zip_file = os.path.join(temp_dir, "binary.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(binary_file, None, zip_file, "binpass", 5)
        pyminizip.uncompress(zip_file, "binpass", extract_dir, 0)

        extracted = os.path.join(extract_dir, "binary.bin")
        with open(extracted, 'rb') as f:
            extracted_data = f.read()

        assert extracted_data == binary_data

    def test_unicode_content_integrity(self, temp_dir):
        """Test that unicode content is preserved correctly."""
        unicode_file = os.path.join(temp_dir, "unicode.txt")
        unicode_content = "Hello 世界 🌍 مرحبا שלום"
        with open(unicode_file, 'w', encoding='utf-8') as f:
            f.write(unicode_content)

        zip_file = os.path.join(temp_dir, "unicode.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(unicode_file, None, zip_file, "unicodepass", 5)
        pyminizip.uncompress(zip_file, "unicodepass", extract_dir, 0)

        extracted = os.path.join(extract_dir, "unicode.txt")
        with open(extracted, 'r', encoding='utf-8') as f:
            extracted_content = f.read()

        assert extracted_content == unicode_content

    def test_empty_file_integrity(self, temp_dir):
        """Test that empty files are handled correctly."""
        empty_file = os.path.join(temp_dir, "empty.txt")
        with open(empty_file, 'w') as f:
            pass  # Create empty file

        zip_file = os.path.join(temp_dir, "empty.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(empty_file, None, zip_file, "emptypass", 5)
        pyminizip.uncompress(zip_file, "emptypass", extract_dir, 0)

        extracted = os.path.join(extract_dir, "empty.txt")
        assert os.path.exists(extracted)
        assert os.path.getsize(extracted) == 0

    def test_large_file_integrity(self, temp_dir):
        """Test that large files are handled correctly."""
        large_file = os.path.join(temp_dir, "large.bin")
        # Create 1MB file
        large_data = os.urandom(1024 * 1024)
        with open(large_file, 'wb') as f:
            f.write(large_data)

        zip_file = os.path.join(temp_dir, "large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(large_file, None, zip_file, "largepass", 5)
        pyminizip.uncompress(zip_file, "largepass", extract_dir, 0)

        extracted = os.path.join(extract_dir, "large.bin")
        with open(extracted, 'rb') as f:
            extracted_data = f.read()

        assert extracted_data == large_data

    def test_multiple_files_content_integrity(self, temp_dir):
        """Test that multiple files maintain their individual content."""
        files = {}
        for i in range(5):
            path = os.path.join(temp_dir, f"file{i}.txt")
            content = f"Unique content for file {i}: {os.urandom(50).hex()}"
            with open(path, 'w') as f:
                f.write(content)
            files[f"file{i}.txt"] = content

        file_paths = list(files.keys())
        full_paths = [os.path.join(temp_dir, f) for f in file_paths]

        zip_file = os.path.join(temp_dir, "multi.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(full_paths, [None] * len(full_paths), zip_file, "multipass", 5)
        pyminizip.uncompress(zip_file, "multipass", extract_dir, 0)

        for filename, expected_content in files.items():
            extracted = os.path.join(extract_dir, filename)
            with open(extracted, 'r') as f:
                actual_content = f.read()
            assert actual_content == expected_content, f"Content mismatch for {filename}"


class TestWithoutpathBehavior:
    """Tests for withoutpath parameter behavior."""

    def test_withoutpath_zero_preserves_structure(self, temp_dir):
        """Test that withoutpath=0 preserves directory structure."""
        nested_file = os.path.join(temp_dir, "nested.txt")
        with open(nested_file, 'w') as f:
            f.write("Nested content")

        zip_file = os.path.join(temp_dir, "nested.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with deep prefix
        pyminizip.compress(nested_file, "a/b/c/d", zip_file, "pass", 5)

        # Extract with withoutpath=0
        pyminizip.uncompress(zip_file, "pass", extract_dir, 0)

        # Should preserve structure
        expected = os.path.join(extract_dir, "a", "b", "c", "d", "nested.txt")
        assert os.path.exists(expected), f"Expected {expected} to exist"

    def test_withoutpath_one_flattens_structure(self, temp_dir):
        """Test that withoutpath=1 flattens directory structure."""
        nested_file = os.path.join(temp_dir, "nested.txt")
        with open(nested_file, 'w') as f:
            f.write("Nested content")

        zip_file = os.path.join(temp_dir, "nested.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with deep prefix
        pyminizip.compress(nested_file, "a/b/c/d", zip_file, "pass", 5)

        # Extract with withoutpath=1
        pyminizip.uncompress(zip_file, "pass", extract_dir, 1)

        # Should flatten
        expected_flat = os.path.join(extract_dir, "nested.txt")
        not_expected = os.path.join(extract_dir, "a")

        assert os.path.exists(expected_flat), f"Expected {expected_flat} to exist"
        assert not os.path.exists(not_expected), f"Did not expect {not_expected} to exist"

    def test_withoutpath_nonzero_values_flatten(self, temp_dir):
        """Test that any non-zero withoutpath value flattens."""
        for withoutpath_val in [1, 2, 100, -1]:
            nested_file = os.path.join(temp_dir, "test.txt")
            with open(nested_file, 'w') as f:
                f.write("Test")

            zip_file = os.path.join(temp_dir, f"test_{withoutpath_val}.zip")
            extract_dir = os.path.join(temp_dir, f"extracted_{withoutpath_val}")

            pyminizip.compress(nested_file, "dir/subdir", zip_file, None, 5)
            pyminizip.uncompress(zip_file, None, extract_dir, withoutpath_val)

            # Should be flattened
            assert os.path.exists(os.path.join(extract_dir, "test.txt"))
            assert not os.path.exists(os.path.join(extract_dir, "dir"))


class TestSecurityParameters:
    """Tests for security parameters in compat API (max_size, max_ratio, allow_symlinks)."""

    def test_uncompress_default_security_limits(self, temp_dir, sample_file):
        """Test that default security limits are applied (2GB size, 500:1 ratio)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "password", 5)

        # Should work with default limits for normal files
        pyminizip.uncompress(zip_file, "password", extract_dir, 0)

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_custom_max_size(self, temp_dir, sample_file):
        """Test uncompress with custom max_size parameter."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Use a large custom max_size
        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            max_size=10 * 1024 * 1024 * 1024  # 10GB
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_disabled_max_size(self, temp_dir, sample_file):
        """Test uncompress with max_size=0 (disabled)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Disable size limit
        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            max_size=0
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_custom_max_ratio(self, temp_dir, sample_file):
        """Test uncompress with custom max_ratio parameter."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Use a higher ratio limit
        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            max_ratio=1000
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_disabled_max_ratio(self, temp_dir, sample_file):
        """Test uncompress with max_ratio=0 (disabled)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Disable ratio limit
        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            max_ratio=0
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_both_limits_custom(self, temp_dir, sample_file):
        """Test uncompress with both max_size and max_ratio customized."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "pass123", 5)

        pyminizip.uncompress(
            zip_file, "pass123", extract_dir, 0,
            max_size=5 * 1024 * 1024 * 1024,  # 5GB
            max_ratio=2000
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_both_limits_disabled(self, temp_dir, sample_file):
        """Test uncompress with both limits disabled (permissive mode)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Fully permissive mode
        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            max_size=0,
            max_ratio=0
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_allow_symlinks_false(self, temp_dir, sample_file):
        """Test uncompress with allow_symlinks=False (default behavior)."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        pyminizip.uncompress(
            zip_file, None, extract_dir, 0,
            allow_symlinks=False
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_with_password_and_security_params(self, temp_dir, sample_file):
        """Test uncompress combining password and security parameters."""
        zip_file = os.path.join(temp_dir, "secure.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "SecureP@ssw0rd"

        pyminizip.compress(sample_file, None, zip_file, password, 5)

        pyminizip.uncompress(
            zip_file, password, extract_dir, 0,
            max_size=1024 * 1024 * 1024,
            max_ratio=500,
            allow_symlinks=False
        )

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_with_prefix_and_security_params(self, temp_dir, sample_file):
        """Test uncompress with archive prefix and security parameters."""
        zip_file = os.path.join(temp_dir, "prefixed.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with prefix
        pyminizip.compress(sample_file, "subdir/nested", zip_file, "pass", 5)

        pyminizip.uncompress(
            zip_file, "pass", extract_dir, 0,
            max_size=0,  # Disabled
            max_ratio=0  # Disabled
        )

        # Should preserve directory structure
        assert os.path.exists(os.path.join(extract_dir, "subdir", "nested", "sample.txt"))

    def test_uncompress_withoutpath_and_security_params(self, temp_dir, sample_file):
        """Test uncompress with withoutpath=1 and security parameters."""
        zip_file = os.path.join(temp_dir, "nested.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Compress with prefix
        pyminizip.compress(sample_file, "deep/path/here", zip_file, None, 5)

        # Extract flattened with custom security
        pyminizip.uncompress(
            zip_file, None, extract_dir, 1,  # withoutpath=1
            max_size=10 * 1024 * 1024 * 1024,
            max_ratio=1000
        )

        # Should be flattened
        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))
        assert not os.path.exists(os.path.join(extract_dir, "deep"))

    def test_uncompress_security_params_keyword_only(self, temp_dir, sample_file):
        """Test that security parameters must be keyword arguments."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, None, 5)

        # Passing max_size as positional should raise TypeError
        with pytest.raises(TypeError):
            pyminizip.uncompress(zip_file, None, extract_dir, 0, 1024)

    def test_uncompress_backward_compatibility(self, temp_dir, sample_file):
        """Test that existing code without security params still works."""
        zip_file = os.path.join(temp_dir, "legacy.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(sample_file, None, zip_file, "oldpass", 5)

        # Old-style call without any security params
        pyminizip.uncompress(zip_file, "oldpass", extract_dir, 0)

        assert os.path.exists(os.path.join(extract_dir, "sample.txt"))

    def test_uncompress_large_file_with_limits(self, temp_dir):
        """Test uncompress of larger file with security limits."""
        # Create a larger file (100KB of compressible data)
        large_file = os.path.join(temp_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("ABCD" * 25000)  # 100KB

        zip_file = os.path.join(temp_dir, "large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(large_file, None, zip_file, "largepass", 9)

        # Should work with default limits
        pyminizip.uncompress(
            zip_file, "largepass", extract_dir, 0,
            max_size=1024 * 1024 * 1024,  # 1GB
            max_ratio=1000
        )

        extracted = os.path.join(extract_dir, "large.txt")
        assert os.path.exists(extracted)
        assert os.path.getsize(extracted) == 100000

    def test_uncompress_multiple_files_with_security(self, temp_dir):
        """Test uncompress of multiple files with security parameters."""
        # Create multiple files
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file{i}.txt")
            with open(path, 'w') as f:
                f.write(f"Content of file {i}")
            files.append(path)

        zip_file = os.path.join(temp_dir, "multi.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        pyminizip.compress(files, [None, None, None], zip_file, "multipass", 5)

        pyminizip.uncompress(
            zip_file, "multipass", extract_dir, 0,
            max_size=0,
            max_ratio=0,
            allow_symlinks=False
        )

        for i in range(3):
            assert os.path.exists(os.path.join(extract_dir, f"file{i}.txt"))


class TestLargeBinaryCompatAPI:
    """Tests for large binary encryption/decryption using pyminizip compat API."""

    @pytest.fixture
    def large_binary_data(self):
        """Generate 5MB of random binary data for testing."""
        import random
        random.seed(12345)  # Reproducible randomness
        return bytes([random.randint(0, 255) for _ in range(5 * 1024 * 1024)])

    @pytest.fixture
    def large_binary_file(self, temp_dir, large_binary_data):
        """Create a large binary file for testing."""
        path = os.path.join(temp_dir, "large_binary.bin")
        with open(path, "wb") as f:
            f.write(large_binary_data)
        return path

    def test_large_binary_compress_uncompress_with_password(self, temp_dir, large_binary_file, large_binary_data):
        """Test compress/uncompress of large binary with password."""
        zip_file = os.path.join(temp_dir, "large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "LargeBinaryPassword123!"

        pyminizip.compress(large_binary_file, None, zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        extracted = os.path.join(extract_dir, "large_binary.bin")
        assert os.path.exists(extracted)

        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data
        assert len(extracted_data) == len(large_binary_data)

    def test_large_binary_compress_multiple_with_password(self, temp_dir, large_binary_data):
        """Test compress_multiple with large binary files and password."""
        # Create multiple large binary files
        files = []
        expected_data = {}
        for i in range(3):
            filename = f"large{i}.bin"
            path = os.path.join(temp_dir, filename)
            # Create variations of the data
            if i == 0:
                data = large_binary_data
            elif i == 1:
                data = large_binary_data[::-1]  # Reversed
            else:
                data = bytes([(b + i) % 256 for b in large_binary_data])  # Shifted
            with open(path, "wb") as f:
                f.write(data)
            files.append(path)
            expected_data[filename] = data

        zip_file = os.path.join(temp_dir, "multi_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "MultiLargeBinary!"

        pyminizip.compress_multiple(files, [], zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        for filename, expected in expected_data.items():
            extracted = os.path.join(extract_dir, filename)
            assert os.path.exists(extracted), f"{filename} not found"
            with open(extracted, "rb") as f:
                actual = f.read()
            assert actual == expected, f"Content mismatch for {filename}"

    def test_large_binary_with_prefix_and_password(self, temp_dir, large_binary_file, large_binary_data):
        """Test large binary with archive prefix and password."""
        zip_file = os.path.join(temp_dir, "prefixed_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "PrefixedLargeBinary!"

        pyminizip.compress(large_binary_file, "deep/nested/path", zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        extracted = os.path.join(extract_dir, "deep", "nested", "path", "large_binary.bin")
        assert os.path.exists(extracted)

        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data

    def test_large_binary_withoutpath_flattens(self, temp_dir, large_binary_file, large_binary_data):
        """Test large binary with withoutpath=1 flattens directory structure."""
        zip_file = os.path.join(temp_dir, "flatten_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "FlattenLargeBinary!"

        pyminizip.compress(large_binary_file, "a/b/c/d", zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 1)  # withoutpath=1

        # Should be flattened
        extracted = os.path.join(extract_dir, "large_binary.bin")
        assert os.path.exists(extracted)
        assert not os.path.exists(os.path.join(extract_dir, "a"))

        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data

    def test_large_binary_compression_levels(self, temp_dir, large_binary_file, large_binary_data):
        """Test large binary with different compression levels."""
        password = "CompressionLevelTest!"

        for level in [1, 5, 9]:
            zip_file = os.path.join(temp_dir, f"level{level}.zip")
            extract_dir = os.path.join(temp_dir, f"extracted_{level}")

            pyminizip.compress(large_binary_file, None, zip_file, password, level)
            pyminizip.uncompress(zip_file, password, extract_dir, 0)

            extracted = os.path.join(extract_dir, "large_binary.bin")
            with open(extracted, "rb") as f:
                extracted_data = f.read()

            assert extracted_data == large_binary_data, f"Mismatch at level {level}"

    def test_large_binary_with_security_params(self, temp_dir, large_binary_file, large_binary_data):
        """Test large binary with custom security parameters."""
        zip_file = os.path.join(temp_dir, "secure_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "SecureLargeBinary!"

        pyminizip.compress(large_binary_file, None, zip_file, password, 5)
        pyminizip.uncompress(
            zip_file, password, extract_dir, 0,
            max_size=10 * 1024 * 1024 * 1024,  # 10GB
            max_ratio=1000,
            allow_symlinks=False
        )

        extracted = os.path.join(extract_dir, "large_binary.bin")
        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data

    def test_large_binary_disabled_security_limits(self, temp_dir, large_binary_file, large_binary_data):
        """Test large binary with disabled security limits (permissive mode)."""
        zip_file = os.path.join(temp_dir, "permissive_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "PermissiveLargeBinary!"

        pyminizip.compress(large_binary_file, None, zip_file, password, 5)
        pyminizip.uncompress(
            zip_file, password, extract_dir, 0,
            max_size=0,  # Disabled
            max_ratio=0  # Disabled
        )

        extracted = os.path.join(extract_dir, "large_binary.bin")
        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data

    def test_large_binary_zipcrypto_python_zipfile_readable(self, temp_dir, large_binary_file, large_binary_data):
        """Verify large binary encrypted with ZipCrypto is readable by Python's zipfile."""
        zip_file = os.path.join(temp_dir, "zipcrypto_large.zip")
        password = "ZipCryptoLarge!"

        pyminizip.compress(large_binary_file, None, zip_file, password, 5)

        # Verify Python's standard zipfile can read it (ZipCrypto only)
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            extracted_data = zf.read("large_binary.bin")

        assert extracted_data == large_binary_data
        assert len(extracted_data) == len(large_binary_data)

    def test_large_binary_content_all_byte_values(self, temp_dir):
        """Test large binary containing all possible byte values multiple times."""
        # Create data with all byte values repeated
        all_bytes_data = bytes(range(256)) * (5 * 1024 * 4)  # ~5MB

        binary_file = os.path.join(temp_dir, "all_bytes.bin")
        with open(binary_file, "wb") as f:
            f.write(all_bytes_data)

        zip_file = os.path.join(temp_dir, "all_bytes.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "AllBytesTest!"

        pyminizip.compress(binary_file, None, zip_file, password, 5)
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        extracted = os.path.join(extract_dir, "all_bytes.bin")
        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == all_bytes_data

    def test_cross_api_compat_vs_rustyzipper(self, temp_dir, large_binary_file, large_binary_data):
        """Verify compat API and rustyzipper API can interoperate for large binaries."""
        password = "CrossAPICompat!"

        # Compress with compat API (ZipCrypto)
        zip_compat = os.path.join(temp_dir, "compat.zip")
        pyminizip.compress(large_binary_file, None, zip_compat, password, 5)

        # Decompress with rustyzipper API
        extract_dir = os.path.join(temp_dir, "rustyzipper_extracted")
        rustyzipper.decompress_file(zip_compat, extract_dir, password=password)

        extracted = os.path.join(extract_dir, "large_binary.bin")
        with open(extracted, "rb") as f:
            extracted_data = f.read()

        assert extracted_data == large_binary_data

    def test_large_binary_progress_callback(self, temp_dir, large_binary_data):
        """Test compress_multiple with large binary and progress callback."""
        # Create large binary files
        files = []
        for i in range(2):
            path = os.path.join(temp_dir, f"large{i}.bin")
            with open(path, "wb") as f:
                f.write(large_binary_data)
            files.append(path)

        zip_file = os.path.join(temp_dir, "progress_large.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "ProgressLarge!"

        progress_calls = []
        def on_progress(count):
            progress_calls.append(count)

        pyminizip.compress_multiple(files, [], zip_file, password, 5, on_progress)

        assert len(progress_calls) == 1
        assert progress_calls[0] == 2

        # Verify extraction works
        pyminizip.uncompress(zip_file, password, extract_dir, 0)

        for i in range(2):
            extracted = os.path.join(extract_dir, f"large{i}.bin")
            with open(extracted, "rb") as f:
                extracted_data = f.read()
            assert extracted_data == large_binary_data
