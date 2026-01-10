"""Tests for pyminizip compatibility layer."""

import os
import tempfile
import shutil

import pytest

from rustyzipper.compat import pyminizip


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
