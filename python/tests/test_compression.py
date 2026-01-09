"""Tests for rustyzipper compression and decompression functionality."""

import os
import tempfile
import shutil
from pathlib import Path

import pytest

from rustyzipper import (
    compress_file,
    compress_files,
    compress_directory,
    decompress_file,
    EncryptionMethod,
    CompressionLevel,
)


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
        f.write("Hello, World! This is a test file for rustyzipper.")
    return path


@pytest.fixture
def sample_directory(temp_dir):
    """Create a sample directory structure for testing."""
    base = os.path.join(temp_dir, "sample_dir")
    os.makedirs(base)

    # Create files
    with open(os.path.join(base, "file1.txt"), "w") as f:
        f.write("File 1 content")
    with open(os.path.join(base, "file2.py"), "w") as f:
        f.write("# Python file\nprint('hello')")

    # Create subdirectory
    subdir = os.path.join(base, "subdir")
    os.makedirs(subdir)
    with open(os.path.join(subdir, "nested.txt"), "w") as f:
        f.write("Nested file content")

    # Create __pycache__ directory (to test exclusion)
    pycache = os.path.join(base, "__pycache__")
    os.makedirs(pycache)
    with open(os.path.join(pycache, "cached.pyc"), "wb") as f:
        f.write(b"\x00\x00\x00\x00")

    return base


class TestCompressFile:
    """Tests for compress_file function."""

    def test_compress_no_password(self, temp_dir, sample_file):
        """Test compression without password."""
        output = os.path.join(temp_dir, "output.zip")

        compress_file(sample_file, output, encryption=EncryptionMethod.NONE)

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

    def test_compress_with_aes256(self, temp_dir, sample_file):
        """Test compression with AES-256 encryption."""
        output = os.path.join(temp_dir, "output.zip")

        compress_file(sample_file, output, password="secret123")

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

    def test_compress_with_zipcrypto(self, temp_dir, sample_file):
        """Test compression with ZipCrypto encryption."""
        output = os.path.join(temp_dir, "output.zip")

        compress_file(
            sample_file,
            output,
            password="secret123",
            encryption=EncryptionMethod.ZIPCRYPTO,
            suppress_warning=True,
        )

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

    def test_compress_file_not_found(self, temp_dir):
        """Test compression of non-existent file."""
        output = os.path.join(temp_dir, "output.zip")

        with pytest.raises(IOError):
            compress_file("nonexistent.txt", output)

    def test_compression_levels(self, temp_dir, sample_file):
        """Test different compression levels."""
        for level in [CompressionLevel.STORE, CompressionLevel.FAST, CompressionLevel.DEFAULT, CompressionLevel.BEST]:
            output = os.path.join(temp_dir, f"output_{level.name}.zip")
            compress_file(
                sample_file,
                output,
                compression_level=level,
                encryption=EncryptionMethod.NONE,
            )
            assert os.path.exists(output)


class TestDecompressFile:
    """Tests for decompress_file function."""

    def test_decompress_no_password(self, temp_dir, sample_file):
        """Test decompression without password."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        compress_file(sample_file, zip_file, encryption=EncryptionMethod.NONE)
        decompress_file(zip_file, extract_dir)

        extracted_file = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted_file)

        with open(extracted_file, "r") as f:
            content = f.read()
        assert "Hello, World!" in content

    def test_decompress_with_password(self, temp_dir, sample_file):
        """Test decompression with password."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")
        password = "MySecretP@ss"

        compress_file(sample_file, zip_file, password=password)
        decompress_file(zip_file, extract_dir, password=password)

        extracted_file = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted_file)

    def test_decompress_wrong_password(self, temp_dir, sample_file):
        """Test decompression with wrong password."""
        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        compress_file(sample_file, zip_file, password="correct")

        with pytest.raises((ValueError, IOError)):
            decompress_file(zip_file, extract_dir, password="wrong")

    def test_decompress_file_not_found(self, temp_dir):
        """Test decompression of non-existent file."""
        extract_dir = os.path.join(temp_dir, "extracted")

        with pytest.raises(IOError):
            decompress_file("nonexistent.zip", extract_dir)


class TestCompressFiles:
    """Tests for compress_files function."""

    def test_compress_multiple_files(self, temp_dir):
        """Test compression of multiple files."""
        # Create test files
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file{i}.txt")
            with open(path, "w") as f:
                f.write(f"Content of file {i}")
            files.append(path)

        output = os.path.join(temp_dir, "multi.zip")
        compress_files(files, output, encryption=EncryptionMethod.NONE)

        assert os.path.exists(output)

        # Extract and verify
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir)

        for i in range(3):
            extracted = os.path.join(extract_dir, f"file{i}.txt")
            assert os.path.exists(extracted)

    def test_compress_with_prefixes(self, temp_dir):
        """Test compression with archive path prefixes."""
        # Create test files
        file1 = os.path.join(temp_dir, "doc1.txt")
        file2 = os.path.join(temp_dir, "doc2.txt")

        with open(file1, "w") as f:
            f.write("Document 1")
        with open(file2, "w") as f:
            f.write("Document 2")

        output = os.path.join(temp_dir, "prefixed.zip")
        compress_files(
            [file1, file2],
            output,
            prefixes=["docs/a", "docs/b"],
            encryption=EncryptionMethod.NONE,
        )

        assert os.path.exists(output)


class TestCompressDirectory:
    """Tests for compress_directory function."""

    def test_compress_directory_basic(self, temp_dir, sample_directory):
        """Test basic directory compression."""
        output = os.path.join(temp_dir, "dir.zip")

        compress_directory(sample_directory, output, encryption=EncryptionMethod.NONE)

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

    def test_compress_directory_with_password(self, temp_dir, sample_directory):
        """Test directory compression with password."""
        output = os.path.join(temp_dir, "secure_dir.zip")
        password = "DirPassword123"

        compress_directory(sample_directory, output, password=password)

        assert os.path.exists(output)

        # Verify by extracting
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir, password=password)

        assert os.path.exists(os.path.join(extract_dir, "file1.txt"))

    def test_compress_directory_with_include_patterns(self, temp_dir, sample_directory):
        """Test directory compression with include patterns."""
        output = os.path.join(temp_dir, "filtered.zip")

        compress_directory(
            sample_directory,
            output,
            include_patterns=["*.py"],
            encryption=EncryptionMethod.NONE,
        )

        assert os.path.exists(output)

    def test_compress_directory_with_exclude_patterns(self, temp_dir, sample_directory):
        """Test directory compression with exclude patterns."""
        output = os.path.join(temp_dir, "filtered.zip")

        compress_directory(
            sample_directory,
            output,
            exclude_patterns=["__pycache__", "*.pyc"],
            encryption=EncryptionMethod.NONE,
        )

        assert os.path.exists(output)

        # Extract and verify __pycache__ is excluded
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir)

        assert not os.path.exists(os.path.join(extract_dir, "__pycache__"))


class TestEncryptionMethod:
    """Tests for EncryptionMethod enum."""

    def test_enum_values(self):
        """Test enum values are correct."""
        assert EncryptionMethod.AES256.value == "aes256"
        assert EncryptionMethod.ZIPCRYPTO.value == "zipcrypto"
        assert EncryptionMethod.NONE.value == "none"


class TestCompressionLevel:
    """Tests for CompressionLevel enum."""

    def test_enum_values(self):
        """Test enum values are correct."""
        assert CompressionLevel.STORE.value == 0
        assert CompressionLevel.FAST.value == 1
        assert CompressionLevel.DEFAULT.value == 6
        assert CompressionLevel.BEST.value == 9
