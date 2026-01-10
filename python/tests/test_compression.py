"""Tests for rustyzipper compression and decompression functionality."""

import os
import tempfile
import shutil
from pathlib import Path

import pytest

import io

from rustyzipper import (
    compress_file,
    compress_files,
    compress_directory,
    decompress_file,
    compress_bytes,
    decompress_bytes,
    compress_stream,
    decompress_stream,
    open_zip_stream,
    open_zip_stream_from_file,
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

    def test_decompress_preserves_timestamp(self, temp_dir, sample_file):
        """Test that decompression preserves file modification time."""
        import time as time_module

        zip_file = os.path.join(temp_dir, "test.zip")
        extract_dir = os.path.join(temp_dir, "extracted")

        # Set a specific modification time on the source file (1 hour ago)
        old_mtime = time_module.time() - 3600
        os.utime(sample_file, (old_mtime, old_mtime))

        # Compress and decompress
        compress_file(sample_file, zip_file, encryption=EncryptionMethod.NONE)
        decompress_file(zip_file, extract_dir)

        extracted_file = os.path.join(extract_dir, "sample.txt")
        assert os.path.exists(extracted_file)

        # Check that the modification time is preserved (within 2 seconds tolerance
        # due to ZIP format's 2-second resolution)
        extracted_mtime = os.path.getmtime(extracted_file)
        assert abs(extracted_mtime - old_mtime) < 3, (
            f"Timestamp not preserved: expected ~{old_mtime}, got {extracted_mtime}"
        )


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


class TestCompressBytes:
    """Tests for compress_bytes function."""

    def test_compress_single_file_no_password(self):
        """Test compressing a single file without password."""
        files = [("hello.txt", b"Hello, World!")]

        zip_data = compress_bytes(files, encryption=EncryptionMethod.NONE)

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0
        # ZIP files start with PK magic bytes
        assert zip_data[:2] == b"PK"

    def test_compress_multiple_files(self):
        """Test compressing multiple files."""
        files = [
            ("file1.txt", b"Content of file 1"),
            ("file2.txt", b"Content of file 2"),
            ("data.bin", bytes(range(256))),
        ]

        zip_data = compress_bytes(files, encryption=EncryptionMethod.NONE)

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compress_with_subdirectories(self):
        """Test compressing files with subdirectory paths."""
        files = [
            ("root.txt", b"Root file"),
            ("subdir/nested.txt", b"Nested file"),
            ("subdir/deep/file.txt", b"Deep nested file"),
        ]

        zip_data = compress_bytes(files, encryption=EncryptionMethod.NONE)

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compress_with_aes256_password(self):
        """Test compression with AES-256 encryption."""
        files = [("secret.txt", b"Secret data")]

        zip_data = compress_bytes(files, password="MyPassword123")

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compress_with_zipcrypto_password(self):
        """Test compression with ZipCrypto encryption."""
        files = [("legacy.txt", b"Legacy encrypted data")]

        zip_data = compress_bytes(
            files,
            password="password",
            encryption=EncryptionMethod.ZIPCRYPTO,
            suppress_warning=True,
        )

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compress_empty_file(self):
        """Test compressing an empty file."""
        files = [("empty.txt", b"")]

        zip_data = compress_bytes(files, encryption=EncryptionMethod.NONE)

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compress_binary_data(self):
        """Test compressing binary data with all byte values."""
        binary_data = bytes(range(256)) * 10
        files = [("binary.bin", binary_data)]

        zip_data = compress_bytes(files, encryption=EncryptionMethod.NONE)

        assert isinstance(zip_data, bytes)
        assert len(zip_data) > 0

    def test_compression_levels(self):
        """Test different compression levels produce valid output."""
        # Repetitive data compresses well
        data = b"AAAA" * 1000
        files = [("data.txt", data)]

        for level in [CompressionLevel.STORE, CompressionLevel.FAST, CompressionLevel.DEFAULT, CompressionLevel.BEST]:
            zip_data = compress_bytes(
                files,
                compression_level=level,
                encryption=EncryptionMethod.NONE,
            )
            assert isinstance(zip_data, bytes)
            assert len(zip_data) > 0

    def test_compression_level_affects_size(self):
        """Test that higher compression levels produce smaller output for compressible data."""
        # Highly repetitive data
        data = b"AAAA" * 10000
        files = [("data.txt", data)]

        zip_store = compress_bytes(
            files,
            compression_level=CompressionLevel.STORE,
            encryption=EncryptionMethod.NONE,
        )
        zip_best = compress_bytes(
            files,
            compression_level=CompressionLevel.BEST,
            encryption=EncryptionMethod.NONE,
        )

        # BEST compression should be smaller than STORE for repetitive data
        assert len(zip_best) < len(zip_store)


class TestDecompressBytes:
    """Tests for decompress_bytes function."""

    def test_decompress_single_file_no_password(self):
        """Test decompressing a single file without password."""
        original_files = [("hello.txt", b"Hello, World!")]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 1
        assert result[0][0] == "hello.txt"
        assert result[0][1] == b"Hello, World!"

    def test_decompress_multiple_files(self):
        """Test decompressing multiple files."""
        original_files = [
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("file3.txt", b"Content 3"),
        ]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 3
        result_dict = {name: data for name, data in result}
        assert result_dict["file1.txt"] == b"Content 1"
        assert result_dict["file2.txt"] == b"Content 2"
        assert result_dict["file3.txt"] == b"Content 3"

    def test_decompress_with_subdirectories(self):
        """Test decompressing files with subdirectory paths."""
        original_files = [
            ("root.txt", b"Root"),
            ("subdir/nested.txt", b"Nested"),
            ("a/b/c/deep.txt", b"Deep"),
        ]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 3
        result_dict = {name: data for name, data in result}
        assert result_dict["root.txt"] == b"Root"
        assert result_dict["subdir/nested.txt"] == b"Nested"
        assert result_dict["a/b/c/deep.txt"] == b"Deep"

    def test_decompress_with_password_aes256(self):
        """Test decompression with AES-256 encryption."""
        original_files = [("secret.txt", b"Secret data")]
        password = "StrongP@ssw0rd"

        zip_data = compress_bytes(original_files, password=password)
        result = decompress_bytes(zip_data, password=password)

        assert len(result) == 1
        assert result[0][0] == "secret.txt"
        assert result[0][1] == b"Secret data"

    def test_decompress_with_password_zipcrypto(self):
        """Test decompression with ZipCrypto encryption."""
        original_files = [("legacy.txt", b"Legacy data")]
        password = "simple"

        zip_data = compress_bytes(
            original_files,
            password=password,
            encryption=EncryptionMethod.ZIPCRYPTO,
            suppress_warning=True,
        )
        result = decompress_bytes(zip_data, password=password)

        assert len(result) == 1
        assert result[0][0] == "legacy.txt"
        assert result[0][1] == b"Legacy data"

    def test_decompress_wrong_password(self):
        """Test decompression with wrong password raises error."""
        original_files = [("secret.txt", b"Secret")]

        zip_data = compress_bytes(original_files, password="correct_password")

        with pytest.raises((ValueError, IOError)):
            decompress_bytes(zip_data, password="wrong_password")

    def test_decompress_empty_file(self):
        """Test decompressing an empty file."""
        original_files = [("empty.txt", b"")]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 1
        assert result[0][0] == "empty.txt"
        assert result[0][1] == b""

    def test_decompress_binary_data(self):
        """Test decompressing binary data with all byte values."""
        binary_data = bytes(range(256))
        original_files = [("binary.bin", binary_data)]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 1
        assert result[0][0] == "binary.bin"
        assert result[0][1] == binary_data

    def test_decompress_large_data(self):
        """Test decompressing larger data (1MB)."""
        # Create 1MB of data
        large_data = bytes(range(256)) * 4096  # 1MB
        original_files = [("large.bin", large_data)]

        zip_data = compress_bytes(original_files, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == 1
        assert result[0][0] == "large.bin"
        assert result[0][1] == large_data
        assert len(result[0][1]) == 1024 * 1024


class TestCompressDecompressBytesRoundTrip:
    """Tests for compress_bytes and decompress_bytes round-trip scenarios."""

    def test_roundtrip_text_files(self):
        """Test round-trip with text files."""
        original = [
            ("readme.txt", b"This is a readme file"),
            ("config.json", b'{"key": "value", "number": 42}'),
            ("data.csv", b"name,age\nAlice,30\nBob,25"),
        ]

        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert len(result) == len(original)
        for orig, res in zip(original, result):
            assert orig[0] == res[0]
            assert orig[1] == res[1]

    def test_roundtrip_with_encryption(self):
        """Test round-trip with password encryption."""
        original = [
            ("doc1.txt", b"Document 1 content"),
            ("doc2.txt", b"Document 2 content"),
        ]
        password = "SecureP@ss123"

        zip_data = compress_bytes(original, password=password)
        result = decompress_bytes(zip_data, password=password)

        assert len(result) == len(original)
        for orig, res in zip(original, result):
            assert orig[0] == res[0]
            assert orig[1] == res[1]

    def test_roundtrip_mixed_content(self):
        """Test round-trip with mixed text and binary content."""
        original = [
            ("text.txt", "Unicode text: \u4e2d\u6587".encode("utf-8")),
            ("binary.bin", bytes(range(256))),
            ("empty.dat", b""),
            ("nested/file.txt", b"Nested content"),
        ]

        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        result_dict = {name: data for name, data in result}
        for name, data in original:
            assert result_dict[name] == data

    def test_roundtrip_preserves_bytes_type(self):
        """Test that decompressed data is bytes type."""
        original = [("test.txt", b"Test content")]

        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)
        result = decompress_bytes(zip_data)

        assert isinstance(result[0][1], bytes)


class TestCompressStream:
    """Tests for compress_stream function (streaming compression)."""

    def test_compress_stream_single_file(self):
        """Test streaming compression of a single file."""
        input_data = b"Hello, streaming world!"
        input_file = io.BytesIO(input_data)
        output = io.BytesIO()

        compress_stream(
            [("hello.txt", input_file)],
            output,
            encryption=EncryptionMethod.NONE,
        )

        # Verify output is valid ZIP
        zip_data = output.getvalue()
        assert len(zip_data) > 0
        assert zip_data[:2] == b"PK"

    def test_compress_stream_multiple_files(self):
        """Test streaming compression of multiple files."""
        file1 = io.BytesIO(b"Content 1")
        file2 = io.BytesIO(b"Content 2")
        file3 = io.BytesIO(b"Content 3")
        output = io.BytesIO()

        compress_stream(
            [("file1.txt", file1), ("file2.txt", file2), ("file3.txt", file3)],
            output,
            encryption=EncryptionMethod.NONE,
        )

        zip_data = output.getvalue()
        assert len(zip_data) > 0

    def test_compress_stream_with_password(self):
        """Test streaming compression with password."""
        input_file = io.BytesIO(b"Secret data")
        output = io.BytesIO()

        compress_stream(
            [("secret.txt", input_file)],
            output,
            password="MyPassword123",
        )

        zip_data = output.getvalue()
        assert len(zip_data) > 0

    def test_compress_stream_with_subdirectories(self):
        """Test streaming compression with subdirectory paths."""
        file1 = io.BytesIO(b"Root file")
        file2 = io.BytesIO(b"Nested file")
        output = io.BytesIO()

        compress_stream(
            [("root.txt", file1), ("subdir/nested.txt", file2)],
            output,
            encryption=EncryptionMethod.NONE,
        )

        zip_data = output.getvalue()
        assert len(zip_data) > 0

    def test_compress_stream_large_file(self):
        """Test streaming compression of a large file (chunks properly)."""
        # Create 1MB of data
        large_data = bytes(range(256)) * 4096
        input_file = io.BytesIO(large_data)
        output = io.BytesIO()

        compress_stream(
            [("large.bin", input_file)],
            output,
            encryption=EncryptionMethod.NONE,
        )

        zip_data = output.getvalue()
        assert len(zip_data) > 0

    def test_compress_stream_to_file(self, temp_dir):
        """Test streaming compression directly to a file."""
        input_data = b"File streaming test"
        input_file = io.BytesIO(input_data)
        output_path = os.path.join(temp_dir, "stream_output.zip")

        with open(output_path, "wb") as out:
            compress_stream(
                [("test.txt", input_file)],
                out,
                encryption=EncryptionMethod.NONE,
            )

        assert os.path.exists(output_path)
        assert os.path.getsize(output_path) > 0

    def test_compress_stream_compression_levels(self):
        """Test streaming compression with different levels."""
        data = b"AAAA" * 1000

        for level in [CompressionLevel.STORE, CompressionLevel.FAST, CompressionLevel.BEST]:
            input_file = io.BytesIO(data)
            output = io.BytesIO()

            compress_stream(
                [("data.txt", input_file)],
                output,
                compression_level=level,
                encryption=EncryptionMethod.NONE,
            )

            assert len(output.getvalue()) > 0


class TestDecompressStream:
    """Tests for decompress_stream function (streaming decompression)."""

    def test_decompress_stream_single_file(self):
        """Test streaming decompression of a single file."""
        # First create a ZIP using compress_bytes
        original = [("hello.txt", b"Hello, streaming!")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        # Decompress using stream
        input_stream = io.BytesIO(zip_data)
        result = decompress_stream(input_stream)

        assert len(result) == 1
        assert result[0][0] == "hello.txt"
        assert result[0][1] == b"Hello, streaming!"

    def test_decompress_stream_multiple_files(self):
        """Test streaming decompression of multiple files."""
        original = [
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("file3.txt", b"Content 3"),
        ]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        input_stream = io.BytesIO(zip_data)
        result = decompress_stream(input_stream)

        assert len(result) == 3
        result_dict = {name: data for name, data in result}
        assert result_dict["file1.txt"] == b"Content 1"
        assert result_dict["file2.txt"] == b"Content 2"
        assert result_dict["file3.txt"] == b"Content 3"

    def test_decompress_stream_with_password(self):
        """Test streaming decompression with password."""
        original = [("secret.txt", b"Secret data")]
        password = "StrongPassword123"
        zip_data = compress_bytes(original, password=password)

        input_stream = io.BytesIO(zip_data)
        result = decompress_stream(input_stream, password=password)

        assert len(result) == 1
        assert result[0][1] == b"Secret data"

    def test_decompress_stream_wrong_password(self):
        """Test streaming decompression with wrong password."""
        original = [("secret.txt", b"Secret")]
        zip_data = compress_bytes(original, password="correct")

        input_stream = io.BytesIO(zip_data)
        with pytest.raises((ValueError, IOError)):
            decompress_stream(input_stream, password="wrong")

    def test_decompress_stream_from_file(self, temp_dir):
        """Test streaming decompression from a file."""
        original = [("test.txt", b"File test content")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        zip_path = os.path.join(temp_dir, "test.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_data)

        with open(zip_path, "rb") as f:
            result = decompress_stream(f)

        assert len(result) == 1
        assert result[0][1] == b"File test content"

    def test_decompress_stream_large_file(self):
        """Test streaming decompression of large file."""
        large_data = bytes(range(256)) * 4096  # 1MB
        original = [("large.bin", large_data)]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        input_stream = io.BytesIO(zip_data)
        result = decompress_stream(input_stream)

        assert len(result) == 1
        assert result[0][1] == large_data


class TestStreamRoundTrip:
    """Tests for compress_stream and decompress_stream round-trip scenarios."""

    def test_stream_roundtrip_bytesio(self):
        """Test round-trip using only BytesIO (fully in-memory streaming)."""
        original_data = b"Round trip streaming test"
        input_file = io.BytesIO(original_data)
        zip_output = io.BytesIO()

        # Compress
        compress_stream(
            [("test.txt", input_file)],
            zip_output,
            encryption=EncryptionMethod.NONE,
        )

        # Decompress
        zip_output.seek(0)  # Reset to beginning for reading
        result = decompress_stream(zip_output)

        assert len(result) == 1
        assert result[0][0] == "test.txt"
        assert result[0][1] == original_data

    def test_stream_roundtrip_with_encryption(self):
        """Test round-trip with password encryption."""
        original_data = b"Encrypted streaming data"
        password = "SecurePass123"
        input_file = io.BytesIO(original_data)
        zip_output = io.BytesIO()

        compress_stream(
            [("encrypted.txt", input_file)],
            zip_output,
            password=password,
        )

        zip_output.seek(0)
        result = decompress_stream(zip_output, password=password)

        assert len(result) == 1
        assert result[0][1] == original_data

    def test_stream_roundtrip_multiple_files(self):
        """Test round-trip with multiple files."""
        files_data = [
            ("file1.txt", b"Content 1"),
            ("dir/file2.txt", b"Content 2"),
            ("dir/subdir/file3.bin", bytes(range(256))),
        ]

        zip_output = io.BytesIO()
        input_files = [(name, io.BytesIO(data)) for name, data in files_data]

        compress_stream(
            input_files,
            zip_output,
            encryption=EncryptionMethod.NONE,
        )

        zip_output.seek(0)
        result = decompress_stream(zip_output)

        result_dict = {name: data for name, data in result}
        for name, expected_data in files_data:
            assert result_dict[name] == expected_data

    def test_stream_roundtrip_file_based(self, temp_dir):
        """Test round-trip using actual files."""
        # Create input file
        input_path = os.path.join(temp_dir, "input.txt")
        with open(input_path, "wb") as f:
            f.write(b"File-based streaming test")

        zip_path = os.path.join(temp_dir, "output.zip")

        # Compress from file to file
        with open(input_path, "rb") as infile, open(zip_path, "wb") as outfile:
            compress_stream(
                [("input.txt", infile)],
                outfile,
                encryption=EncryptionMethod.NONE,
            )

        # Decompress from file
        with open(zip_path, "rb") as f:
            result = decompress_stream(f)

        assert len(result) == 1
        assert result[0][1] == b"File-based streaming test"

    def test_stream_interop_with_bytes_functions(self):
        """Test that stream functions work with bytes functions."""
        # Compress with compress_bytes
        original = [("test.txt", b"Interop test")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        # Decompress with decompress_stream
        input_stream = io.BytesIO(zip_data)
        result = decompress_stream(input_stream)

        assert result[0][1] == b"Interop test"

        # Now compress with compress_stream
        input_file = io.BytesIO(b"Reverse interop")
        zip_output = io.BytesIO()
        compress_stream(
            [("reverse.txt", input_file)],
            zip_output,
            encryption=EncryptionMethod.NONE,
        )

        # Decompress with decompress_bytes
        result2 = decompress_bytes(zip_output.getvalue())
        assert result2[0][1] == b"Reverse interop"


class TestOpenZipStream:
    """Tests for open_zip_stream (per-file streaming iterator)."""

    def test_iterate_single_file(self):
        """Test iterating over a single file."""
        zip_data = compress_bytes(
            [("hello.txt", b"Hello, World!")],
            encryption=EncryptionMethod.NONE,
        )

        files = list(open_zip_stream(zip_data))

        assert len(files) == 1
        assert files[0][0] == "hello.txt"
        assert files[0][1] == b"Hello, World!"

    def test_iterate_multiple_files(self):
        """Test iterating over multiple files."""
        original = [
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("file3.txt", b"Content 3"),
        ]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        files = list(open_zip_stream(zip_data))

        assert len(files) == 3
        for orig, result in zip(original, files):
            assert orig[0] == result[0]
            assert orig[1] == result[1]

    def test_iterate_with_password(self):
        """Test iterating with password-protected archive."""
        original = [("secret.txt", b"Secret data")]
        password = "MyPassword123"
        zip_data = compress_bytes(original, password=password)

        files = list(open_zip_stream(zip_data, password=password))

        assert len(files) == 1
        assert files[0][1] == b"Secret data"

    def test_iterate_wrong_password(self):
        """Test iterating with wrong password raises error."""
        zip_data = compress_bytes(
            [("secret.txt", b"Secret")],
            password="correct",
        )

        reader = open_zip_stream(zip_data, password="wrong")
        with pytest.raises((ValueError, IOError)):
            list(reader)

    def test_len(self):
        """Test __len__ returns correct file count."""
        zip_data = compress_bytes(
            [("a.txt", b"A"), ("b.txt", b"B"), ("c.txt", b"C")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)
        assert len(reader) == 3

    def test_namelist(self):
        """Test namelist() returns all filenames."""
        zip_data = compress_bytes(
            [("file1.txt", b"1"), ("subdir/file2.txt", b"2")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)
        names = reader.namelist()

        assert "file1.txt" in names
        assert "subdir/file2.txt" in names

    def test_read_specific_file(self):
        """Test read() extracts a specific file by name."""
        zip_data = compress_bytes(
            [("a.txt", b"AAA"), ("b.txt", b"BBB"), ("c.txt", b"CCC")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)

        assert reader.read("b.txt") == b"BBB"
        assert reader.read("a.txt") == b"AAA"
        assert reader.read("c.txt") == b"CCC"

    def test_read_nonexistent_file(self):
        """Test read() raises error for nonexistent file."""
        zip_data = compress_bytes(
            [("exists.txt", b"data")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)
        with pytest.raises(IOError):
            reader.read("nonexistent.txt")

    def test_file_count_property(self):
        """Test file_count property."""
        zip_data = compress_bytes(
            [("a.txt", b"A"), ("b.txt", b"B")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)
        assert reader.file_count == 2

    def test_iterator_only_yields_once(self):
        """Test that iterator is exhausted after one pass."""
        zip_data = compress_bytes(
            [("a.txt", b"A"), ("b.txt", b"B")],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)

        # First pass
        files1 = list(reader)
        assert len(files1) == 2

        # Second pass should be empty (iterator exhausted)
        files2 = list(reader)
        assert len(files2) == 0

    def test_iterate_large_files_memory_efficient(self):
        """Test that large files are handled one at a time."""
        # Create 3 files of 100KB each
        large_content = b"X" * (100 * 1024)
        original = [
            ("large1.bin", large_content),
            ("large2.bin", large_content),
            ("large3.bin", large_content),
        ]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        # Iterate and verify each file
        count = 0
        for filename, content in open_zip_stream(zip_data):
            assert len(content) == 100 * 1024
            count += 1
            # Content should be garbage collected after this iteration

        assert count == 3

    def test_binary_content(self):
        """Test iterating over binary content."""
        binary_data = bytes(range(256))
        zip_data = compress_bytes(
            [("binary.bin", binary_data)],
            encryption=EncryptionMethod.NONE,
        )

        reader = open_zip_stream(zip_data)
        files = list(reader)

        assert files[0][1] == binary_data

    def test_subdirectories(self):
        """Test iterating over files in subdirectories."""
        original = [
            ("root.txt", b"root"),
            ("dir1/file1.txt", b"file1"),
            ("dir1/dir2/file2.txt", b"file2"),
        ]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        files = list(open_zip_stream(zip_data))

        assert len(files) == 3
        result_dict = {name: data for name, data in files}
        assert result_dict["root.txt"] == b"root"
        assert result_dict["dir1/file1.txt"] == b"file1"
        assert result_dict["dir1/dir2/file2.txt"] == b"file2"


class TestOpenZipStreamFromFile:
    """Tests for open_zip_stream_from_file."""

    def test_from_bytesio(self):
        """Test streaming from BytesIO."""
        original = [("test.txt", b"Test content")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        buf = io.BytesIO(zip_data)
        files = list(open_zip_stream_from_file(buf))

        assert len(files) == 1
        assert files[0][1] == b"Test content"

    def test_from_file(self, temp_dir):
        """Test streaming from actual file."""
        original = [("file.txt", b"File content")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        zip_path = os.path.join(temp_dir, "test.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_data)

        with open(zip_path, "rb") as f:
            files = list(open_zip_stream_from_file(f))

        assert len(files) == 1
        assert files[0][1] == b"File content"

    def test_from_file_with_password(self, temp_dir):
        """Test streaming from file with password."""
        original = [("secret.txt", b"Secret")]
        password = "pass123"
        zip_data = compress_bytes(original, password=password)

        zip_path = os.path.join(temp_dir, "secure.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_data)

        with open(zip_path, "rb") as f:
            files = list(open_zip_stream_from_file(f, password=password))

        assert len(files) == 1
        assert files[0][1] == b"Secret"

    def test_namelist_and_read(self):
        """Test namelist and read on file-based stream."""
        original = [("a.txt", b"AAA"), ("b.txt", b"BBB")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        buf = io.BytesIO(zip_data)
        reader = open_zip_stream_from_file(buf)

        assert len(reader.namelist()) == 2
        assert reader.read("a.txt") == b"AAA"
        assert reader.read("b.txt") == b"BBB"

    def test_returns_zip_file_stream_reader(self):
        """Test that open_zip_stream_from_file returns ZipFileStreamReader."""
        from rustyzipper import ZipFileStreamReader

        zip_data = compress_bytes([("test.txt", b"test")], encryption=EncryptionMethod.NONE)
        buf = io.BytesIO(zip_data)
        reader = open_zip_stream_from_file(buf)

        # Verify it's the file-based reader, not the bytes-based one
        assert type(reader).__name__ == "ZipFileStreamReader"

    def test_file_handle_stays_open(self):
        """Test that file handle is kept open and reused during iteration."""
        original = [("a.txt", b"A"), ("b.txt", b"B"), ("c.txt", b"C")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        buf = io.BytesIO(zip_data)
        reader = open_zip_stream_from_file(buf)

        # Iterate and verify file handle is still usable
        results = []
        for filename, content in reader:
            results.append((filename, content))
            # File handle should still be open and usable

        assert len(results) == 3

        # Reader should still be able to read() after iteration
        assert reader.read("b.txt") == b"B"

    def test_multiple_reads_after_iteration(self):
        """Test multiple read() calls after iteration completes."""
        original = [("x.txt", b"XXX"), ("y.txt", b"YYY"), ("z.txt", b"ZZZ")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        buf = io.BytesIO(zip_data)
        reader = open_zip_stream_from_file(buf)

        # Exhaust the iterator
        list(reader)

        # Should still be able to read individual files
        assert reader.read("x.txt") == b"XXX"
        assert reader.read("y.txt") == b"YYY"
        assert reader.read("z.txt") == b"ZZZ"
        # Can read the same file multiple times
        assert reader.read("x.txt") == b"XXX"

    def test_large_file_streaming(self, temp_dir):
        """Test streaming a large file from disk."""
        # Create 500KB of data (multiple files)
        large_content = b"X" * (100 * 1024)  # 100KB each
        original = [
            ("large1.bin", large_content),
            ("large2.bin", large_content),
            ("large3.bin", large_content),
            ("large4.bin", large_content),
            ("large5.bin", large_content),
        ]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        zip_path = os.path.join(temp_dir, "large.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_data)

        # Stream from file - ZIP data should NOT be loaded into memory
        with open(zip_path, "rb") as f:
            reader = open_zip_stream_from_file(f)

            assert len(reader) == 5

            count = 0
            for filename, content in reader:
                assert len(content) == 100 * 1024
                count += 1

            assert count == 5

    def test_file_count_and_total_entries(self):
        """Test file_count and total_entries properties."""
        original = [("a.txt", b"A"), ("b.txt", b"B")]
        zip_data = compress_bytes(original, encryption=EncryptionMethod.NONE)

        buf = io.BytesIO(zip_data)
        reader = open_zip_stream_from_file(buf)

        assert reader.file_count == 2
        assert reader.total_entries >= 2  # May include directory entries


class TestPyminizipCompatCompressMultiple:
    """Tests for pyminizip compatibility compress_multiple function."""

    def test_compress_multiple_basic(self, temp_dir):
        """Test basic compress_multiple without progress callback."""
        from rustyzipper.compat import pyminizip

        # Create test files
        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(temp_dir, "file2.txt")
        with open(file1, "w") as f:
            f.write("Content of file 1")
        with open(file2, "w") as f:
            f.write("Content of file 2")

        output = os.path.join(temp_dir, "output.zip")

        pyminizip.compress_multiple(
            [file1, file2],
            [],
            output,
            None,
            5,
        )

        assert os.path.exists(output)
        assert os.path.getsize(output) > 0

        # Verify contents by extracting
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir)
        assert os.path.exists(os.path.join(extract_dir, "file1.txt"))
        assert os.path.exists(os.path.join(extract_dir, "file2.txt"))

    def test_compress_multiple_with_password(self, temp_dir):
        """Test compress_multiple with password."""
        from rustyzipper.compat import pyminizip

        # Create test files
        file1 = os.path.join(temp_dir, "secret1.txt")
        file2 = os.path.join(temp_dir, "secret2.txt")
        with open(file1, "w") as f:
            f.write("Secret content 1")
        with open(file2, "w") as f:
            f.write("Secret content 2")

        output = os.path.join(temp_dir, "secure.zip")
        password = "mypassword123"

        pyminizip.compress_multiple(
            [file1, file2],
            [],
            output,
            password,
            5,
        )

        assert os.path.exists(output)

        # Verify by extracting with password
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir, password=password)
        assert os.path.exists(os.path.join(extract_dir, "secret1.txt"))

    def test_compress_multiple_with_prefixes(self, temp_dir):
        """Test compress_multiple with prefix paths."""
        from rustyzipper.compat import pyminizip

        # Create test files
        file1 = os.path.join(temp_dir, "doc1.txt")
        file2 = os.path.join(temp_dir, "doc2.txt")
        with open(file1, "w") as f:
            f.write("Document 1")
        with open(file2, "w") as f:
            f.write("Document 2")

        output = os.path.join(temp_dir, "prefixed.zip")

        pyminizip.compress_multiple(
            [file1, file2],
            ["path1", "path2"],
            output,
            None,
            5,
        )

        assert os.path.exists(output)

        # Verify prefixes by extracting
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir)
        assert os.path.exists(os.path.join(extract_dir, "path1", "doc1.txt"))
        assert os.path.exists(os.path.join(extract_dir, "path2", "doc2.txt"))

    def test_compress_multiple_with_progress_callback(self, temp_dir):
        """Test compress_multiple with progress callback."""
        from rustyzipper.compat import pyminizip

        # Create test files
        files = []
        for i in range(3):
            path = os.path.join(temp_dir, f"file{i}.txt")
            with open(path, "w") as f:
                f.write(f"Content {i}")
            files.append(path)

        output = os.path.join(temp_dir, "progress.zip")

        # Track progress callback calls
        progress_calls = []

        def on_progress(count):
            progress_calls.append(count)

        pyminizip.compress_multiple(
            files,
            [],
            output,
            None,
            5,
            on_progress,
        )

        assert os.path.exists(output)
        # Progress callback should be called with total count
        assert len(progress_calls) == 1
        assert progress_calls[0] == 3

    def test_compress_multiple_progress_callback_with_password(self, temp_dir):
        """Test compress_multiple with both password and progress callback."""
        from rustyzipper.compat import pyminizip

        # Create test files
        file1 = os.path.join(temp_dir, "a.txt")
        file2 = os.path.join(temp_dir, "b.txt")
        with open(file1, "w") as f:
            f.write("File A")
        with open(file2, "w") as f:
            f.write("File B")

        output = os.path.join(temp_dir, "secure_progress.zip")
        password = "secretpass"

        progress_count = []
        pyminizip.compress_multiple(
            [file1, file2],
            [],
            output,
            password,
            5,
            lambda count: progress_count.append(count),
        )

        assert os.path.exists(output)
        assert progress_count == [2]

        # Verify extraction works
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir, password=password)
        assert os.path.exists(os.path.join(extract_dir, "a.txt"))

    def test_compress_multiple_no_progress_callback(self, temp_dir):
        """Test compress_multiple with progress=None (default)."""
        from rustyzipper.compat import pyminizip

        file1 = os.path.join(temp_dir, "test.txt")
        with open(file1, "w") as f:
            f.write("Test content")

        output = os.path.join(temp_dir, "no_progress.zip")

        # Should work without progress callback
        pyminizip.compress_multiple(
            [file1],
            [],
            output,
            None,
            5,
            None,
        )

        assert os.path.exists(output)

    def test_compress_multiple_different_compression_levels(self, temp_dir):
        """Test compress_multiple with different compression levels."""
        from rustyzipper.compat import pyminizip

        file1 = os.path.join(temp_dir, "data.txt")
        # Create compressible content
        with open(file1, "w") as f:
            f.write("AAAA" * 1000)

        sizes = {}
        for level in [1, 5, 9]:
            output = os.path.join(temp_dir, f"level{level}.zip")
            pyminizip.compress_multiple([file1], [], output, None, level)
            sizes[level] = os.path.getsize(output)

        # Higher compression levels should produce smaller (or equal) files
        assert sizes[9] <= sizes[1]

    def test_compress_multiple_empty_prefix_in_list(self, temp_dir):
        """Test compress_multiple with empty strings in prefix list."""
        from rustyzipper.compat import pyminizip

        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(temp_dir, "file2.txt")
        with open(file1, "w") as f:
            f.write("Content 1")
        with open(file2, "w") as f:
            f.write("Content 2")

        output = os.path.join(temp_dir, "mixed_prefix.zip")

        # Mix of empty and non-empty prefixes
        pyminizip.compress_multiple(
            [file1, file2],
            ["", "subdir"],
            output,
            None,
            5,
        )

        assert os.path.exists(output)

        # Verify extraction
        extract_dir = os.path.join(temp_dir, "extracted")
        decompress_file(output, extract_dir)
        assert os.path.exists(os.path.join(extract_dir, "file1.txt"))
        assert os.path.exists(os.path.join(extract_dir, "subdir", "file2.txt"))
