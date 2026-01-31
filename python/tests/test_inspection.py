"""Tests for archive inspection functions."""

import os
import tempfile
from pathlib import Path

import pytest

from rustyzipper import (
    compress_bytes,
    compress_file,
    compress_files,
    compress_directory,
    list_archive,
    list_archive_bytes,
    get_archive_info,
    get_archive_info_bytes,
    get_file_info,
    get_file_info_bytes,
    get_all_file_info,
    get_all_file_info_bytes,
    has_file,
    has_file_bytes,
    FileInfo,
    ArchiveInfo,
    EncryptionMethod,
    CompressionLevel,
)


class TestInfoClasses:
    """Tests for FileInfo and ArchiveInfo classes."""

    def test_file_info_attributes(self, tmp_path: Path) -> None:
        """Test FileInfo class attributes."""
        content = b"Hello, World!"
        zip_data = compress_bytes([("test.txt", content)])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        info = get_file_info(str(archive_path), "test.txt")

        # Check it's the right type
        assert isinstance(info, FileInfo)

        # Check all attributes are accessible
        assert info.name == "test.txt"
        assert info.size == len(content)
        assert info.compressed_size > 0
        assert info.is_dir is False
        assert info.is_encrypted is False
        assert isinstance(info.crc32, int)
        assert isinstance(info.compression_method, str)
        assert info.compression_ratio > 0

    def test_file_info_repr(self, tmp_path: Path) -> None:
        """Test FileInfo __repr__ and __str__."""
        zip_data = compress_bytes([("test.txt", b"Hello")])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        info = get_file_info(str(archive_path), "test.txt")

        # Check repr contains class name and key info
        repr_str = repr(info)
        assert "FileInfo" in repr_str
        assert "test.txt" in repr_str

        # Check str is readable
        str_str = str(info)
        assert "test.txt" in str_str

    def test_archive_info_attributes(self, tmp_path: Path) -> None:
        """Test ArchiveInfo class attributes."""
        zip_data = compress_bytes([
            ("file1.txt", b"Hello"),
            ("file2.txt", b"World"),
        ])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        info = get_archive_info(str(archive_path))

        # Check it's the right type
        assert isinstance(info, ArchiveInfo)

        # Check all attributes are accessible
        assert info.total_entries == 2
        assert info.file_count == 2
        assert info.dir_count == 0
        assert info.total_size == len(b"Hello") + len(b"World")
        assert info.total_compressed_size > 0
        assert info.compression_ratio > 0
        assert info.encryption == "none"
        assert info.has_encrypted_files is False
        assert isinstance(info.comment, str)

    def test_archive_info_repr(self, tmp_path: Path) -> None:
        """Test ArchiveInfo __repr__ and __str__."""
        zip_data = compress_bytes([("test.txt", b"Hello")])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        info = get_archive_info(str(archive_path))

        # Check repr contains class name
        repr_str = repr(info)
        assert "ArchiveInfo" in repr_str

        # Check str is readable
        str_str = str(info)
        assert "1 files" in str_str or "file" in str_str.lower()


class TestListArchive:
    """Tests for list_archive and list_archive_bytes."""

    def test_list_archive_single_file(self, tmp_path: Path) -> None:
        """Test listing a single-file archive."""
        # Create test file
        src_file = tmp_path / "test.txt"
        src_file.write_text("Hello, World!")

        # Create archive
        archive_path = tmp_path / "test.zip"
        compress_file(str(src_file), str(archive_path))

        # List archive
        files = list_archive(str(archive_path))
        assert files == ["test.txt"]

    def test_list_archive_multiple_files(self, tmp_path: Path) -> None:
        """Test listing a multi-file archive."""
        # Create test files
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("Content 1")
        file2.write_text("Content 2")

        # Create archive
        archive_path = tmp_path / "test.zip"
        compress_files(
            [str(file1), str(file2)],
            str(archive_path),
        )

        # List archive
        files = list_archive(str(archive_path))
        assert sorted(files) == ["file1.txt", "file2.txt"]

    def test_list_archive_with_directories(self, tmp_path: Path) -> None:
        """Test listing archive with directory structure."""
        # Create directory structure
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "file.txt").write_text("content")
        sub_dir = src_dir / "subdir"
        sub_dir.mkdir()
        (sub_dir / "nested.txt").write_text("nested content")

        # Create archive
        archive_path = tmp_path / "test.zip"
        compress_directory(str(src_dir), str(archive_path))

        # List archive
        files = list_archive(str(archive_path))
        # Should contain files with paths
        assert any("file.txt" in f for f in files)
        assert any("nested.txt" in f for f in files)

    def test_list_archive_not_found(self) -> None:
        """Test listing non-existent archive."""
        with pytest.raises(Exception):
            list_archive("/nonexistent/archive.zip")

    def test_list_archive_bytes(self, tmp_path: Path) -> None:
        """Test listing archive from bytes."""
        # Create archive in memory
        zip_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("subdir/file2.txt", b"Content 2"),
        ])

        # List archive
        files = list_archive_bytes(zip_data)
        assert sorted(files) == ["file1.txt", "subdir/file2.txt"]


class TestGetArchiveInfo:
    """Tests for get_archive_info and get_archive_info_bytes."""

    def test_get_archive_info_basic(self, tmp_path: Path) -> None:
        """Test getting basic archive info."""
        # Create test file
        src_file = tmp_path / "test.txt"
        content = "Hello, World! This is a test file."
        src_file.write_text(content)

        # Create archive
        archive_path = tmp_path / "test.zip"
        compress_file(str(src_file), str(archive_path))

        # Get info
        info = get_archive_info(str(archive_path))

        assert info.total_entries == 1
        assert info.file_count == 1
        assert info.dir_count == 0
        assert info.total_size == len(content)
        assert info.total_compressed_size > 0
        assert info.compression_ratio > 0  # Can be < 1.0 for small files due to overhead
        assert info.has_encrypted_files is False
        assert info.encryption == "none"

    def test_get_archive_info_encrypted_aes256(self, tmp_path: Path) -> None:
        """Test getting info for AES-256 encrypted archive."""
        # Create test file
        src_file = tmp_path / "test.txt"
        src_file.write_text("Secret content")

        # Create encrypted archive
        archive_path = tmp_path / "test.zip"
        compress_file(
            str(src_file),
            str(archive_path),
            password="secret",
            encryption=EncryptionMethod.AES256,
        )

        # Get info
        info = get_archive_info(str(archive_path))

        assert info.has_encrypted_files is True
        assert info.encryption == "aes256"

    def test_get_archive_info_encrypted_zipcrypto(self, tmp_path: Path) -> None:
        """Test getting info for ZipCrypto encrypted archive."""
        # Create test file
        src_file = tmp_path / "test.txt"
        src_file.write_text("Secret content")

        # Create encrypted archive
        archive_path = tmp_path / "test.zip"
        compress_file(
            str(src_file),
            str(archive_path),
            password="secret",
            encryption=EncryptionMethod.ZIPCRYPTO,
            suppress_warning=True,
        )

        # Get info
        info = get_archive_info(str(archive_path))

        assert info.has_encrypted_files is True
        assert info.encryption == "zipcrypto"

    def test_get_archive_info_multiple_files(self, tmp_path: Path) -> None:
        """Test getting info for multi-file archive."""
        # Create archive in memory
        zip_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2 is longer"),
            ("subdir/file3.txt", b"Nested content"),
        ])

        # Write to file
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Get info
        info = get_archive_info(str(archive_path))

        assert info.file_count == 3
        assert info.total_size == len(b"Content 1") + len(b"Content 2 is longer") + len(b"Nested content")

    def test_get_archive_info_bytes(self) -> None:
        """Test getting archive info from bytes."""
        zip_data = compress_bytes([
            ("file1.txt", b"Hello"),
            ("file2.txt", b"World"),
        ])

        info = get_archive_info_bytes(zip_data)

        assert info.file_count == 2
        assert info.total_entries == 2


class TestGetFileInfo:
    """Tests for get_file_info and get_file_info_bytes."""

    def test_get_file_info_basic(self, tmp_path: Path) -> None:
        """Test getting basic file info."""
        content = b"Hello, World! This is test content."

        # Create archive
        zip_data = compress_bytes([("test.txt", content)])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Get file info
        info = get_file_info(str(archive_path), "test.txt")

        assert info.name == "test.txt"
        assert info.size == len(content)
        assert info.compressed_size > 0
        assert info.is_dir is False
        assert info.is_encrypted is False
        assert info.crc32 > 0
        assert info.compression_ratio > 0

    def test_get_file_info_encrypted(self, tmp_path: Path) -> None:
        """Test getting info for encrypted file."""
        content = b"Secret content"

        # Create encrypted archive
        zip_data = compress_bytes(
            [("secret.txt", content)],
            password="password",
            encryption=EncryptionMethod.AES256,
        )
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Get file info
        info = get_file_info(str(archive_path), "secret.txt")

        assert info.is_encrypted is True

    def test_get_file_info_not_found(self, tmp_path: Path) -> None:
        """Test getting info for non-existent file."""
        # Create archive
        zip_data = compress_bytes([("existing.txt", b"content")])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Try to get non-existent file
        with pytest.raises(Exception):
            get_file_info(str(archive_path), "nonexistent.txt")

    def test_get_file_info_bytes(self) -> None:
        """Test getting file info from bytes."""
        content = b"Test content"
        zip_data = compress_bytes([("test.txt", content)])

        info = get_file_info_bytes(zip_data, "test.txt")

        assert info.name == "test.txt"
        assert info.size == len(content)


class TestGetAllFileInfo:
    """Tests for get_all_file_info and get_all_file_info_bytes."""

    def test_get_all_file_info(self, tmp_path: Path) -> None:
        """Test getting info for all files."""
        # Create archive
        zip_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("subdir/file3.txt", b"Nested"),
        ])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Get all file info
        files = get_all_file_info(str(archive_path))

        assert len(files) == 3
        assert all(isinstance(f, FileInfo) for f in files)
        names = [f.name for f in files]
        assert "file1.txt" in names
        assert "file2.txt" in names
        assert "subdir/file3.txt" in names

    def test_get_all_file_info_bytes(self) -> None:
        """Test getting all file info from bytes."""
        zip_data = compress_bytes([
            ("a.txt", b"A"),
            ("b.txt", b"B"),
        ])

        files = get_all_file_info_bytes(zip_data)

        assert len(files) == 2
        assert all(isinstance(f, FileInfo) for f in files)


class TestHasFile:
    """Tests for has_file and has_file_bytes."""

    def test_has_file_exists(self, tmp_path: Path) -> None:
        """Test checking for existing file."""
        # Create archive
        zip_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("subdir/file2.txt", b"Content 2"),
        ])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        assert has_file(str(archive_path), "file1.txt") is True
        assert has_file(str(archive_path), "subdir/file2.txt") is True

    def test_has_file_not_exists(self, tmp_path: Path) -> None:
        """Test checking for non-existent file."""
        # Create archive
        zip_data = compress_bytes([("file1.txt", b"Content")])
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        assert has_file(str(archive_path), "nonexistent.txt") is False
        assert has_file(str(archive_path), "file1.txt.bak") is False

    def test_has_file_bytes(self) -> None:
        """Test checking for file in bytes archive."""
        zip_data = compress_bytes([
            ("config.json", b"{}"),
            ("data/values.csv", b"a,b,c"),
        ])

        assert has_file_bytes(zip_data, "config.json") is True
        assert has_file_bytes(zip_data, "data/values.csv") is True
        assert has_file_bytes(zip_data, "missing.txt") is False


class TestInspectionIntegration:
    """Integration tests for inspection functions."""

    def test_inspect_before_extract(self, tmp_path: Path) -> None:
        """Test inspecting archive before deciding to extract."""
        # Create a mixed archive
        zip_data = compress_bytes(
            [
                ("readme.txt", b"Read this first"),
                ("data/large.bin", b"X" * 10000),
                ("config.json", b'{"key": "value"}'),
            ],
            password="secret",
            encryption=EncryptionMethod.AES256,
        )
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Step 1: Check archive info
        info = get_archive_info(str(archive_path))
        assert info.file_count == 3
        assert info.has_encrypted_files is True
        assert info.encryption == "aes256"

        # Step 2: List files
        files = list_archive(str(archive_path))
        assert len(files) == 3

        # Step 3: Check for specific file
        assert has_file(str(archive_path), "config.json") is True
        assert has_file(str(archive_path), "missing.txt") is False

        # Step 4: Get specific file info
        config_info = get_file_info(str(archive_path), "config.json")
        assert config_info.size == len(b'{"key": "value"}')

        # Step 5: Get all file info for size analysis
        all_info = get_all_file_info(str(archive_path))
        total_size = sum(f.size for f in all_info if not f.is_dir)
        assert total_size == info.total_size

    def test_compression_statistics(self, tmp_path: Path) -> None:
        """Test using inspection for compression statistics."""
        # Create archive with different compression levels
        content = b"A" * 10000  # Highly compressible

        # Store (no compression)
        store_data = compress_bytes(
            [("data.txt", content)],
            compression_level=CompressionLevel.STORE,
        )

        # Best compression
        best_data = compress_bytes(
            [("data.txt", content)],
            compression_level=CompressionLevel.BEST,
        )

        # Compare compression ratios
        store_info = get_file_info_bytes(store_data, "data.txt")
        best_info = get_file_info_bytes(best_data, "data.txt")

        # Store should have ratio ~1.0, best should be much higher
        assert store_info.compression_ratio < 2.0
        assert best_info.compression_ratio > 10.0  # Highly compressible data

    def test_bytes_vs_file_consistency(self, tmp_path: Path) -> None:
        """Test that bytes and file inspection return consistent results."""
        # Create archive in memory
        zip_data = compress_bytes([
            ("file1.txt", b"Hello"),
            ("file2.txt", b"World"),
        ])

        # Write to file
        archive_path = tmp_path / "test.zip"
        archive_path.write_bytes(zip_data)

        # Compare bytes vs file results
        bytes_list = list_archive_bytes(zip_data)
        file_list = list_archive(str(archive_path))
        assert bytes_list == file_list

        bytes_info = get_archive_info_bytes(zip_data)
        file_info = get_archive_info(str(archive_path))
        assert bytes_info.file_count == file_info.file_count
        assert bytes_info.total_size == file_info.total_size

        bytes_file_info = get_file_info_bytes(zip_data, "file1.txt")
        file_file_info = get_file_info(str(archive_path), "file1.txt")
        assert bytes_file_info.size == file_file_info.size
        assert bytes_file_info.crc32 == file_file_info.crc32
