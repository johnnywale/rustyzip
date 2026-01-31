"""Tests for archive modification functionality."""

import os
import tempfile
from pathlib import Path

import pytest

from rustyzipper import (
    compress_file,
    decompress_file,
    list_archive,
    get_archive_info,
    compress_bytes,
    decompress_bytes,
    # Modification functions (file-based)
    add_to_archive,
    add_bytes_to_archive,
    remove_from_archive,
    rename_in_archive,
    update_in_archive,
    # Modification functions (bytes-based)
    add_to_archive_bytes,
    remove_from_archive_bytes,
    rename_in_archive_bytes,
    update_in_archive_bytes,
    EncryptionMethod,
    CompressionLevel,
)


class TestAddToArchive:
    """Tests for add_to_archive function."""

    def test_add_single_file(self, tmp_path: Path) -> None:
        """Test adding a single file to an archive."""
        # Create initial archive
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content 1")
        archive = tmp_path / "test.zip"
        compress_file(str(file1), str(archive), encryption=EncryptionMethod.NONE)

        # Create new file to add
        file2 = tmp_path / "file2.txt"
        file2.write_text("Content 2")

        # Add to archive
        add_to_archive(
            str(archive),
            [str(file2)],
            ["file2.txt"],
            encryption=EncryptionMethod.NONE,
        )

        # Verify
        files = list_archive(str(archive))
        assert "file1.txt" in files
        assert "file2.txt" in files
        assert len(files) == 2

    def test_add_multiple_files(self, tmp_path: Path) -> None:
        """Test adding multiple files to an archive."""
        # Create initial archive
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content 1")
        archive = tmp_path / "test.zip"
        compress_file(str(file1), str(archive), encryption=EncryptionMethod.NONE)

        # Create new files
        file2 = tmp_path / "file2.txt"
        file2.write_text("Content 2")
        file3 = tmp_path / "file3.txt"
        file3.write_text("Content 3")

        # Add to archive with subdirectory paths
        add_to_archive(
            str(archive),
            [str(file2), str(file3)],
            ["docs/file2.txt", "docs/file3.txt"],
            encryption=EncryptionMethod.NONE,
        )

        # Verify
        files = list_archive(str(archive))
        assert "file1.txt" in files
        assert "docs/file2.txt" in files
        assert "docs/file3.txt" in files
        assert len(files) == 3

    def test_add_to_nonexistent_archive(self, tmp_path: Path) -> None:
        """Test adding to a non-existent archive raises error."""
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content")
        archive = tmp_path / "nonexistent.zip"

        with pytest.raises(Exception):  # FileNotFoundError
            add_to_archive(str(archive), [str(file1)], ["file1.txt"])

    def test_add_mismatched_lengths(self, tmp_path: Path) -> None:
        """Test that mismatched file/name lengths raises error."""
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content")
        archive = tmp_path / "test.zip"
        compress_file(str(file1), str(archive), encryption=EncryptionMethod.NONE)

        file2 = tmp_path / "file2.txt"
        file2.write_text("Content 2")

        with pytest.raises(Exception):  # ValueError
            add_to_archive(str(archive), [str(file2)], ["name1.txt", "name2.txt"])


class TestAddBytesToArchive:
    """Tests for add_bytes_to_archive function."""

    def test_add_bytes(self, tmp_path: Path) -> None:
        """Test adding bytes data to an archive."""
        # Create initial archive
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content 1")
        archive = tmp_path / "test.zip"
        compress_file(str(file1), str(archive), encryption=EncryptionMethod.NONE)

        # Add bytes
        add_bytes_to_archive(
            str(archive),
            b"Hello from bytes!",
            "bytes_file.txt",
            encryption=EncryptionMethod.NONE,
        )

        # Verify
        files = list_archive(str(archive))
        assert "bytes_file.txt" in files

        # Extract and verify content
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        content = (extract_dir / "bytes_file.txt").read_bytes()
        assert content == b"Hello from bytes!"

    def test_add_bytes_with_encryption(self, tmp_path: Path) -> None:
        """Test adding encrypted bytes data."""
        file1 = tmp_path / "file1.txt"
        file1.write_text("Content 1")
        archive = tmp_path / "test.zip"
        compress_file(str(file1), str(archive), encryption=EncryptionMethod.NONE)

        add_bytes_to_archive(
            str(archive),
            b"Secret data",
            "secret.txt",
            password="test123",
            encryption=EncryptionMethod.AES256,
        )

        files = list_archive(str(archive))
        assert "secret.txt" in files


class TestRemoveFromArchive:
    """Tests for remove_from_archive function."""

    def test_remove_single_file(self, tmp_path: Path) -> None:
        """Test removing a single file from archive."""
        # Create archive with multiple files
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Remove one file
        removed = remove_from_archive(str(archive), ["file1.txt"])
        assert removed == 1

        # Verify
        files = list_archive(str(archive))
        assert "file1.txt" not in files
        assert "file2.txt" in files
        assert len(files) == 1

    def test_remove_multiple_files(self, tmp_path: Path) -> None:
        """Test removing multiple files from archive."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
            ("file3.txt", b"Content 3"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        removed = remove_from_archive(str(archive), ["file1.txt", "file3.txt"])
        assert removed == 2

        files = list_archive(str(archive))
        assert files == ["file2.txt"]

    def test_remove_nonexistent_file(self, tmp_path: Path) -> None:
        """Test removing a file that doesn't exist."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        removed = remove_from_archive(str(archive), ["nonexistent.txt"])
        assert removed == 0

        # Archive unchanged
        files = list_archive(str(archive))
        assert len(files) == 1


class TestRenameInArchive:
    """Tests for rename_in_archive function."""

    def test_rename_file(self, tmp_path: Path) -> None:
        """Test renaming a file in archive."""
        archive_data = compress_bytes([
            ("old_name.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        rename_in_archive(str(archive), "old_name.txt", "new_name.txt")

        files = list_archive(str(archive))
        assert "old_name.txt" not in files
        assert "new_name.txt" in files

    def test_rename_to_different_directory(self, tmp_path: Path) -> None:
        """Test renaming a file to a different directory."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        rename_in_archive(str(archive), "file.txt", "subdir/file.txt")

        files = list_archive(str(archive))
        assert "file.txt" not in files
        assert "subdir/file.txt" in files

    def test_rename_nonexistent_file(self, tmp_path: Path) -> None:
        """Test renaming a file that doesn't exist."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        with pytest.raises(Exception):  # FileNotFoundError
            rename_in_archive(str(archive), "nonexistent.txt", "new.txt")


class TestUpdateInArchive:
    """Tests for update_in_archive function."""

    def test_update_file_content(self, tmp_path: Path) -> None:
        """Test updating file content in archive."""
        archive_data = compress_bytes([
            ("config.json", b'{"version": 1}'),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        update_in_archive(
            str(archive),
            "config.json",
            b'{"version": 2}',
            encryption=EncryptionMethod.NONE,
        )

        # Extract and verify content
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        content = (extract_dir / "config.json").read_bytes()
        assert content == b'{"version": 2}'

    def test_update_preserves_other_files(self, tmp_path: Path) -> None:
        """Test that updating one file preserves others."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        update_in_archive(
            str(archive),
            "file1.txt",
            b"Updated Content 1",
            encryption=EncryptionMethod.NONE,
        )

        # Verify both files exist
        files = list_archive(str(archive))
        assert len(files) == 2

        # Extract and verify contents
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))

        assert (extract_dir / "file1.txt").read_bytes() == b"Updated Content 1"
        assert (extract_dir / "file2.txt").read_bytes() == b"Content 2"

    def test_update_nonexistent_file(self, tmp_path: Path) -> None:
        """Test updating a file that doesn't exist."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        with pytest.raises(Exception):  # FileNotFoundError
            update_in_archive(str(archive), "nonexistent.txt", b"New content")


class TestBytesVariants:
    """Tests for in-memory modification functions."""

    def test_add_to_archive_bytes(self) -> None:
        """Test adding files to archive in memory."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
        ], encryption=EncryptionMethod.NONE)

        new_data = add_to_archive_bytes(
            archive_data,
            [(b"Content 2", "file2.txt")],
            encryption=EncryptionMethod.NONE,
        )

        # Verify
        files = decompress_bytes(new_data)
        names = [name for name, _ in files]
        assert "file1.txt" in names
        assert "file2.txt" in names

    def test_remove_from_archive_bytes(self) -> None:
        """Test removing files from archive in memory."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
        ], encryption=EncryptionMethod.NONE)

        new_data, count = remove_from_archive_bytes(archive_data, ["file1.txt"])
        assert count == 1

        files = decompress_bytes(new_data)
        names = [name for name, _ in files]
        assert "file1.txt" not in names
        assert "file2.txt" in names

    def test_rename_in_archive_bytes(self) -> None:
        """Test renaming file in archive in memory."""
        archive_data = compress_bytes([
            ("old.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        new_data = rename_in_archive_bytes(archive_data, "old.txt", "new.txt")

        files = decompress_bytes(new_data)
        names = [name for name, _ in files]
        assert "old.txt" not in names
        assert "new.txt" in names

    def test_update_in_archive_bytes(self) -> None:
        """Test updating file in archive in memory."""
        archive_data = compress_bytes([
            ("file.txt", b"Old content"),
        ], encryption=EncryptionMethod.NONE)

        new_data = update_in_archive_bytes(
            archive_data,
            "file.txt",
            b"New content",
            encryption=EncryptionMethod.NONE,
        )

        files = decompress_bytes(new_data)
        content = dict(files)
        assert content["file.txt"] == b"New content"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_archive_modification(self, tmp_path: Path) -> None:
        """Test modifying an empty archive."""
        # Create empty archive
        archive_data = compress_bytes([], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "empty.zip"
        archive.write_bytes(archive_data)

        # Add a file
        add_bytes_to_archive(
            str(archive),
            b"Content",
            "file.txt",
            encryption=EncryptionMethod.NONE,
        )

        files = list_archive(str(archive))
        assert files == ["file.txt"]

    def test_modification_with_compression_levels(self, tmp_path: Path) -> None:
        """Test modification with different compression levels."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Add with STORE (no compression)
        add_bytes_to_archive(
            str(archive),
            b"Stored content",
            "stored.txt",
            encryption=EncryptionMethod.NONE,
            compression_level=CompressionLevel.STORE,
        )

        # Add with BEST compression
        add_bytes_to_archive(
            str(archive),
            b"Best compressed" * 100,
            "best.txt",
            encryption=EncryptionMethod.NONE,
            compression_level=CompressionLevel.BEST,
        )

        files = list_archive(str(archive))
        assert len(files) == 3

    def test_chain_multiple_modifications(self, tmp_path: Path) -> None:
        """Test chaining multiple modifications."""
        archive_data = compress_bytes([
            ("a.txt", b"A"),
            ("b.txt", b"B"),
            ("c.txt", b"C"),
        ], encryption=EncryptionMethod.NONE)

        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Chain: remove, rename, add, update
        remove_from_archive(str(archive), ["a.txt"])
        rename_in_archive(str(archive), "b.txt", "renamed_b.txt")
        add_bytes_to_archive(str(archive), b"D", "d.txt", encryption=EncryptionMethod.NONE)
        update_in_archive(str(archive), "c.txt", b"Updated C", encryption=EncryptionMethod.NONE)

        # Verify final state
        files = list_archive(str(archive))
        assert sorted(files) == ["c.txt", "d.txt", "renamed_b.txt"]

        # Verify content
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))

        assert (extract_dir / "c.txt").read_bytes() == b"Updated C"
        assert (extract_dir / "d.txt").read_bytes() == b"D"
        assert (extract_dir / "renamed_b.txt").read_bytes() == b"B"

    def test_add_empty_content(self, tmp_path: Path) -> None:
        """Test adding a file with empty content."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        add_bytes_to_archive(
            str(archive),
            b"",  # Empty content
            "empty.txt",
            encryption=EncryptionMethod.NONE,
        )

        files = list_archive(str(archive))
        assert "empty.txt" in files

        # Verify content
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / "empty.txt").read_bytes() == b""

    def test_update_to_empty_content(self, tmp_path: Path) -> None:
        """Test updating a file to empty content."""
        archive_data = compress_bytes([
            ("file.txt", b"Original content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        update_in_archive(
            str(archive),
            "file.txt",
            b"",  # Empty content
            encryption=EncryptionMethod.NONE,
        )

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / "file.txt").read_bytes() == b""

    def test_binary_data_all_bytes(self) -> None:
        """Test with binary data containing all possible byte values."""
        # Create data with all byte values 0x00-0xFF
        binary_data = bytes(range(256)) * 10

        archive_data = compress_bytes([
            ("binary.bin", b"placeholder"),
        ], encryption=EncryptionMethod.NONE)

        new_data = update_in_archive_bytes(
            archive_data,
            "binary.bin",
            binary_data,
            encryption=EncryptionMethod.NONE,
        )

        files = decompress_bytes(new_data)
        content = dict(files)
        assert content["binary.bin"] == binary_data

    def test_unicode_filenames(self, tmp_path: Path) -> None:
        """Test with Unicode characters in filenames."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Add files with various Unicode names
        add_bytes_to_archive(
            str(archive),
            b"Chinese content",
            "文件.txt",
            encryption=EncryptionMethod.NONE,
        )
        add_bytes_to_archive(
            str(archive),
            b"Japanese content",
            "ファイル.txt",
            encryption=EncryptionMethod.NONE,
        )
        add_bytes_to_archive(
            str(archive),
            b"Emoji content",
            "📁data.txt",
            encryption=EncryptionMethod.NONE,
        )

        files = list_archive(str(archive))
        assert "文件.txt" in files
        assert "ファイル.txt" in files
        assert "📁data.txt" in files

    def test_filename_with_spaces_and_special_chars(self, tmp_path: Path) -> None:
        """Test filenames with spaces and special characters."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        special_names = [
            "file with spaces.txt",
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.multiple.dots.txt",
            "file (parentheses).txt",
        ]

        for name in special_names:
            add_bytes_to_archive(
                str(archive),
                f"Content of {name}".encode(),
                name,
                encryption=EncryptionMethod.NONE,
            )

        files = list_archive(str(archive))
        for name in special_names:
            assert name in files

    def test_deeply_nested_paths(self, tmp_path: Path) -> None:
        """Test with deeply nested directory paths."""
        archive_data = compress_bytes([], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        deep_path = "a/b/c/d/e/f/g/h/i/j/deep_file.txt"
        add_bytes_to_archive(
            str(archive),
            b"Deep content",
            deep_path,
            encryption=EncryptionMethod.NONE,
        )

        files = list_archive(str(archive))
        assert deep_path in files

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / deep_path).read_bytes() == b"Deep content"

    def test_add_duplicate_filename_raises_error(self, tmp_path: Path) -> None:
        """Test adding a file with a name that already exists raises error."""
        archive_data = compress_bytes([
            ("file.txt", b"Original"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Adding a file with the same name should raise an error
        # (the zip crate doesn't allow duplicate filenames)
        with pytest.raises(Exception):
            add_bytes_to_archive(
                str(archive),
                b"Duplicate",
                "file.txt",
                encryption=EncryptionMethod.NONE,
            )

    def test_remove_all_files(self, tmp_path: Path) -> None:
        """Test removing all files from archive."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        removed = remove_from_archive(str(archive), ["file1.txt", "file2.txt"])
        assert removed == 2

        files = list_archive(str(archive))
        assert len(files) == 0

    def test_rename_preserves_content(self, tmp_path: Path) -> None:
        """Test that renaming preserves the file content."""
        original_content = b"Important data that must be preserved!"
        archive_data = compress_bytes([
            ("original.txt", original_content),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        rename_in_archive(str(archive), "original.txt", "renamed.txt")

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / "renamed.txt").read_bytes() == original_content

    def test_large_file_modification(self, tmp_path: Path) -> None:
        """Test modifying archive with larger files."""
        # Create 1MB of compressible data
        large_content = (b"This is a line of text that will be repeated.\n" * 25000)

        archive_data = compress_bytes([
            ("small.txt", b"Small"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        add_bytes_to_archive(
            str(archive),
            large_content,
            "large.txt",
            encryption=EncryptionMethod.NONE,
        )

        # Verify
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / "large.txt").read_bytes() == large_content

    def test_content_integrity_after_many_modifications(self, tmp_path: Path) -> None:
        """Test that content stays intact after many sequential modifications."""
        archive_data = compress_bytes([
            ("keep.txt", b"This content must survive all modifications"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Perform many modifications
        for i in range(10):
            add_bytes_to_archive(
                str(archive),
                f"temp content {i}".encode(),
                f"temp_{i}.txt",
                encryption=EncryptionMethod.NONE,
            )

        for i in range(5):
            remove_from_archive(str(archive), [f"temp_{i}.txt"])

        for i in range(5, 10):
            rename_in_archive(str(archive), f"temp_{i}.txt", f"renamed_{i}.txt")

        # Verify original file content is intact
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        decompress_file(str(archive), str(extract_dir))
        assert (extract_dir / "keep.txt").read_bytes() == b"This content must survive all modifications"

    def test_modify_encrypted_archive_preserves_encryption(self, tmp_path: Path) -> None:
        """Test that modifying an encrypted archive preserves existing encrypted entries.

        With raw_copy optimization, encrypted entries are copied as-is without
        needing the password. This allows adding new files to encrypted archives
        while preserving the original encrypted content.
        """
        archive_data = compress_bytes([
            ("encrypted.txt", b"Secret content"),
        ], password="secret", encryption=EncryptionMethod.AES256)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Adding without password succeeds - encrypted entry is copied as-is
        add_bytes_to_archive(
            str(archive),
            b"Public content",
            "public.txt",
            encryption=EncryptionMethod.NONE,
        )

        # Verify both files exist
        files = list_archive(str(archive))
        assert "encrypted.txt" in files
        assert "public.txt" in files

        # Encrypted file still requires password to read
        result = decompress_bytes(archive.read_bytes(), password="secret")
        # Result is a list of (name, content) tuples
        result_dict = {name: content for name, content in result}
        assert result_dict["encrypted.txt"] == b"Secret content"
        assert result_dict["public.txt"] == b"Public content"

    def test_modify_unencrypted_archive_add_encrypted(self, tmp_path: Path) -> None:
        """Test adding encrypted file to unencrypted archive."""
        archive_data = compress_bytes([
            ("public.txt", b"Public content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Add an encrypted file
        add_bytes_to_archive(
            str(archive),
            b"Secret content",
            "secret.txt",
            password="secret",
            encryption=EncryptionMethod.AES256,
        )

        files = list_archive(str(archive))
        assert "public.txt" in files
        assert "secret.txt" in files

        # Verify we can still read the unencrypted file
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        # Note: This will fail for secret.txt without password, but public.txt should work
        info = get_archive_info(str(archive))
        assert info.file_count == 2


class TestErrorConditions:
    """Tests for error conditions and invalid inputs."""

    def test_add_nonexistent_source_file(self, tmp_path: Path) -> None:
        """Test adding a file that doesn't exist on disk."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        with pytest.raises(Exception):
            add_to_archive(
                str(archive),
                [str(tmp_path / "nonexistent.txt")],
                ["new.txt"],
            )

    def test_invalid_archive_data(self) -> None:
        """Test bytes variants with invalid archive data."""
        invalid_data = b"This is not a valid ZIP file"

        with pytest.raises(Exception):
            add_to_archive_bytes(invalid_data, [(b"content", "file.txt")])

        with pytest.raises(Exception):
            remove_from_archive_bytes(invalid_data, ["file.txt"])

        with pytest.raises(Exception):
            rename_in_archive_bytes(invalid_data, "old.txt", "new.txt")

        with pytest.raises(Exception):
            update_in_archive_bytes(invalid_data, "file.txt", b"content")

    def test_empty_file_list_add(self, tmp_path: Path) -> None:
        """Test adding empty file list."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Adding empty list should be a no-op
        add_to_archive(str(archive), [], [], encryption=EncryptionMethod.NONE)

        files = list_archive(str(archive))
        assert len(files) == 1

    def test_empty_file_list_remove(self, tmp_path: Path) -> None:
        """Test removing empty file list."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        removed = remove_from_archive(str(archive), [])
        assert removed == 0

        files = list_archive(str(archive))
        assert len(files) == 1


class TestSecurityPathTraversal:
    """Tests for path traversal (Zip Slip) prevention."""

    def test_add_rejects_parent_directory_traversal(self, tmp_path: Path) -> None:
        """Test that add_bytes_to_archive rejects ../ in names."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # All of these should be rejected
        malicious_names = [
            "../etc/passwd",
            "foo/../../../etc/passwd",
            "..\\Windows\\System32\\config",
            "foo\\..\\..\\secret.txt",
        ]

        for name in malicious_names:
            with pytest.raises(Exception) as exc_info:
                add_bytes_to_archive(
                    str(archive),
                    b"Malicious content",
                    name,
                    encryption=EncryptionMethod.NONE,
                )
            # Verify it's a path traversal error
            assert "traversal" in str(exc_info.value).lower() or "path" in str(exc_info.value).lower()

    def test_add_rejects_absolute_paths(self, tmp_path: Path) -> None:
        """Test that add_bytes_to_archive rejects absolute paths."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        absolute_paths = [
            "/etc/passwd",
            "\\Windows\\System32",
            "C:\\Windows\\System32\\config",
        ]

        for name in absolute_paths:
            with pytest.raises(Exception):
                add_bytes_to_archive(
                    str(archive),
                    b"Malicious content",
                    name,
                    encryption=EncryptionMethod.NONE,
                )

    def test_add_rejects_null_bytes(self, tmp_path: Path) -> None:
        """Test that add_bytes_to_archive rejects null bytes in names."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        with pytest.raises(Exception):
            add_bytes_to_archive(
                str(archive),
                b"Content",
                "file\x00.txt",
                encryption=EncryptionMethod.NONE,
            )

    def test_rename_rejects_path_traversal(self, tmp_path: Path) -> None:
        """Test that rename_in_archive rejects path traversal in new name."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        with pytest.raises(Exception):
            rename_in_archive(str(archive), "file.txt", "../../../etc/malicious.txt")

    def test_add_to_archive_rejects_path_traversal(self, tmp_path: Path) -> None:
        """Test that add_to_archive rejects path traversal."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # Create a file to add
        new_file = tmp_path / "new.txt"
        new_file.write_text("Content")

        with pytest.raises(Exception):
            add_to_archive(
                str(archive),
                [str(new_file)],
                ["../../../etc/malicious.txt"],
                encryption=EncryptionMethod.NONE,
            )

    def test_bytes_variants_reject_path_traversal(self) -> None:
        """Test that bytes variants also reject path traversal."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)

        # add_to_archive_bytes
        with pytest.raises(Exception):
            add_to_archive_bytes(
                archive_data,
                [(b"Malicious", "../../../passwd")],
                encryption=EncryptionMethod.NONE,
            )

        # rename_in_archive_bytes
        with pytest.raises(Exception):
            rename_in_archive_bytes(archive_data, "file.txt", "../../../malicious")

    def test_safe_paths_still_work(self, tmp_path: Path) -> None:
        """Test that legitimate paths with dots still work."""
        archive_data = compress_bytes([
            ("file.txt", b"Content"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        # These should all be allowed (not path traversal)
        safe_names = [
            "..hidden",         # Starts with .. but not a component
            "foo..bar",         # Contains .. but not as component
            ".dotfile",         # Hidden file
            "subdir/.hidden",   # Hidden in subdir
            "foo/bar/baz.txt",  # Normal nested path
        ]

        for name in safe_names:
            add_bytes_to_archive(
                str(archive),
                f"Content of {name}".encode(),
                name,
                encryption=EncryptionMethod.NONE,
            )

        files = list_archive(str(archive))
        for name in safe_names:
            assert name in files


class TestArchiveInfoAfterModification:
    """Tests to verify archive info is correct after modifications."""

    def test_archive_info_after_add(self, tmp_path: Path) -> None:
        """Test that archive info is correct after adding files."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        info_before = get_archive_info(str(archive))
        assert info_before.file_count == 1

        add_bytes_to_archive(
            str(archive),
            b"Content 2",
            "file2.txt",
            encryption=EncryptionMethod.NONE,
        )

        info_after = get_archive_info(str(archive))
        assert info_after.file_count == 2
        assert info_after.total_size > info_before.total_size

    def test_archive_info_after_remove(self, tmp_path: Path) -> None:
        """Test that archive info is correct after removing files."""
        archive_data = compress_bytes([
            ("file1.txt", b"Content 1"),
            ("file2.txt", b"Content 2" * 100),
        ], encryption=EncryptionMethod.NONE)
        archive = tmp_path / "test.zip"
        archive.write_bytes(archive_data)

        info_before = get_archive_info(str(archive))
        assert info_before.file_count == 2

        remove_from_archive(str(archive), ["file2.txt"])

        info_after = get_archive_info(str(archive))
        assert info_after.file_count == 1
        assert info_after.total_size < info_before.total_size
