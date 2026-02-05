//! Comprehensive tests for stream/reader.rs and stream/writer.rs to achieve 100% coverage
//!
//! These tests require embedding Python and only run when `extension-module` is disabled.
//! When building as a Python extension (maturin build), use `--features extension-module`.

#![cfg(not(feature = "extension-module"))]

use pyo3::ffi::c_str;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use rustyzip::stream::reader::{PyReadSeeker, PyReader};
use rustyzip::stream::writer::{PyWriteSeeker, PyWriter};
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};

// ============================================================================
// Helper Functions to Create Mock Python File Objects
// ============================================================================

fn create_mock_readable_file(py: Python, data: Vec<u8>) -> PyResult<Bound<PyAny>> {
    let code = r#"
class MockReadable:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, size):
        result = self.data[self.pos:self.pos + size]
        self.pos += len(result)
        return bytes(result)

    def seek(self, offset, whence=0):
        if whence == 0:  # SEEK_SET
            self.pos = offset
        elif whence == 1:  # SEEK_CUR
            self.pos += offset
        elif whence == 2:  # SEEK_END
            self.pos = len(self.data) + offset
        self.pos = max(0, min(self.pos, len(self.data)))
        return self.pos
"#;

    let code_cstr = CString::new(code).unwrap();
    let module = PyModule::from_code(
        py,
        code_cstr.as_c_str(),
        c_str!("test_module.py"),
        c_str!("test_module"),
    )?;
    let mock_class = module.getattr("MockReadable")?;
    mock_class.call1((data,))
}

fn create_mock_writable_file(py: Python) -> PyResult<(Bound<PyAny>, Bound<PyAny>)> {
    let code = r#"
class MockWritable:
    def __init__(self):
        self.data = bytearray()
        self.pos = 0
        self.flush_count = 0

    def write(self, data):
        bytes_data = bytes(data)
        if self.pos >= len(self.data):
            self.data.extend(bytes_data)
            self.pos = len(self.data)
        else:
            for i, byte in enumerate(bytes_data):
                if self.pos + i < len(self.data):
                    self.data[self.pos + i] = byte
                else:
                    self.data.append(byte)
            self.pos += len(bytes_data)
        return len(bytes_data)

    def flush(self):
        self.flush_count += 1

    def seek(self, offset, whence=0):
        if whence == 0:  # SEEK_SET
            self.pos = offset
        elif whence == 1:  # SEEK_CUR
            self.pos += offset
        elif whence == 2:  # SEEK_END
            self.pos = len(self.data) + offset
        self.pos = max(0, self.pos)
        return self.pos

    def get_data(self):
        return bytes(self.data)
"#;

    let code_cstr = CString::new(code).unwrap();
    let module = PyModule::from_code(
        py,
        code_cstr.as_c_str(),
        c_str!("test_module.py"),
        c_str!("test_module"),
    )?;
    let mock_class = module.getattr("MockWritable")?;
    let instance = mock_class.call0()?;
    Ok((instance.clone(), instance))
}

// ============================================================================
// PyReader Tests
// ============================================================================

#[test]
fn test_pyreader_new_default_buffer() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let _reader = PyReader::new(py_file, None);
        // Buffer size is tested indirectly through read behavior
    });
}

#[test]
fn test_pyreader_new_custom_buffer() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let _reader = PyReader::new(py_file, Some(1024));
        // Buffer size is tested indirectly through read behavior
    });
}

#[test]
fn test_pyreader_read_small_buffer() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data.clone()).unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 5];

        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5]);
    });
}

#[test]
fn test_pyreader_read_multiple_calls() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data.clone()).unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 3];

        // First read
        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[1, 2, 3]);

        // Second read
        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[4, 5, 6]);

        // Third read
        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[7, 8, 9]);
    });
}

#[test]
fn test_pyreader_read_empty_file() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 10];

        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 0);
    });
}

#[test]
fn test_pyreader_read_with_custom_buffer_size() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data).unwrap();

        // Buffer size of 4, but request 10 bytes
        let mut reader = PyReader::new(py_file, Some(4));
        let mut buf = [0u8; 10];

        // Should only read 4 bytes (buffer_size limit)
        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    });
}

// ============================================================================
// PyReader Error Tests
// ============================================================================

#[test]
fn test_pyreader_error_read_method_fails() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class FailingReadable:
    def read(self, size):
        raise IOError("Read failed")
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("FailingReadable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 10];

        let result = reader.read(&mut buf);
        assert!(result.is_err());
    });
}

#[test]
fn test_pyreader_error_returns_too_many_bytes_pybytes() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class BadReadable:
    def read(self, size):
        # Return more bytes than requested
        return b"x" * (size + 10)
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("BadReadable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 10];

        let result = reader.read(&mut buf);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    });
}

#[test]
fn test_pyreader_error_returns_too_many_bytes_memoryview() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class BadMemoryViewReadable:
    def read(self, size):
        # Return memoryview with more bytes than requested
        data = bytearray(b"x" * (size + 10))
        return memoryview(data)
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("BadMemoryViewReadable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 10];

        let result = reader.read(&mut buf);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        }
    });
}

#[test]
fn test_pyreader_error_returns_non_bytes() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class InvalidReadable:
    def read(self, size):
        # Return something that's not bytes
        return "not bytes"
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("InvalidReadable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 10];

        let result = reader.read(&mut buf);
        assert!(result.is_err());
    });
}

#[test]
fn test_pyreader_with_memoryview() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class MemoryViewReadable:
    def __init__(self, data):
        self.data = bytearray(data)
        self.pos = 0

    def read(self, size):
        result = self.data[self.pos:self.pos + size]
        self.pos += len(result)
        return memoryview(result)
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("MemoryViewReadable").unwrap();
        let py_file = mock_class.call1((vec![1u8, 2, 3, 4, 5],)).unwrap();

        let mut reader = PyReader::new(py_file, None);
        let mut buf = [0u8; 3];

        let bytes_read = reader.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[1, 2, 3]);
    });
}

// ============================================================================
// PyReadSeeker Tests
// ============================================================================

#[test]
fn test_pyreadseeker_new() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let _seeker = PyReadSeeker::new(py_file, None);
    });
}

#[test]
fn test_pyreadseeker_read() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);
        let mut buf = [0u8; 5];

        let bytes_read = seeker.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5]);
    });
}

#[test]
fn test_pyreadseeker_seek_start() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);

        // Seek to position 5
        let new_pos = seeker.seek(SeekFrom::Start(5)).unwrap();
        assert_eq!(new_pos, 5);

        // Read from new position
        let mut buf = [0u8; 3];
        let bytes_read = seeker.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[6, 7, 8]);
    });
}

#[test]
fn test_pyreadseeker_seek_current() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);

        // Read 3 bytes (pos = 3)
        let mut buf = [0u8; 3];
        seeker.read(&mut buf).unwrap();

        // Seek forward 2 bytes from current position
        let new_pos = seeker.seek(SeekFrom::Current(2)).unwrap();
        assert_eq!(new_pos, 5);

        // Read from new position
        let bytes_read = seeker.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..], &[6, 7, 8]);
    });
}

#[test]
fn test_pyreadseeker_seek_end() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_file = create_mock_readable_file(py, data).unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);

        // Seek to 3 bytes before end
        let new_pos = seeker.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(new_pos, 7);

        // Read from new position
        let mut buf = [0u8; 5];
        let bytes_read = seeker.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3);
        assert_eq!(&buf[..3], &[8, 9, 10]);
    });
}

// ============================================================================
// PyReadSeeker Error Tests
// ============================================================================

#[test]
fn test_pyreadseeker_error_seek_fails() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class FailingSeekable:
    def read(self, size):
        return b"test"

    def seek(self, offset, whence=0):
        raise IOError("Seek failed")
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("FailingSeekable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);

        let result = seeker.seek(SeekFrom::Start(10));
        assert!(result.is_err());
    });
}

#[test]
fn test_pyreadseeker_error_seek_returns_invalid() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class BadSeekable:
    def read(self, size):
        return b"test"

    def seek(self, offset, whence=0):
        return "not a number"
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("BadSeekable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut seeker = PyReadSeeker::new(py_file, None);

        let result = seeker.seek(SeekFrom::Start(10));
        assert!(result.is_err());
    });
}

// ============================================================================
// PyWriter Tests
// ============================================================================

#[test]
fn test_pywriter_new() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, _) = create_mock_writable_file(py).unwrap();
        let _writer = PyWriter::new(py_file);
    });
}

#[test]
fn test_pywriter_write_simple() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_file);

        let data = b"Hello, World!";
        let bytes_written = writer.write(data).unwrap();

        assert_eq!(bytes_written, 13);

        // Verify data was written
        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], data);
    });
}

#[test]
fn test_pywriter_write_multiple() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_file);

        writer.write(b"Hello, ").unwrap();
        writer.write(b"World!").unwrap();

        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], b"Hello, World!");
    });
}

#[test]
fn test_pywriter_write_empty() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_file);

        let bytes_written = writer.write(b"").unwrap();
        assert_eq!(bytes_written, 0);

        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(written_data.len(), 0);
    });
}

#[test]
fn test_pywriter_flush() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_file);

        writer.write(b"test").unwrap();
        writer.flush().unwrap();

        // Check flush was called
        let flush_count: i32 = py_instance
            .getattr("flush_count")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(flush_count, 1);
    });
}

#[test]
fn test_pywriter_flush_without_method() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        // Create a simple object without flush method
        let code = r#"
class SimpleWritable:
    def __init__(self):
        self.data = bytearray()

    def write(self, data):
        self.data.extend(bytes(data))
        return len(data)
"#;
        let code_cstr = CString::new(code).unwrap();
        let module = PyModule::from_code(
            py,
            code_cstr.as_c_str(),
            c_str!("test_module.py"),
            c_str!("test_module"),
        )
        .unwrap();
        let mock_class = module.getattr("SimpleWritable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut writer = PyWriter::new(py_file);

        // Should not error even without flush method
        writer.write(b"test").unwrap();
        writer.flush().unwrap();
    });
}

// ============================================================================
// PyWriter Error Tests
// ============================================================================

#[test]
fn test_pywriter_error_write_fails() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class FailingWritable:
    def write(self, data):
        raise IOError("Write failed")
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("FailingWritable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut writer = PyWriter::new(py_file);

        let result = writer.write(b"test");
        assert!(result.is_err());
    });
}

#[test]
fn test_pywriter_error_write_returns_invalid() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class BadWritable:
    def write(self, data):
        return "not a number"
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("BadWritable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut writer = PyWriter::new(py_file);

        let result = writer.write(b"test");
        assert!(result.is_err());
    });
}

#[test]
fn test_pywriter_error_flush_fails() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class FailingFlush:
    def write(self, data):
        return len(data)

    def flush(self):
        raise IOError("Flush failed")
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("FailingFlush").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut writer = PyWriter::new(py_file);

        writer.write(b"test").unwrap();
        let result = writer.flush();
        assert!(result.is_err());
    });
}

#[test]
fn test_pywriter_error_hasattr_check() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        // This tests the hasattr error path which might occur in rare cases
        let code = r#"
class MinimalWritable:
    def write(self, data):
        return len(data)
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("MinimalWritable").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut writer = PyWriter::new(py_file);

        // Should succeed even though there's no flush method
        writer.write(b"test").unwrap();
        writer.flush().unwrap(); // Should not error
    });
}

// ============================================================================
// PyWriteSeeker Tests
// ============================================================================

#[test]
fn test_pywriteseeker_new() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, _) = create_mock_writable_file(py).unwrap();
        let _seeker = PyWriteSeeker::new(py_file);
    });
}

#[test]
fn test_pywriteseeker_write() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut seeker = PyWriteSeeker::new(py_file);

        let data = b"Hello, Seeker!";
        let bytes_written = seeker.write(data).unwrap();

        assert_eq!(bytes_written, 14);

        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], data);
    });
}

#[test]
fn test_pywriteseeker_flush() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut seeker = PyWriteSeeker::new(py_file);

        seeker.write(b"test").unwrap();
        seeker.flush().unwrap();

        let flush_count: i32 = py_instance
            .getattr("flush_count")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(flush_count, 1);
    });
}

#[test]
fn test_pywriteseeker_seek_start() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut seeker = PyWriteSeeker::new(py_file);

        // Write some data
        seeker.write(b"Hello, World!").unwrap();

        // Seek to position 7
        let new_pos = seeker.seek(SeekFrom::Start(7)).unwrap();
        assert_eq!(new_pos, 7);

        // Overwrite "World" with "Seeker"
        seeker.write(b"Seeker!").unwrap();

        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], b"Hello, Seeker!");
    });
}

#[test]
fn test_pywriteseeker_seek_current() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, _) = create_mock_writable_file(py).unwrap();
        let mut seeker = PyWriteSeeker::new(py_file);

        // Write 5 bytes (pos = 5)
        seeker.write(b"Hello").unwrap();

        // Seek forward 2 bytes from current position
        let new_pos = seeker.seek(SeekFrom::Current(2)).unwrap();
        assert_eq!(new_pos, 7);
    });
}

#[test]
fn test_pywriteseeker_seek_end() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, _) = create_mock_writable_file(py).unwrap();
        let mut seeker = PyWriteSeeker::new(py_file);

        // Write some data
        seeker.write(b"Hello, World!").unwrap();

        // Seek to 3 bytes before end
        let new_pos = seeker.seek(SeekFrom::End(-3)).unwrap();
        assert_eq!(new_pos, 10);

        // Overwrite last 3 bytes
        seeker.write(b"!!!").unwrap();
    });
}

// ============================================================================
// PyWriteSeeker Error Tests
// ============================================================================

#[test]
fn test_pywriteseeker_error_seek_fails() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class FailingSeekableWriter:
    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def seek(self, offset, whence=0):
        raise IOError("Seek failed")
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("FailingSeekableWriter").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut seeker = PyWriteSeeker::new(py_file);

        let result = seeker.seek(SeekFrom::Start(10));
        assert!(result.is_err());
    });
}

#[test]
fn test_pywriteseeker_error_seek_returns_invalid() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let code = r#"
class BadSeekableWriter:
    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def seek(self, offset, whence=0):
        return "not a number"
"#;
        let code_cstr = CString::new(code).unwrap();
        let module =
            PyModule::from_code(py, code_cstr.as_c_str(), c_str!("test.py"), c_str!("test"))
                .unwrap();
        let mock_class = module.getattr("BadSeekableWriter").unwrap();
        let py_file = mock_class.call0().unwrap();

        let mut seeker = PyWriteSeeker::new(py_file);

        let result = seeker.seek(SeekFrom::Start(10));
        assert!(result.is_err());
    });
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_reader_writer_roundtrip() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        // Write data
        let (py_write_file, py_write_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_write_file);

        let original_data = b"Test roundtrip data";
        writer.write(original_data).unwrap();

        // Get written data
        let written_data: Vec<u8> = py_write_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();

        // Read it back
        let py_read_file = create_mock_readable_file(py, written_data).unwrap();
        let mut reader = PyReader::new(py_read_file, None);

        let mut buf = vec![0u8; original_data.len()];
        let bytes_read = reader.read(&mut buf).unwrap();

        assert_eq!(bytes_read, original_data.len());
        assert_eq!(&buf[..], original_data);
    });
}

#[test]
fn test_seek_read_write_integration() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        // Create data to read
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let py_read_file = create_mock_readable_file(py, data.clone()).unwrap();
        let mut reader = PyReadSeeker::new(py_read_file, None);

        // Create writer
        let (py_write_file, py_write_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriteSeeker::new(py_write_file);

        // Read from position 5, write to writer
        reader.seek(SeekFrom::Start(5)).unwrap();
        let mut buf = [0u8; 3];
        reader.read(&mut buf).unwrap();
        writer.write(&buf).unwrap();

        // Verify
        let written_data: Vec<u8> = py_write_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], &[6, 7, 8]);
    });
}

#[test]
fn test_large_buffer_read() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        // Create larger data
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let py_file = create_mock_readable_file(py, data.clone()).unwrap();

        let mut reader = PyReader::new(py_file, Some(128));
        let mut buf = vec![0u8; 1000];

        let mut total_read = 0;
        while total_read < 1000 {
            let bytes_read = reader.read(&mut buf[total_read..]).unwrap();
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        assert_eq!(total_read, 1000);
        assert_eq!(&buf[..], &data[..]);
    });
}

#[test]
fn test_large_buffer_write() {
    pyo3::Python::initialize();

    Python::attach(|py| {
        let (py_file, py_instance) = create_mock_writable_file(py).unwrap();
        let mut writer = PyWriter::new(py_file);

        // Write large data in chunks
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let mut written = 0;

        while written < data.len() {
            let chunk_size = std::cmp::min(128, data.len() - written);
            let bytes_written = writer.write(&data[written..written + chunk_size]).unwrap();
            written += bytes_written;
        }

        let written_data: Vec<u8> = py_instance
            .call_method0("get_data")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(&written_data[..], &data[..]);
    });
}
