# In-Memory Operations

RustyZip supports compressing and decompressing data entirely in memory, without touching the filesystem. This is ideal for web applications, APIs, and data pipelines.

## Compressing to Bytes

Use `compress_bytes()` to create a ZIP archive in memory:

```python
from rustyzipper import compress_bytes, EncryptionMethod

# Create files as (name, content) tuples
files = [
    ("hello.txt", b"Hello, World!"),
    ("data.json", b'{"key": "value", "count": 42}'),
    ("subdir/nested.txt", b"Nested file content"),
]

# Compress to bytes
zip_data = compress_bytes(files, password="secret")

# Use the data however you need
# - Send over HTTP
# - Store in a database
# - Write to file
with open("archive.zip", "wb") as f:
    f.write(zip_data)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `files` | List[Tuple[str, bytes]] | required | List of (filename, content) tuples |
| `password` | str | None | Password for encryption |
| `encryption` | EncryptionMethod | AES256 | Encryption method |
| `compression_level` | CompressionLevel | DEFAULT | Compression level |
| `suppress_warning` | bool | False | Suppress weak encryption warnings |

## Decompressing from Bytes

Use `decompress_bytes()` to extract files from ZIP data in memory:

```python
from rustyzipper import decompress_bytes, SecurityPolicy

# Decompress with default security
files = decompress_bytes(zip_data, password="secret")

for filename, content in files:
    print(f"{filename}: {len(content)} bytes")
    # Process the content...

# With custom security policy
policy = SecurityPolicy(max_size="1GB", max_ratio=500)
files = decompress_bytes(zip_data, password="secret", policy=policy)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | bytes | required | ZIP archive data |
| `password` | str | None | Password for encrypted archives |
| `policy` | SecurityPolicy | None | Security policy |

### Return Value

Returns `List[Tuple[str, bytes]]` - a list of (filename, content) tuples.

## Web Application Example

### Flask API

```python
from flask import Flask, request, send_file
from rustyzipper import compress_bytes, decompress_bytes
import io

app = Flask(__name__)

@app.route("/download-bundle", methods=["POST"])
def download_bundle():
    """Create a ZIP of requested files and return it."""
    file_names = request.json["files"]

    # Gather file contents
    files = []
    for name in file_names:
        content = get_file_content(name)  # Your function
        files.append((name, content))

    # Compress in memory
    zip_data = compress_bytes(files, password=request.json.get("password"))

    return send_file(
        io.BytesIO(zip_data),
        mimetype="application/zip",
        as_attachment=True,
        download_name="bundle.zip"
    )

@app.route("/upload", methods=["POST"])
def upload():
    """Accept a ZIP upload and process its contents."""
    zip_data = request.files["archive"].read()
    password = request.form.get("password")

    # Decompress in memory with strict security
    from rustyzipper import SecurityPolicy
    policy = SecurityPolicy.strict(max_size="50MB")

    files = decompress_bytes(zip_data, password=password, policy=policy)

    results = []
    for filename, content in files:
        result = process_file(filename, content)  # Your function
        results.append(result)

    return {"processed": len(results)}
```

### FastAPI Example

```python
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import StreamingResponse
from rustyzipper import compress_bytes, decompress_bytes, SecurityPolicy
import io

app = FastAPI()

@app.post("/compress")
async def compress_files(files: list[UploadFile], password: str = None):
    """Compress uploaded files into a ZIP."""
    file_data = []
    for f in files:
        content = await f.read()
        file_data.append((f.filename, content))

    zip_data = compress_bytes(file_data, password=password)

    return StreamingResponse(
        io.BytesIO(zip_data),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=archive.zip"}
    )

@app.post("/extract")
async def extract_archive(archive: UploadFile, password: str = None):
    """Extract and list contents of uploaded ZIP."""
    zip_data = await archive.read()

    try:
        policy = SecurityPolicy.strict()
        files = decompress_bytes(zip_data, password=password, policy=policy)
        return {"files": [{"name": n, "size": len(c)} for n, c in files]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## Database Storage

Store compressed data directly in your database:

```python
from rustyzipper import compress_bytes, decompress_bytes
import sqlite3

def store_documents(db: sqlite3.Connection, doc_id: str, files: list):
    """Store multiple documents as a compressed blob."""
    file_data = [(f["name"], f["content"]) for f in files]
    zip_data = compress_bytes(file_data, password="db_secret")

    db.execute(
        "INSERT INTO documents (id, data) VALUES (?, ?)",
        (doc_id, zip_data)
    )

def retrieve_documents(db: sqlite3.Connection, doc_id: str) -> list:
    """Retrieve and decompress documents."""
    cursor = db.execute(
        "SELECT data FROM documents WHERE id = ?",
        (doc_id,)
    )
    row = cursor.fetchone()
    if not row:
        return []

    files = decompress_bytes(row[0], password="db_secret")
    return [{"name": n, "content": c} for n, c in files]
```

## Memory Considerations

When working with in-memory operations:

1. **Input data stays in memory**: The entire ZIP data must fit in memory
2. **Decompressed files are returned as a list**: All extracted files are held in memory
3. **Use streaming for large files**: See [Streaming Guide](streaming.md) for memory-efficient alternatives

For very large archives or when memory is constrained, consider using streaming operations instead.
