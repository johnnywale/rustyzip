# Installation

## Requirements

- Python 3.8 or higher
- No Rust compiler needed (pre-built wheels available)

## Installing from PyPI

The easiest way to install RustyZip is via pip:

```bash
pip install rustyzipper
```

Pre-built wheels are available for:

| Platform | Architectures |
|----------|--------------|
| Linux | x86_64, aarch64, armv7, i686 |
| Windows | x86_64, aarch64 |
| macOS | Universal (x86_64 + ARM64) |

## Installing from Source

If you need to build from source (e.g., for an unsupported platform):

### Prerequisites

1. **Rust toolchain**: Install from [rustup.rs](https://rustup.rs/)
2. **Python development headers**: Usually included with Python installations
3. **maturin**: The build tool for PyO3 projects

### Build Steps

```bash
# Clone the repository
git clone https://github.com/johnnywale/rustyzip.git
cd rustyzip

# Install maturin
pip install maturin

# Build and install in development mode
maturin develop

# Or build a release wheel
maturin build --release
pip install target/wheels/*.whl
```

## Verifying Installation

After installation, verify it works:

```python
import rustyzipper
print(rustyzipper.__version__)
```

## Optional: Building with Features

The library has optional features you can enable when building from source:

```bash
# Disable parallel compression (smaller binary)
maturin build --release --no-default-features

# Windows ARM64 support (automatic on that platform)
maturin build --release --features win-arm64
```

## Troubleshooting

### "No matching distribution found"

If pip can't find a wheel for your platform:

1. Ensure you're using Python 3.8+
2. Try upgrading pip: `pip install --upgrade pip`
3. Build from source (see above)

### Import errors on Windows

If you get DLL errors, ensure you have the [Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) installed.

### Build failures on Linux

Install development packages:

```bash
# Debian/Ubuntu
sudo apt-get install python3-dev build-essential

# Fedora/RHEL
sudo dnf install python3-devel gcc
```
