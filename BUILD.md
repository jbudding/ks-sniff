# Build Instructions

## Prerequisites

KS-Sniff requires libpcap development libraries to compile. Install them before building:

### Alpine Linux
```bash
sudo apk add libpcap-dev

# IMPORTANT: Alpine requires an additional step!
# Create the missing unversioned symlink:
sudo ln -sf /usr/lib/libpcap.so.1 /usr/lib/libpcap.so
```

**Note:** Alpine Linux has a known issue where `libpcap-dev` doesn't create the unversioned `libpcap.so` symlink. See [FIX_ALPINE.md](FIX_ALPINE.md) for details.

### Ubuntu/Debian
```bash
sudo apt-get install libpcap-dev
```

### Fedora/RHEL/CentOS
```bash
sudo dnf install libpcap-devel
```

### macOS
```bash
brew install libpcap
```

### Arch Linux
```bash
sudo pacman -S libpcap
```

## Building

### Debug Build
```bash
cargo build
```

### Release Build (Optimized)
```bash
cargo build --release
```

The release build includes:
- Level 3 optimization (`opt-level = 3`)
- Link-time optimization (`lto = true`)
- Single codegen unit for maximum optimization
- Binary stripping for smaller size

### Running Examples

```bash
# List network interfaces and capture packets (requires root)
sudo cargo run --example simple_capture

# Read from a PCAP file (no root required)
cargo run --example read_pcap -- /path/to/capture.pcap
```

### Running Tests

```bash
cargo test
```

### Running the Main IDS

```bash
# Generate default configuration
cargo run --release -- --generate-config

# Run with default config (requires root for live capture)
sudo cargo run --release

# Run with custom config
sudo cargo run --release -- --config my-config.yaml

# Read from PCAP file (no root required)
cargo run --release -- --pcap-file capture.pcap
```

## Troubleshooting

### "cannot find -lpcap"

This error means libpcap development libraries are not installed. Install them using the commands above.

### "Permission denied" when capturing

Live packet capture requires root/administrator privileges. Either:
- Run with `sudo` on Linux/macOS
- Run as Administrator on Windows
- Use a PCAP file instead with `--pcap-file`

### Cross-compilation

For cross-compilation, ensure libpcap is available for the target architecture:

```bash
# Example: Cross-compile for ARM64
cargo build --release --target aarch64-unknown-linux-gnu
```

## Development

### Code Formatting
```bash
cargo fmt
```

### Linting
```bash
cargo clippy
```

### Documentation
```bash
cargo doc --open
```

### Benchmarks
```bash
cargo bench
```
