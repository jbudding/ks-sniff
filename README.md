# KS-Sniff

A high-performance, multithreaded network intrusion detection system (IDS) written in Rust, inspired by Snort.

## Features

- **Multithreaded Architecture**: Leverages all CPU cores for maximum throughput
- **Snort-Compatible Rules**: Parse and execute Snort rule syntax
- **Protocol Support**: Deep packet inspection for TCP, UDP, ICMP, HTTP, HTTPS, and DNS
- **Multiple Output Formats**: JSON, Fast Alert, Syslog, and PCAP
- **High Performance**: 100K+ packets/sec throughput on commodity hardware
- **Memory Safe**: Built with Rust for safety and reliability

## Architecture

```
Main Thread
  ├─> Capture Thread (1) - libpcap packet acquisition
  ├─> Worker Pool (N-2) - Packet decode & rule matching
  ├─> Alert Thread (1) - Alert aggregation & output
  └─> Stats Thread (1) - Performance monitoring
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ks-sniff
cd ks-sniff

# Install libpcap development libraries (see BUILD.md for your OS)
# Alpine: sudo apk add libpcap-dev
# Ubuntu: sudo apt-get install libpcap-dev
# macOS: brew install libpcap

# Build in release mode
cargo build --release

# Install (optional)
cargo install --path .
```

See [BUILD.md](BUILD.md) for detailed build instructions.

### Basic Usage

```bash
# Generate default configuration
./target/release/ks-sniff --generate-config

# Run with default config
sudo ./target/release/ks-sniff

# Specify interface
sudo ./target/release/ks-sniff --interface eth0

# Use custom config
sudo ./target/release/ks-sniff --config /path/to/config.yaml

# Read from PCAP file
./target/release/ks-sniff --pcap-file capture.pcap

# Verbose logging
sudo ./target/release/ks-sniff -vv

# Enable packet decode logging (see detailed protocol info)
sudo ./target/release/ks-sniff --decode-logging

# Combine with BPF filter
sudo ./target/release/ks-sniff -d --bpf-filter "tcp port 80"
```

## Configuration

The configuration file uses YAML format. See `config/ks-sniff.yaml` for a complete example.

### Key Configuration Sections

- **network**: Interface settings, BPF filters, buffer sizes
- **variables**: Network variables ($HOME_NET, $EXTERNAL_NET, etc.)
- **rules**: Rule file paths and enabled groups
- **detection**: Worker thread count, queue sizes
- **outputs**: Alert output formats and destinations
- **logging**: Application logging configuration

## Writing Rules

KS-Sniff uses Snort-compatible rule syntax:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"HTTP GET Request Detected";
    content:"GET";
    http_method;
    sid:1000001;
    rev:1;
)
```

### Supported Rule Options

- `msg`: Alert message
- `content`: Pattern matching (with `nocase`, `offset`, `depth`)
- `pcre`: Perl-compatible regular expressions
- `flow`: Connection state (to_client, to_server, established)
- `flags`: TCP flags (S, A, F, R, P, U)
- `dsize`: Payload size matching
- `sid`/`rev`: Rule identification
- `classtype`: Rule classification
- `priority`: Alert priority

## Performance

Target performance on commodity hardware:

- **Throughput**: 100,000+ packets/second (1 Gbps)
- **Latency**: < 1ms average per packet
- **Memory**: < 500MB with 10,000 rules loaded
- **Scalability**: Linear scaling with CPU cores

## Development Status

KS-Sniff is currently in active development. Implementation is progressing through these phases:

- [x] Phase 1: Foundation (project structure, config, CLI) ✓
- [x] Phase 2: Packet Capture (libpcap integration) ✓
- [x] Phase 3: Protocol Decoders (Ethernet, IP, TCP, UDP, ICMP) ✓
- [ ] Phase 4: Rule Engine (Snort rule parser)
- [ ] Phase 5: Pattern Matching (Aho-Corasick optimization)
- [ ] Phase 6: Detection Pipeline (multithreaded processing)
- [ ] Phase 7: Application Layer (HTTP, HTTPS, DNS parsers)
- [ ] Phase 8: Alerting System (multiple output formats)
- [ ] Phase 9: Statistics & Polish (monitoring, docs)

### Recently Completed

**Phase 3: Protocol Decoders** - Complete packet decoding with:
- Ethernet frame parsing
- IPv4 and IPv6 support
- TCP segment decoding with flag analysis
- UDP datagram parsing
- ICMP packet support
- Layered decoder architecture
- Protocol-specific statistics

**Phase 2: Packet Capture** - Full libpcap integration with:
- Live capture from network interfaces
- PCAP file reading support
- BPF filter support
- Multi-threaded capture with bounded channels
- Comprehensive statistics tracking
- Graceful shutdown handling

## Requirements

- Rust 1.70 or later
- libpcap development libraries
- Linux (primary), macOS (supported), Windows (experimental)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libpcap-dev
```

**macOS:**
```bash
brew install libpcap
```

**Fedora/RHEL:**
```bash
sudo dnf install libpcap-devel
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## Acknowledgments

- Inspired by [Snort](https://www.snort.org/) - the original open-source IDS
- Built with excellent Rust crates: pcap, etherparse, nom, crossbeam, and more
