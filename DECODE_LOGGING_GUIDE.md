# Wireshark-Style Decode Logging Guide

## Overview

ks-sniff now supports Wireshark-style detailed packet decode logging! When enabled, each captured packet is displayed with comprehensive protocol information, similar to how Wireshark dissects packets.

## Quick Start

### Enable Decode Logging

There are three ways to enable Wireshark-style decode logging:

#### 1. CLI Flag (Recommended)
```bash
# Short form
sudo ./target/release/ks-sniff -d

# Long form
sudo ./target/release/ks-sniff --decode-logging
```

#### 2. Configuration File
Edit `config/ks-sniff.yaml`:
```yaml
logging:
  decode_logging: true
```

Then run:
```bash
sudo ./target/release/ks-sniff --config config/ks-sniff.yaml
```

#### 3. Environment Variable
```bash
RUST_LOG=debug sudo ./target/release/ks-sniff
```

**Priority Order**: RUST_LOG > CLI flag > config file

## Output Format

When decode logging is enabled, you'll see detailed output for each packet:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Frame 1: 54 bytes captured
  Arrival Time: 2024-01-07 14:30:45.123456
  Frame Length: 54 bytes
  Capture Length: 54 bytes

Ethernet II
  Destination: 00:11:22:33:44:55
  Source:      aa:bb:cc:dd:ee:ff
  Type:        0x0800 (IPv4)

Internet Protocol Version 4
  Version: 4
  Header Length: 20 bytes
  Total Length: 40
  Protocol: 6 (TCP)
  Time to Live: 64
  Source Address: 192.168.1.100
  Destination Address: 192.168.1.1

Transmission Control Protocol
  Source Port: 1234
  Destination Port: 80
  Sequence Number: 1
  Acknowledgment Number: 0
  Flags: 0x02
      0 .... = Reserved
      .0 ... = Urgent
      ..0 .. = Acknowledgment
      ...0 . = Push
      .... 0 = Reset
      .... .1 = Syn
      .... ..0 = Fin
  Window: 8192

Data (10 bytes)
  0000  48 65 6c 6c 6f 20 57 6f  72 6c 64                 Hello World

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Supported Protocols

### Layer 2 (Data Link)
- **Ethernet II**: MAC addresses, EtherType

### Layer 3 (Network)
- **IPv4**: Addresses, protocol, TTL, header length, total length
- **IPv6**: Addresses, next header, hop limit, payload length

### Layer 4 (Transport)
- **TCP**: Ports, sequence/ack numbers, flags (detailed bit breakdown), window size, payload
- **UDP**: Ports, length, payload
- **ICMP/ICMPv6**: Type, code, payload

### Hex Dump
- First 256 bytes of payload data
- Hex representation with ASCII view
- Wireshark-style formatting with 16 bytes per line

## Usage Examples

### Basic Live Capture with Decode Logging
```bash
sudo ./target/release/ks-sniff -d
```

### Capture on Specific Interface
```bash
sudo ./target/release/ks-sniff -d --interface eth0
```

### With BPF Filter
```bash
sudo ./target/release/ks-sniff -d --bpf-filter 'tcp port 80'
```

### Read PCAP File
```bash
./target/release/ks-sniff -d --pcap-file capture.pcap
```

### Combined with Verbose Logging
```bash
# -vv adds additional debug information
sudo ./target/release/ks-sniff -d -vv
```

### Trace-Level Logging (Very Detailed)
```bash
# Shows both Wireshark-style output AND individual field traces
sudo ./target/release/ks-sniff -d -vvv
```

## Output Modes

### Normal Mode (Default)
Without `-d`, you see only summary statistics:
```
Stats: captured=1000, decoded=998, TCP=850, UDP=120, ICMP=28, dropped=0, bytes=524288
```

### Decode Mode (with -d)
With `-d`, you see detailed Wireshark-style dissection for each packet plus statistics.

### Quiet Mode
```bash
# Suppress most output, show only errors
sudo ./target/release/ks-sniff -d --quiet
```

## Performance Notes

- **Overhead**: Decode logging adds ~5-10% overhead
- **Log volume**: High packet rates generate significant log output
- **Recommendation**: Use decode logging for:
  - Debugging network issues
  - Understanding traffic patterns
  - Developing/testing detection rules
  - Learning packet structure
  - Analyzing specific traffic (use BPF filters)

- **Avoid** decode logging for:
  - Production monitoring (use summary stats instead)
  - High-speed captures (>100K packets/sec)
  - Long-running captures (log files grow quickly)

## Troubleshooting

### Decode Logging Not Working?

1. **Check if RUST_LOG is set**:
   ```bash
   echo $RUST_LOG
   # If set, it overrides the flag
   unset RUST_LOG
   ```

2. **Verify the flag is recognized**:
   ```bash
   ./target/release/ks-sniff --help | grep decode
   ```
   Should show:
   ```
   -d, --decode-logging  Enable packet decode logging to console
   ```

3. **Check startup output**:
   You should see:
   ```
   ✓ Decode logging ENABLED (via CLI flag)
     Log filter: ks_sniff=debug
   ```

4. **See TROUBLESHOOTING.md** for more detailed debugging steps.

## Examples

### Run the Demo Example
```bash
cargo run --example decode_logging_demo --release
```

This example demonstrates:
- Wireshark-style detailed output
- Compact summary format
- Usage instructions

### Capture HTTP Traffic
```bash
sudo ./target/release/ks-sniff -d --bpf-filter 'tcp port 80'
```

### Capture DNS Traffic
```bash
sudo ./target/release/ks-sniff -d --bpf-filter 'udp port 53'
```

### Capture ICMP (Ping)
```bash
# In one terminal:
sudo ./target/release/ks-sniff -d --bpf-filter 'icmp'

# In another terminal:
ping -c 3 8.8.8.8
```

## Format Comparison

### Before (Individual Debug Lines)
```
[DEBUG] Ethernet: aa:bb:cc:dd:ee:ff -> 00:11:22:33:44:55, EtherType: 0x0800
[DEBUG] IPv4: 192.168.1.100 -> 192.168.1.1, Protocol: 6
[DEBUG] TCP: 192.168.1.100:1234 -> 192.168.1.1:80, Flags: SYN
```

### After (Wireshark-Style)
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Frame 1: 54 bytes captured
  Arrival Time: 2024-01-07 14:30:45.123456

Ethernet II
  Destination: 00:11:22:33:44:55
  Source:      aa:bb:cc:dd:ee:ff
  Type:        0x0800 (IPv4)

Internet Protocol Version 4
  Source Address: 192.168.1.100
  Destination Address: 192.168.1.1
  Protocol: 6 (TCP)

Transmission Control Protocol
  Source Port: 1234
  Destination Port: 80
  Flags: 0x02
      .... .1 = Syn
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Advanced Usage

### Log to File
```bash
sudo ./target/release/ks-sniff -d 2>&1 | tee capture.log
```

### Filter Specific Hosts
```bash
sudo ./target/release/ks-sniff -d --bpf-filter 'host 192.168.1.100'
```

### Capture with Packet Count Limit
```bash
# Use timeout to limit duration
timeout 10s sudo ./target/release/ks-sniff -d
```

## Configuration File Example

Create or edit `config/ks-sniff.yaml`:

```yaml
network:
  interface: "eth0"
  promisc_mode: true
  snaplen: 65535
  bpf_filter: "tcp port 80 or tcp port 443"

logging:
  level: "info"
  format: "json"
  decode_logging: true  # Enable Wireshark-style output
  output: null          # null = console, or specify file path

detection:
  worker_threads: 0     # 0 = auto-detect
  packet_queue_size: 10000
```

Then run:
```bash
sudo ./target/release/ks-sniff --config config/ks-sniff.yaml
```

## See Also

- **TROUBLESHOOTING.md**: Detailed troubleshooting guide
- **BUILD.md**: Build instructions
- **README.md**: Project overview

## Feedback

If you encounter issues or have suggestions for the decode logging feature, please open an issue on GitHub.
