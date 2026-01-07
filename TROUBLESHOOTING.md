# Troubleshooting Guide

## Decode Logging Not Working

If the `--decode-logging` flag is not showing detailed packet information, try these steps:

### 1. Check if RUST_LOG is Set

The `RUST_LOG` environment variable overrides the `--decode-logging` flag.

```bash
# Check if RUST_LOG is set
echo $RUST_LOG

# If it's set, unset it
unset RUST_LOG

# Then try again
sudo ./target/release/ks-sniff --decode-logging
```

### 2. Verify the Flag is Working

When you run with `--decode-logging`, you should see this output at startup:

```
Decode logging ENABLED
Log filter: ks_sniff=info,ks_sniff::decoders::decoder=debug
```

If you don't see this, the flag is not being parsed correctly.

### 3. Use the Test Script

Run the test script to diagnose issues:

```bash
./test_decode_logging.sh
```

### 4. Manual Environment Variable

You can manually set the log level:

```bash
RUST_LOG=ks_sniff::decoders::decoder=debug sudo ./target/release/ks-sniff
```

### 5. Try the Example

The `decode_packet` example has logging enabled by default:

```bash
cargo run --example decode_packet
```

You should see Wireshark-style output like:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Frame 1: 54 bytes captured
  Arrival Time: 2024-01-07 14:30:45.123

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
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 6. Increase Verbosity

Combine decode logging with verbose mode:

```bash
sudo ./target/release/ks-sniff --decode-logging -vv
```

This should show even more detailed information.

### 7. Check Build

Make sure you're using the latest build:

```bash
cargo clean
cargo build --release
sudo ./target/release/ks-sniff --decode-logging
```

## Common Issues

### Issue: "Permission denied" when running

**Cause**: Packet capture requires root privileges on most systems.

**Solution**:
```bash
sudo ./target/release/ks-sniff
```

### Issue: "cannot find -lpcap"

**Cause**: libpcap development libraries not installed.

**Solution**: See [FIX_ALPINE.md](FIX_ALPINE.md) or [BUILD.md](BUILD.md)

### Issue: No packets being captured

**Cause**: Wrong interface or no traffic.

**Solution**:
```bash
# List available interfaces
ip link show

# Specify correct interface
sudo ./target/release/ks-sniff --interface eth0

# Or use 'any' to capture on all interfaces
sudo ./target/release/ks-sniff --interface any
```

### Issue: Too much log output

**Cause**: Decode logging or verbose mode enabled.

**Solution**:
```bash
# Run without decode logging (default)
sudo ./target/release/ks-sniff

# Use quiet mode
sudo ./target/release/ks-sniff --quiet
```

### Issue: Config file decode_logging not working

**Cause**: Order of operations - need to rebuild or config file not being loaded.

**Solution**:
1. Make sure config file exists and is being loaded:
   ```bash
   ./target/release/ks-sniff --config config/ks-sniff.yaml
   ```

2. Check startup output for:
   ```
   ✓ Decode logging ENABLED (via config file)
   ```

3. CLI flag always overrides config file:
   ```bash
   # Even if config has decode_logging: true, this disables it
   ./target/release/ks-sniff  # (no -d flag = disabled)
   ```

### Issue: Logs going to file instead of console

**Cause**: Configuration file setting.

**Solution**: Check `config/ks-sniff.yaml`:
```yaml
logging:
  output: null  # null = console, or specify a file path
```

## Debugging Steps

If decode logging still doesn't work:

1. **Verify the binary**:
   ```bash
   ./target/release/ks-sniff --version
   ./target/release/ks-sniff --help | grep decode
   ```

2. **Check filter at runtime**:
   The program prints the filter being used. Look for:
   ```
   Log filter: ks_sniff=info,ks_sniff::decoders::decoder=debug
   ```

3. **Run with explicit RUST_LOG**:
   ```bash
   RUST_LOG=trace sudo ./target/release/ks-sniff
   ```

4. **Test with decode_packet example**:
   ```bash
   cargo run --example decode_packet 2>&1 | grep DEBUG
   ```
   Should show DEBUG lines for Ethernet, IP, TCP.

5. **Check for compilation issues**:
   ```bash
   cargo check 2>&1 | grep -i error
   ```

## Getting Help

If none of these solutions work:

1. Check that you're using the latest code
2. Verify the decoder module has `debug!()` statements
3. Run the test script: `./test_decode_logging.sh`
4. Check the issue tracker

## Quick Reference

### Enable Decode Logging

```bash
# Method 1: CLI flag (overrides config)
sudo ./target/release/ks-sniff -d

# Method 2: Config file
# Edit config/ks-sniff.yaml:
logging:
  decode_logging: true

# Then run (no -d needed):
sudo ./target/release/ks-sniff --config config/ks-sniff.yaml

# Method 3: Environment variable (overrides everything)
RUST_LOG=ks_sniff::decoders::decoder=debug sudo ./target/release/ks-sniff
```

**Priority (highest to lowest):**
1. RUST_LOG environment variable
2. --decode-logging CLI flag
3. decode_logging in config file

### Disable Decode Logging

```bash
# Default (no flag)
sudo ./target/release/ks-sniff

# Explicit environment
RUST_LOG=ks_sniff::decoders::decoder=warn sudo ./target/release/ks-sniff

# Config file
logging:
  decode_logging: false
```

### Check What's Enabled

Look for these lines at startup:
- `✓ Decode logging ENABLED` = decode logging is on
- `Log filter: ks_sniff=debug` = shows the actual filter being used
- `⚠ Using RUST_LOG environment variable` = RUST_LOG is overriding settings

### What Output to Expect

When decode logging is enabled, you'll see **Wireshark-style** packet dissection with:
- Frame information (number, timestamp, size)
- Ethernet layer details (MAC addresses, EtherType)
- IP layer details (addresses, protocol, TTL)
- Transport layer details (TCP/UDP/ICMP with all fields)
- Hex dump of packet payload (first 256 bytes)

See DECODE_LOGGING_GUIDE.md for complete examples and usage instructions.
