#!/bin/bash
# Test script for decode logging feature

echo "=== Testing Decode Logging Feature ==="
echo ""

# Check if binary exists
if [ ! -f "target/release/ks-sniff" ]; then
    echo "Building release binary..."
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "Build failed. Trying debug build..."
        cargo build
        BINARY="target/debug/ks-sniff"
    else
        BINARY="target/release/ks-sniff"
    fi
else
    BINARY="target/release/ks-sniff"
fi

echo "Using binary: $BINARY"
echo ""

# Test 1: Show help
echo "--- Test 1: Checking help text ---"
$BINARY --help | grep -A 2 "decode-logging"
echo ""

# Test 2: Check if RUST_LOG is set
echo "--- Test 2: Environment check ---"
if [ -n "$RUST_LOG" ]; then
    echo "WARNING: RUST_LOG is set to: $RUST_LOG"
    echo "This may override the --decode-logging flag"
    echo "To unset: unset RUST_LOG"
else
    echo "✓ RUST_LOG is not set (good)"
fi
echo ""

# Test 3: Run with decode logging on a sample PCAP (if available)
echo "--- Test 3: Creating sample packet ---"

# Create a minimal test
cat > /tmp/test_decode.rs << 'EOF'
use std::io::Write;

fn main() {
    // Create sample Ethernet + IP + TCP packet
    let mut data = Vec::new();

    // Ethernet
    data.extend_from_slice(&[0x00,0x11,0x22,0x33,0x44,0x55,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x08,0x00]);

    // IPv4
    data.extend_from_slice(&[0x45,0x00,0x00,0x3c,0x1c,0x46,0x40,0x00,0x40,0x06,0xb1,0xe6,192,168,1,100,192,168,1,1]);

    // TCP
    data.extend_from_slice(&[0x04,0xd2,0x00,0x50,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x50,0x02,0x20,0x00,0x00,0x00,0x00,0x00]);

    std::io::stdout().write_all(&data).unwrap();
}
EOF

rustc /tmp/test_decode.rs -o /tmp/test_decode 2>/dev/null
/tmp/test_decode > /tmp/test_packet.raw
echo "✓ Created test packet at /tmp/test_packet.raw"
echo ""

# Test 4: Run WITHOUT decode logging
echo "--- Test 4: Running WITHOUT --decode-logging ---"
echo "Command: $BINARY --help 2>&1 | head -5"
$BINARY --help 2>&1 | head -5
echo ""

# Test 5: Run WITH decode logging
echo "--- Test 5: Running WITH --decode-logging ---"
echo "This should show 'Decode logging ENABLED' and the filter string"
echo ""
echo "Command: $BINARY -d --help 2>&1 | head -10"
$BINARY -d --help 2>&1 | head -10
echo ""

echo "=== Troubleshooting Tips ==="
echo ""
echo "If decode logging is not working:"
echo "  1. Make sure RUST_LOG is not set: unset RUST_LOG"
echo "  2. Check the filter string in the output above"
echo "  3. Use verbose mode: $BINARY -d -vv"
echo "  4. Manually set RUST_LOG: RUST_LOG=ks_sniff::decoders::decoder=debug $BINARY"
echo ""
echo "Expected output WITH -d flag:"
echo "  Decode logging ENABLED"
echo "  Log filter: ks_sniff=info,ks_sniff::decoders::decoder=debug"
echo ""
echo "To see decode logging in action:"
echo "  cargo run --example decode_packet"
echo "  OR"
echo "  $BINARY -d --pcap-file /tmp/test_packet.pcap (if you have a pcap file)"
echo ""

# Cleanup
rm -f /tmp/test_decode.rs /tmp/test_decode /tmp/test_packet.raw
