/// Example demonstrating the decode logging feature
///
/// This shows the difference between normal operation and decode logging enabled.
///
/// Run without decode logging (default):
///   cargo run --example decode_logging_demo
///
/// The output will show summary statistics but not detailed packet decoding.
///
/// To enable detailed packet decode logging, you would run the main binary with:
///   sudo cargo run --release -- --decode-logging
///
/// Or the short form:
///   sudo cargo run --release -- -d

use ks_sniff::capture::packet::RawPacket;
use ks_sniff::decoders::PacketDecoder;
use ks_sniff::decoders::pretty_print;
use chrono::Utc;

fn main() {
    println!("=== Decode Logging Feature Demo ===\n");

    println!("This example demonstrates the --decode-logging feature.\n");

    println!("Without --decode-logging (default):");
    println!("  - Shows: Capture stats, packet counts, TCP/UDP/ICMP counters");
    println!("  - Hides: Detailed per-packet protocol information\n");

    println!("With --decode-logging (-d):");
    println!("  - Shows: All of the above PLUS Wireshark-style detailed packet decoding");
    println!("  - Example output:");
    println!("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("    Frame 1: 54 bytes captured");
    println!("      Arrival Time: 2024-01-07 14:30:45.123");
    println!("    ");
    println!("    Ethernet II");
    println!("      Destination: 00:11:22:33:44:55");
    println!("      Source:      aa:bb:cc:dd:ee:ff");
    println!("      Type:        0x0800 (IPv4)");
    println!("    ");
    println!("    Internet Protocol Version 4");
    println!("      Source Address: 192.168.1.100");
    println!("      Destination Address: 192.168.1.1");
    println!("      Protocol: 6 (TCP)");
    println!("    ");
    println!("    Transmission Control Protocol");
    println!("      Source Port: 1234");
    println!("      Destination Port: 80");
    println!("      Flags: 0x02");
    println!("          .... ..1. = Syn\n");

    println!("Usage Examples:\n");
    println!("  # Normal operation (minimal logging)");
    println!("  sudo ./target/release/ks-sniff\n");

    println!("  # With packet decode logging");
    println!("  sudo ./target/release/ks-sniff --decode-logging\n");

    println!("  # Short form");
    println!("  sudo ./target/release/ks-sniff -d\n");

    println!("  # Combined with other options");
    println!("  sudo ./target/release/ks-sniff -d --interface eth0 --bpf-filter 'tcp port 80'\n");

    println!("  # Read PCAP with decode logging");
    println!("  ./target/release/ks-sniff -d --pcap-file capture.pcap\n");

    println!("Configuration File:");
    println!("  You can also set this in config/ks-sniff.yaml:");
    println!("  logging:");
    println!("    decode_logging: true\n");

    println!("Performance Note:");
    println!("  Decode logging adds minimal overhead (~5-10%).");
    println!("  The logging itself is more expensive than the decoding.\n");

    // Demonstrate with a sample packet
    println!("=== Sample Packet Decode ===\n");

    // Initialize minimal logging for demo
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .init();

    // Create sample packet
    let mut packet_data = Vec::new();

    // Ethernet
    packet_data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
    ]);

    // IPv4
    packet_data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06,
        0xb1, 0xe6,
        192, 168, 1, 100,
        192, 168, 1, 1,
    ]);

    // TCP
    packet_data.extend_from_slice(&[
        0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,
        0x20, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ]);

    let raw = RawPacket::new(Utc::now(), packet_data);
    let decoder = PacketDecoder::new();

    println!("Decoding sample packet...\n");

    match decoder.decode(raw) {
        Ok(decoded) => {
            println!("✓ Packet decoded successfully!\n");
            println!("Wireshark-style output:\n");
            println!("{}", pretty_print::format_packet_detailed(&decoded, 1));
            println!("\nCompact summary format:\n");
            println!("{}", pretty_print::format_packet_summary(&decoded, 1));
        }
        Err(e) => {
            eprintln!("Decode error: {}", e);
        }
    }

    println!("\n=== Summary ===\n");
    println!("Use --decode-logging when:");
    println!("  ✓ Debugging network issues");
    println!("  ✓ Understanding traffic patterns");
    println!("  ✓ Developing/testing new rules");
    println!("  ✓ Learning packet structure\n");

    println!("Disable decode logging when:");
    println!("  ✓ Production monitoring (reduces log volume)");
    println!("  ✓ High-speed captures (>100K pkt/s)");
    println!("  ✓ You only need statistics");
}
