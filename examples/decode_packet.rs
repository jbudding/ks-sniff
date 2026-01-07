use ks_sniff::capture::packet::RawPacket;
use ks_sniff::decoders::PacketDecoder;
use chrono::Utc;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("KS-Sniff Protocol Decoder Example");
    println!("==================================\n");

    // Create a sample Ethernet + IPv4 + TCP packet (SYN)
    let mut packet_data = Vec::new();

    // Ethernet header (14 bytes)
    packet_data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Src MAC
        0x08, 0x00, // EtherType: IPv4
    ]);

    // IPv4 header (20 bytes)
    packet_data.extend_from_slice(&[
        0x45, 0x00, // Version=4, IHL=5
        0x00, 0x3c, // Total Length = 60
        0x1c, 0x46, 0x40, 0x00, // ID, Flags
        0x40, 0x06, // TTL=64, Protocol=TCP
        0xb1, 0xe6, // Checksum
        192, 168, 1, 100, // Src: 192.168.1.100
        192, 168, 1, 1, // Dst: 192.168.1.1
    ]);

    // TCP header (20 bytes) - SYN packet
    packet_data.extend_from_slice(&[
        0x04, 0xd2, // Src port = 1234
        0x00, 0x50, // Dst port = 80 (HTTP)
        0x00, 0x00, 0x00, 0x01, // Seq = 1
        0x00, 0x00, 0x00, 0x00, // Ack = 0
        0x50, 0x02, // Data offset=5, Flags=SYN
        0x20, 0x00, // Window = 8192
        0x00, 0x00, // Checksum
        0x00, 0x00, // Urgent
    ]);

    // HTTP GET request payload
    packet_data.extend_from_slice(b"GET / HTTP/1.1\r\n");

    println!("Sample packet created ({} bytes)\n", packet_data.len());

    // Create raw packet
    let raw_packet = RawPacket::new(Utc::now(), packet_data);

    // Decode the packet
    let decoder = PacketDecoder::new();
    match decoder.decode(raw_packet) {
        Ok(decoded) => {
            println!("=== Decoded Packet Layers ===\n");

            // Ethernet Layer
            if let Some(ref eth) = decoded.ethernet {
                println!("Ethernet:");
                println!("  Source MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.src_mac[0], eth.src_mac[1], eth.src_mac[2],
                    eth.src_mac[3], eth.src_mac[4], eth.src_mac[5]
                );
                println!("  Dest MAC:   {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2],
                    eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]
                );
                println!("  EtherType:  0x{:04x} (IPv4)", eth.ethertype);
                println!();
            }

            // IP Layer
            if let Some(ref ip) = decoded.ip {
                use ks_sniff::capture::packet::IpLayer;
                match ip {
                    IpLayer::V4(header) => {
                        println!("IPv4:");
                        println!("  Source:      {}", header.src_addr);
                        println!("  Destination: {}", header.dst_addr);
                        println!("  Protocol:    {} (TCP)", header.protocol);
                        println!("  TTL:         {}", header.ttl);
                        println!("  Length:      {}", header.total_length);
                        println!();
                    }
                    IpLayer::V6(header) => {
                        println!("IPv6:");
                        println!("  Source:      {}", header.src_addr);
                        println!("  Destination: {}", header.dst_addr);
                        println!("  Next Header: {}", header.next_header);
                        println!();
                    }
                }
            }

            // Transport Layer
            if let Some(ref transport) = decoded.transport {
                use ks_sniff::capture::packet::TransportLayer;
                match transport {
                    TransportLayer::Tcp(tcp) => {
                        println!("TCP:");
                        println!("  Source Port: {}", tcp.src_port);
                        println!("  Dest Port:   {} (HTTP)", tcp.dst_port);
                        println!("  Sequence:    {}", tcp.seq);
                        println!("  Ack:         {}", tcp.ack);
                        println!("  Flags:       {}{}{}{}{}{}",
                            if tcp.flags.syn { "SYN " } else { "" },
                            if tcp.flags.ack { "ACK " } else { "" },
                            if tcp.flags.fin { "FIN " } else { "" },
                            if tcp.flags.rst { "RST " } else { "" },
                            if tcp.flags.psh { "PSH " } else { "" },
                            if tcp.flags.urg { "URG " } else { "" }
                        );
                        println!("  Window:      {}", tcp.window);
                        println!("  Payload:     {} bytes", tcp.payload.len());

                        if !tcp.payload.is_empty() {
                            println!("\n  Payload preview:");
                            let preview = String::from_utf8_lossy(&tcp.payload[..tcp.payload.len().min(50)]);
                            println!("    {}", preview);
                        }
                        println!();
                    }
                    TransportLayer::Udp(udp) => {
                        println!("UDP:");
                        println!("  Source Port: {}", udp.src_port);
                        println!("  Dest Port:   {}", udp.dst_port);
                        println!("  Length:      {}", udp.length);
                        println!("  Payload:     {} bytes", udp.payload.len());
                        println!();
                    }
                    TransportLayer::Icmp(icmp) => {
                        println!("ICMP:");
                        println!("  Type:        {}", icmp.icmp_type);
                        println!("  Code:        {}", icmp.icmp_code);
                        println!("  Payload:     {} bytes", icmp.payload.len());
                        println!();
                    }
                }
            }

            println!("=== Decoding Successful! ===");
        }
        Err(e) => {
            eprintln!("Failed to decode packet: {}", e);
        }
    }

    // Test other packet types
    println!("\n\nTesting additional packet types...\n");

    // UDP/DNS packet
    test_udp_packet();

    // ICMP ping packet
    test_icmp_packet();
}

fn test_udp_packet() {
    println!("--- UDP Packet (DNS) ---");
    let mut packet_data = Vec::new();

    // Ethernet header
    packet_data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
    ]);

    // IPv4 header
    packet_data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x11, // Protocol=UDP
        0xb1, 0xe6,
        192, 168, 1, 100,
        8, 8, 8, 8, // Google DNS
    ]);

    // UDP header
    packet_data.extend_from_slice(&[
        0x04, 0xd2, // Src port = 1234
        0x00, 0x35, // Dst port = 53 (DNS)
        0x00, 0x10, // Length = 16
        0x00, 0x00, // Checksum
    ]);

    // DNS query payload (simplified)
    packet_data.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]);

    let raw = RawPacket::new(Utc::now(), packet_data);
    let decoder = PacketDecoder::new();

    if let Ok(decoded) = decoder.decode(raw) {
        if let Some(transport) = decoded.transport {
            use ks_sniff::capture::packet::TransportLayer;
            if let TransportLayer::Udp(udp) = transport {
                println!("  UDP {}:{} -> {}:{}",
                    match decoded.ip {
                        Some(ks_sniff::capture::packet::IpLayer::V4(ref h)) => h.src_addr.to_string(),
                        _ => "?".to_string(),
                    },
                    udp.src_port,
                    match decoded.ip {
                        Some(ks_sniff::capture::packet::IpLayer::V4(ref h)) => h.dst_addr.to_string(),
                        _ => "?".to_string(),
                    },
                    udp.dst_port
                );
                println!("  Type: DNS Query");
            }
        }
    }
    println!();
}

fn test_icmp_packet() {
    println!("--- ICMP Packet (Ping) ---");
    let mut packet_data = Vec::new();

    // Ethernet header
    packet_data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00,
    ]);

    // IPv4 header
    packet_data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x01, // Protocol=ICMP
        0xb1, 0xe6,
        192, 168, 1, 100,
        192, 168, 1, 1,
    ]);

    // ICMP header (Echo Request)
    packet_data.extend_from_slice(&[
        0x08, // Type = 8 (Echo Request)
        0x00, // Code = 0
        0x00, 0x00, // Checksum
        0x12, 0x34, // Identifier
        0x00, 0x01, // Sequence
    ]);

    // Payload
    packet_data.extend_from_slice(b"ping data");

    let raw = RawPacket::new(Utc::now(), packet_data);
    let decoder = PacketDecoder::new();

    if let Ok(decoded) = decoder.decode(raw) {
        if let Some(transport) = decoded.transport {
            use ks_sniff::capture::packet::TransportLayer;
            if let TransportLayer::Icmp(icmp) = transport {
                println!("  ICMP {} -> {}",
                    match decoded.ip {
                        Some(ks_sniff::capture::packet::IpLayer::V4(ref h)) => h.src_addr.to_string(),
                        _ => "?".to_string(),
                    },
                    match decoded.ip {
                        Some(ks_sniff::capture::packet::IpLayer::V4(ref h)) => h.dst_addr.to_string(),
                        _ => "?".to_string(),
                    }
                );
                println!("  Type: Echo Request (Ping)");
                println!("  Code: {}", icmp.icmp_code);
            }
        }
    }
    println!();
}
