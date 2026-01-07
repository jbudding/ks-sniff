/// Wireshark-style packet pretty printing
use crate::capture::packet::{DecodedPacket, IpLayer, TransportLayer};
use std::fmt::Write;

/// Format a packet in Wireshark-style output
pub fn format_packet_detailed(packet: &DecodedPacket, packet_num: u64) -> String {
    let mut output = String::new();

    // Frame header
    writeln!(output, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").unwrap();
    writeln!(output, "Frame {}: {} bytes captured", packet_num, packet.raw.caplen).unwrap();
    writeln!(output, "  Arrival Time: {}", packet.raw.timestamp).unwrap();
    writeln!(output, "  Frame Length: {} bytes", packet.raw.length).unwrap();
    writeln!(output, "  Capture Length: {} bytes", packet.raw.caplen).unwrap();

    // Ethernet Layer
    if let Some(ref eth) = packet.ethernet {
        writeln!(output, "\nEthernet II").unwrap();
        writeln!(output, "  Destination: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            eth.dst_mac[0], eth.dst_mac[1], eth.dst_mac[2],
            eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]).unwrap();
        writeln!(output, "  Source:      {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            eth.src_mac[0], eth.src_mac[1], eth.src_mac[2],
            eth.src_mac[3], eth.src_mac[4], eth.src_mac[5]).unwrap();
        writeln!(output, "  Type:        0x{:04x} ({})",
            eth.ethertype,
            match eth.ethertype {
                0x0800 => "IPv4",
                0x86DD => "IPv6",
                0x0806 => "ARP",
                0x8100 => "802.1Q VLAN",
                _ => "Unknown",
            }
        ).unwrap();
    }

    // IP Layer
    if let Some(ref ip) = packet.ip {
        match ip {
            IpLayer::V4(header) => {
                writeln!(output, "\nInternet Protocol Version 4").unwrap();
                writeln!(output, "  Version: 4").unwrap();
                writeln!(output, "  Header Length: {} bytes", header.header_length).unwrap();
                writeln!(output, "  Total Length: {}", header.total_length).unwrap();
                writeln!(output, "  Protocol: {} ({})",
                    header.protocol,
                    match header.protocol {
                        1 => "ICMP",
                        6 => "TCP",
                        17 => "UDP",
                        _ => "Unknown",
                    }
                ).unwrap();
                writeln!(output, "  Time to Live: {}", header.ttl).unwrap();
                writeln!(output, "  Source Address: {}", header.src_addr).unwrap();
                writeln!(output, "  Destination Address: {}", header.dst_addr).unwrap();
            }
            IpLayer::V6(header) => {
                writeln!(output, "\nInternet Protocol Version 6").unwrap();
                writeln!(output, "  Version: 6").unwrap();
                writeln!(output, "  Payload Length: {}", header.payload_length).unwrap();
                writeln!(output, "  Next Header: {} ({})",
                    header.next_header,
                    match header.next_header {
                        6 => "TCP",
                        17 => "UDP",
                        58 => "ICMPv6",
                        _ => "Unknown",
                    }
                ).unwrap();
                writeln!(output, "  Hop Limit: {}", header.hop_limit).unwrap();
                writeln!(output, "  Source Address: {}", header.src_addr).unwrap();
                writeln!(output, "  Destination Address: {}", header.dst_addr).unwrap();
            }
        }
    }

    // Transport Layer
    if let Some(ref transport) = packet.transport {
        match transport {
            TransportLayer::Tcp(tcp) => {
                writeln!(output, "\nTransmission Control Protocol").unwrap();
                writeln!(output, "  Source Port: {}", tcp.src_port).unwrap();
                writeln!(output, "  Destination Port: {}", tcp.dst_port).unwrap();
                writeln!(output, "  Sequence Number: {}", tcp.seq).unwrap();
                writeln!(output, "  Acknowledgment Number: {}", tcp.ack).unwrap();
                writeln!(output, "  Flags: 0x{:02x}", tcp.flags.to_byte()).unwrap();
                writeln!(output, "      {} .... = Reserved",
                    if false { '1' } else { '0' }).unwrap();
                writeln!(output, "      .{} ... = Urgent",
                    if tcp.flags.urg { '1' } else { '0' }).unwrap();
                writeln!(output, "      ..{} .. = Acknowledgment",
                    if tcp.flags.ack { '1' } else { '0' }).unwrap();
                writeln!(output, "      ...{} . = Push",
                    if tcp.flags.psh { '1' } else { '0' }).unwrap();
                writeln!(output, "      .... {} = Reset",
                    if tcp.flags.rst { '1' } else { '0' }).unwrap();
                writeln!(output, "      .... .{} = Syn",
                    if tcp.flags.syn { '1' } else { '0' }).unwrap();
                writeln!(output, "      .... ..{} = Fin",
                    if tcp.flags.fin { '1' } else { '0' }).unwrap();
                writeln!(output, "  Window: {}", tcp.window).unwrap();

                if !tcp.payload.is_empty() {
                    writeln!(output, "  [TCP Payload: {} bytes]", tcp.payload.len()).unwrap();
                }
            }
            TransportLayer::Udp(udp) => {
                writeln!(output, "\nUser Datagram Protocol").unwrap();
                writeln!(output, "  Source Port: {}", udp.src_port).unwrap();
                writeln!(output, "  Destination Port: {}", udp.dst_port).unwrap();
                writeln!(output, "  Length: {}", udp.length).unwrap();

                if !udp.payload.is_empty() {
                    writeln!(output, "  [UDP Payload: {} bytes]", udp.payload.len()).unwrap();
                }
            }
            TransportLayer::Icmp(icmp) => {
                writeln!(output, "\nInternet Control Message Protocol").unwrap();
                writeln!(output, "  Type: {} ({})", icmp.icmp_type,
                    match icmp.icmp_type {
                        0 => "Echo Reply",
                        3 => "Destination Unreachable",
                        8 => "Echo Request",
                        11 => "Time Exceeded",
                        _ => "Other",
                    }
                ).unwrap();
                writeln!(output, "  Code: {}", icmp.icmp_code).unwrap();

                if !icmp.payload.is_empty() {
                    writeln!(output, "  [ICMP Payload: {} bytes]", icmp.payload.len()).unwrap();
                }
            }
        }
    }

    // Payload hex dump (if present)
    if let Some(ref transport) = packet.transport {
        let payload = match transport {
            TransportLayer::Tcp(tcp) => Some(&tcp.payload[..]),
            TransportLayer::Udp(udp) => Some(&udp.payload[..]),
            TransportLayer::Icmp(icmp) => Some(&icmp.payload[..]),
        };

        if let Some(data) = payload {
            if !data.is_empty() {
                writeln!(output, "\nData ({} bytes)", data.len()).unwrap();
                write_hex_dump(&mut output, data);
            }
        }
    }

    writeln!(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").unwrap();

    output
}

/// Write hex dump in Wireshark style
fn write_hex_dump(output: &mut String, data: &[u8]) {
    let limit = data.len().min(256); // Limit to first 256 bytes

    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        // Offset
        write!(output, "  {:04x}  ", i * 16).unwrap();

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            write!(output, "{:02x} ", byte).unwrap();
            if j == 7 {
                write!(output, " ").unwrap();
            }
        }

        // Padding if less than 16 bytes
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                write!(output, "   ").unwrap();
                if j == 7 {
                    write!(output, " ").unwrap();
                }
            }
        }

        // ASCII representation
        write!(output, " ").unwrap();
        for byte in chunk {
            let c = if *byte >= 0x20 && *byte <= 0x7e {
                *byte as char
            } else {
                '.'
            };
            write!(output, "{}", c).unwrap();
        }

        writeln!(output).unwrap();
    }

    if data.len() > limit {
        writeln!(output, "  ... ({} more bytes)", data.len() - limit).unwrap();
    }
}

/// Compact one-line summary (for less verbose output)
pub fn format_packet_summary(packet: &DecodedPacket, packet_num: u64) -> String {
    let mut parts = Vec::new();

    parts.push(format!("#{}", packet_num));
    parts.push(format!("{}", packet.raw.timestamp.format("%H:%M:%S%.3f")));

    if let Some(ref ip) = packet.ip {
        match ip {
            IpLayer::V4(h) => {
                parts.push(format!("{} → {}", h.src_addr, h.dst_addr));
            }
            IpLayer::V6(h) => {
                parts.push(format!("{} → {}", h.src_addr, h.dst_addr));
            }
        }
    }

    if let Some(ref transport) = packet.transport {
        match transport {
            TransportLayer::Tcp(tcp) => {
                let flags = format!("{}{}{}{}{}{}",
                    if tcp.flags.syn { "S" } else { "" },
                    if tcp.flags.ack { "A" } else { "" },
                    if tcp.flags.fin { "F" } else { "" },
                    if tcp.flags.rst { "R" } else { "" },
                    if tcp.flags.psh { "P" } else { "" },
                    if tcp.flags.urg { "U" } else { "" },
                );
                parts.push(format!("TCP {}:{} → {}:{} [{}] Seq={} Len={}",
                    match &packet.ip {
                        Some(IpLayer::V4(h)) => h.src_addr.to_string(),
                        Some(IpLayer::V6(h)) => h.src_addr.to_string(),
                        None => "?".to_string(),
                    },
                    tcp.src_port,
                    match &packet.ip {
                        Some(IpLayer::V4(h)) => h.dst_addr.to_string(),
                        Some(IpLayer::V6(h)) => h.dst_addr.to_string(),
                        None => "?".to_string(),
                    },
                    tcp.dst_port,
                    flags,
                    tcp.seq,
                    tcp.payload.len()
                ));
            }
            TransportLayer::Udp(udp) => {
                parts.push(format!("UDP {}:{} → {}:{} Len={}",
                    match &packet.ip {
                        Some(IpLayer::V4(h)) => h.src_addr.to_string(),
                        Some(IpLayer::V6(h)) => h.src_addr.to_string(),
                        None => "?".to_string(),
                    },
                    udp.src_port,
                    match &packet.ip {
                        Some(IpLayer::V4(h)) => h.dst_addr.to_string(),
                        Some(IpLayer::V6(h)) => h.dst_addr.to_string(),
                        None => "?".to_string(),
                    },
                    udp.dst_port,
                    udp.payload.len()
                ));
            }
            TransportLayer::Icmp(icmp) => {
                let type_str = match icmp.icmp_type {
                    0 => "Echo Reply",
                    8 => "Echo Request",
                    _ => "Other",
                };
                parts.push(format!("ICMP {} (type={} code={})",
                    type_str, icmp.icmp_type, icmp.icmp_code));
            }
        }
    }

    parts.join(" ")
}
