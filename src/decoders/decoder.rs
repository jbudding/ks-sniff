use crate::capture::packet::{DecodedPacket, IpLayer, RawPacket, TransportLayer};
use crate::decoders::{ethernet, icmp, ip, tcp, udp};
use crate::error::Result;
use tracing::{trace, warn};

/// Main packet decoder - decodes all protocol layers
pub struct PacketDecoder {
    decode_ethernet: bool,
}

impl PacketDecoder {
    pub fn new() -> Self {
        Self {
            decode_ethernet: true,
        }
    }

    /// Decode a raw packet into structured layers
    pub fn decode(&self, raw: RawPacket) -> Result<DecodedPacket> {
        let mut decoded = DecodedPacket {
            raw: raw.clone(),
            ethernet: None,
            ip: None,
            transport: None,
            application: None,
        };

        let mut data = raw.data.as_ref();

        // Layer 2: Ethernet
        if self.decode_ethernet {
            match ethernet::decode_ethernet(data) {
                Ok((eth_header, payload)) => {
                    trace!(
                        "Ethernet: {} -> {}, EtherType: 0x{:04x}",
                        ethernet::format_mac(&eth_header.src_mac),
                        ethernet::format_mac(&eth_header.dst_mac),
                        eth_header.ethertype
                    );
                    decoded.ethernet = Some(eth_header.clone());
                    data = payload;

                    // Decode based on EtherType
                    match eth_header.ethertype {
                        0x0800 | 0x86DD => {
                            // IPv4 or IPv6 - continue to IP layer
                        }
                        _ => {
                            // Unsupported EtherType (ARP, VLAN, etc.)
                            trace!("Unsupported EtherType: 0x{:04x}", eth_header.ethertype);
                            return Ok(decoded);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to decode Ethernet: {}", e);
                    return Ok(decoded);
                }
            }
        }

        // Layer 3: IP
        match ip::decode_ip(data) {
            Ok((ip_layer, payload)) => {
                match &ip_layer {
                    IpLayer::V4(header) => {
                        trace!(
                            "IPv4: {} -> {}, Protocol: {}",
                            header.src_addr, header.dst_addr, header.protocol
                        );
                    }
                    IpLayer::V6(header) => {
                        trace!(
                            "IPv6: {} -> {}, Next Header: {}",
                            header.src_addr, header.dst_addr, header.next_header
                        );
                    }
                }
                decoded.ip = Some(ip_layer.clone());
                data = payload;

                // Get protocol number
                let protocol = match &ip_layer {
                    IpLayer::V4(h) => h.protocol,
                    IpLayer::V6(h) => h.next_header,
                };

                // Layer 4: Transport
                decoded.transport = match protocol {
                    6 => {
                        // TCP
                        match tcp::decode_tcp(data) {
                            Ok(tcp_seg) => {
                                trace!(
                                    "TCP: {}:{} -> {}:{}, Flags: {}",
                                    match &ip_layer {
                                        IpLayer::V4(h) => h.src_addr.to_string(),
                                        IpLayer::V6(h) => h.src_addr.to_string(),
                                    },
                                    tcp_seg.src_port,
                                    match &ip_layer {
                                        IpLayer::V4(h) => h.dst_addr.to_string(),
                                        IpLayer::V6(h) => h.dst_addr.to_string(),
                                    },
                                    tcp_seg.dst_port,
                                    tcp::format_flags(&tcp_seg.flags)
                                );
                                Some(TransportLayer::Tcp(tcp_seg))
                            }
                            Err(e) => {
                                warn!("Failed to decode TCP: {}", e);
                                None
                            }
                        }
                    }
                    17 => {
                        // UDP
                        match udp::decode_udp(data) {
                            Ok(udp_dgram) => {
                                trace!(
                                    "UDP: {}:{} -> {}:{}, Length: {}",
                                    match &ip_layer {
                                        IpLayer::V4(h) => h.src_addr.to_string(),
                                        IpLayer::V6(h) => h.src_addr.to_string(),
                                    },
                                    udp_dgram.src_port,
                                    match &ip_layer {
                                        IpLayer::V4(h) => h.dst_addr.to_string(),
                                        IpLayer::V6(h) => h.dst_addr.to_string(),
                                    },
                                    udp_dgram.dst_port,
                                    udp_dgram.length
                                );
                                Some(TransportLayer::Udp(udp_dgram))
                            }
                            Err(e) => {
                                warn!("Failed to decode UDP: {}", e);
                                None
                            }
                        }
                    }
                    1 | 58 => {
                        // ICMP or ICMPv6
                        match icmp::decode_icmp(data) {
                            Ok(icmp_pkt) => {
                                trace!(
                                    "ICMP: Type: {}, Code: {}",
                                    icmp::format_icmp_type(icmp_pkt.icmp_type),
                                    icmp_pkt.icmp_code
                                );
                                Some(TransportLayer::Icmp(icmp_pkt))
                            }
                            Err(e) => {
                                warn!("Failed to decode ICMP: {}", e);
                                None
                            }
                        }
                    }
                    _ => {
                        trace!("Unsupported IP protocol: {}", protocol);
                        None
                    }
                };
            }
            Err(e) => {
                warn!("Failed to decode IP: {}", e);
                return Ok(decoded);
            }
        }

        // TODO: Phase 7 - Application layer decoding (HTTP, DNS, TLS)
        // This would inspect the transport layer payload and decode application protocols

        Ok(decoded)
    }

    /// Decode without Ethernet header (for raw IP captures)
    pub fn decode_raw_ip(&self, raw: RawPacket) -> Result<DecodedPacket> {
        let mut decoder = Self::new();
        decoder.decode_ethernet = false;
        decoder.decode(raw)
    }
}

impl Default for PacketDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_decode_full_packet() {
        // Create a complete Ethernet + IPv4 + TCP packet
        let mut packet_data = Vec::new();

        // Ethernet header
        packet_data.extend_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Src MAC
            0x08, 0x00, // EtherType IPv4
        ]);

        // IPv4 header (20 bytes)
        packet_data.extend_from_slice(&[
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x3c, // Total Length
            0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment
            0x40, 0x06, // TTL=64, Protocol=TCP
            0xb1, 0xe6, // Checksum
            0xc0, 0xa8, 0x01, 0x64, // Src: 192.168.1.100
            0xc0, 0xa8, 0x01, 0x01, // Dst: 192.168.1.1
        ]);

        // TCP header (20 bytes)
        packet_data.extend_from_slice(&[
            0x04, 0xd2, // Src port = 1234
            0x00, 0x50, // Dst port = 80
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x02, // Data offset=5, Flags=SYN
            0x20, 0x00, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent
        ]);

        let raw = RawPacket::new(Utc::now(), packet_data);

        let decoder = PacketDecoder::new();
        let decoded = decoder.decode(raw).unwrap();

        assert!(decoded.ethernet.is_some());
        assert!(decoded.ip.is_some());
        assert!(decoded.transport.is_some());

        if let Some(TransportLayer::Tcp(tcp)) = decoded.transport {
            assert_eq!(tcp.src_port, 1234);
            assert_eq!(tcp.dst_port, 80);
            assert!(tcp.flags.syn);
        } else {
            panic!("Expected TCP transport layer");
        }
    }
}
