use crate::capture::packet::{IpLayer, Ipv4Header, Ipv6Header};
use crate::error::{KsError, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Unknown(v) => v,
        }
    }
}

/// Decode IPv4 header
pub fn decode_ipv4(data: &[u8]) -> Result<(Ipv4Header, &[u8])> {
    if data.len() < 20 {
        return Err(KsError::DecodeError(
            "Packet too short for IPv4 header".to_string(),
        ));
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;

    if version != 4 {
        return Err(KsError::DecodeError(format!(
            "Not an IPv4 packet (version {})",
            version
        )));
    }

    let header_length = (version_ihl & 0x0F) as usize * 4; // IHL is in 32-bit words

    if data.len() < header_length {
        return Err(KsError::DecodeError(
            "Packet too short for IPv4 header length".to_string(),
        ));
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let protocol = data[9];

    let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let header = Ipv4Header {
        src_addr,
        dst_addr,
        protocol,
        ttl,
        header_length: header_length as u8,
        total_length,
    };

    // Return header and payload (skip header)
    Ok((header, &data[header_length..]))
}

/// Decode IPv6 header
pub fn decode_ipv6(data: &[u8]) -> Result<(Ipv6Header, &[u8])> {
    if data.len() < 40 {
        return Err(KsError::DecodeError(
            "Packet too short for IPv6 header".to_string(),
        ));
    }

    let version_class_flow = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = (version_class_flow >> 28) as u8;

    if version != 6 {
        return Err(KsError::DecodeError(format!(
            "Not an IPv6 packet (version {})",
            version
        )));
    }

    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    // Extract source address (bytes 8-23)
    let src_bytes: [u8; 16] = data[8..24].try_into().map_err(|_| {
        KsError::DecodeError("Failed to extract IPv6 source address".to_string())
    })?;
    let src_addr = Ipv6Addr::from(src_bytes);

    // Extract destination address (bytes 24-39)
    let dst_bytes: [u8; 16] = data[24..40].try_into().map_err(|_| {
        KsError::DecodeError("Failed to extract IPv6 destination address".to_string())
    })?;
    let dst_addr = Ipv6Addr::from(dst_bytes);

    let header = Ipv6Header {
        src_addr,
        dst_addr,
        next_header,
        hop_limit,
        payload_length,
    };

    // IPv6 header is always 40 bytes
    Ok((header, &data[40..]))
}

/// Decode IP layer (auto-detect IPv4 or IPv6)
pub fn decode_ip(data: &[u8]) -> Result<(IpLayer, &[u8])> {
    if data.is_empty() {
        return Err(KsError::DecodeError("Empty IP packet".to_string()));
    }

    let version = data[0] >> 4;

    match version {
        4 => {
            let (header, payload) = decode_ipv4(data)?;
            Ok((IpLayer::V4(header), payload))
        }
        6 => {
            let (header, payload) = decode_ipv6(data)?;
            Ok((IpLayer::V6(header), payload))
        }
        _ => Err(KsError::DecodeError(format!(
            "Unknown IP version: {}",
            version
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ipv4() {
        // Minimal IPv4 header (20 bytes)
        let data = vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x3c, // Total Length = 60
            0x1c, 0x46, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, 0x06, // TTL=64, Protocol=TCP(6)
            0xb1, 0xe6, // Header Checksum
            0xc0, 0xa8, 0x01, 0x64, // Source: 192.168.1.100
            0xc0, 0xa8, 0x01, 0x01, // Dest: 192.168.1.1
            // Payload would follow
        ];

        let (header, _payload) = decode_ipv4(&data).unwrap();

        assert_eq!(header.src_addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(header.dst_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(header.protocol, 6); // TCP
        assert_eq!(header.ttl, 64);
        assert_eq!(header.header_length, 20);
    }

    #[test]
    fn test_decode_ipv6() {
        // Minimal IPv6 header (40 bytes)
        let mut data = vec![
            0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class, Flow Label
            0x00, 0x14, // Payload Length = 20
            0x06, // Next Header = TCP
            0x40, // Hop Limit = 64
        ];
        // Source: 2001:db8::1
        data.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Dest: 2001:db8::2
        data.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        let (header, _payload) = decode_ipv6(&data).unwrap();

        assert_eq!(header.next_header, 6); // TCP
        assert_eq!(header.hop_limit, 64);
        assert_eq!(header.payload_length, 20);
    }

    #[test]
    fn test_ip_protocol() {
        assert_eq!(IpProtocol::from(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from(17), IpProtocol::Udp);
        assert_eq!(u8::from(IpProtocol::Tcp), 6);
    }

    #[test]
    fn test_short_packet() {
        let data = vec![0x45, 0x00]; // Too short
        assert!(decode_ipv4(&data).is_err());
    }
}
