use crate::capture::packet::UdpDatagram;
use crate::error::{KsError, Result};

/// Decode UDP datagram
pub fn decode_udp(data: &[u8]) -> Result<UdpDatagram> {
    if data.len() < 8 {
        return Err(KsError::DecodeError(
            "Packet too short for UDP header".to_string(),
        ));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    // Checksum is at bytes 6-7 but we don't validate it

    // UDP header is always 8 bytes, payload follows
    let payload = data[8..].to_vec();

    Ok(UdpDatagram {
        src_port,
        dst_port,
        length,
        payload,
    })
}

/// Check if UDP datagram is to/from a specific port
pub fn is_port(datagram: &UdpDatagram, port: u16) -> bool {
    datagram.src_port == port || datagram.dst_port == port
}

/// Check if UDP datagram matches port range
pub fn is_port_range(datagram: &UdpDatagram, start: u16, end: u16) -> bool {
    (datagram.src_port >= start && datagram.src_port <= end)
        || (datagram.dst_port >= start && datagram.dst_port <= end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_udp() {
        // Sample UDP header (8 bytes)
        let data = vec![
            0x04, 0xd2, // Source Port = 1234
            0x00, 0x35, // Dest Port = 53 (DNS)
            0x00, 0x10, // Length = 16 (8 header + 8 payload)
            0x00, 0x00, // Checksum
            // Payload (8 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let datagram = decode_udp(&data).unwrap();

        assert_eq!(datagram.src_port, 1234);
        assert_eq!(datagram.dst_port, 53);
        assert_eq!(datagram.length, 16);
        assert_eq!(datagram.payload.len(), 8);
        assert_eq!(datagram.payload, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_is_port() {
        let datagram = UdpDatagram {
            src_port: 1234,
            dst_port: 53,
            length: 16,
            payload: vec![],
        };

        assert!(is_port(&datagram, 53));
        assert!(is_port(&datagram, 1234));
        assert!(!is_port(&datagram, 80));
    }

    #[test]
    fn test_is_port_range() {
        let datagram = UdpDatagram {
            src_port: 1234,
            dst_port: 8080,
            length: 16,
            payload: vec![],
        };

        assert!(is_port_range(&datagram, 8000, 9000)); // 8080 in range
        assert!(is_port_range(&datagram, 1000, 2000)); // 1234 in range
        assert!(!is_port_range(&datagram, 80, 100));
    }

    #[test]
    fn test_short_packet() {
        let data = vec![0x04, 0xd2]; // Too short
        assert!(decode_udp(&data).is_err());
    }
}
