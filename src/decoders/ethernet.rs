use crate::capture::packet::EthernetHeader;
use crate::error::{KsError, Result};

/// Ethernet frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Vlan,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::Vlan,
            other => EtherType::Unknown(other),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::Vlan => 0x8100,
            EtherType::Unknown(v) => v,
        }
    }
}

/// Decode Ethernet frame header
pub fn decode_ethernet(data: &[u8]) -> Result<(EthernetHeader, &[u8])> {
    if data.len() < 14 {
        return Err(KsError::DecodeError(
            "Packet too short for Ethernet header".to_string(),
        ));
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];

    dst_mac.copy_from_slice(&data[0..6]);
    src_mac.copy_from_slice(&data[6..12]);

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    let header = EthernetHeader {
        dst_mac,
        src_mac,
        ethertype,
    };

    // Return header and remaining payload
    Ok((header, &data[14..]))
}

/// Format MAC address as string
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ethernet() {
        // Sample Ethernet frame header
        let data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Src MAC
            0x08, 0x00, // EtherType IPv4
            0x45, 0x00, // Payload starts here
        ];

        let (header, payload) = decode_ethernet(&data).unwrap();

        assert_eq!(header.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(header.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(header.ethertype, 0x0800);
        assert_eq!(payload, &[0x45, 0x00]);
    }

    #[test]
    fn test_ethertype_conversion() {
        assert_eq!(EtherType::from(0x0800), EtherType::Ipv4);
        assert_eq!(EtherType::from(0x86DD), EtherType::Ipv6);
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800);
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_short_packet() {
        let data = vec![0x00, 0x11, 0x22]; // Too short
        assert!(decode_ethernet(&data).is_err());
    }
}
