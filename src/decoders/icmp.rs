use crate::capture::packet::IcmpPacket;
use crate::error::{KsError, Result};

/// ICMP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    TimeExceeded,
    ParameterProblem,
    Redirect,
    TimestampRequest,
    TimestampReply,
    Unknown(u8),
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            other => IcmpType::Unknown(other),
        }
    }
}

/// Decode ICMP packet
pub fn decode_icmp(data: &[u8]) -> Result<IcmpPacket> {
    if data.len() < 8 {
        return Err(KsError::DecodeError(
            "Packet too short for ICMP header".to_string(),
        ));
    }

    let icmp_type = data[0];
    let icmp_code = data[1];
    // Checksum is at bytes 2-3 but we don't validate it

    // ICMP header is 8 bytes minimum, rest is data
    let payload = data[8..].to_vec();

    Ok(IcmpPacket {
        icmp_type,
        icmp_code,
        payload,
    })
}

/// Check if ICMP is ping request
pub fn is_ping_request(packet: &IcmpPacket) -> bool {
    packet.icmp_type == 8
}

/// Check if ICMP is ping reply
pub fn is_ping_reply(packet: &IcmpPacket) -> bool {
    packet.icmp_type == 0
}

/// Format ICMP type as string
pub fn format_icmp_type(icmp_type: u8) -> String {
    match IcmpType::from(icmp_type) {
        IcmpType::EchoReply => "Echo Reply".to_string(),
        IcmpType::EchoRequest => "Echo Request (Ping)".to_string(),
        IcmpType::DestinationUnreachable => "Destination Unreachable".to_string(),
        IcmpType::TimeExceeded => "Time Exceeded".to_string(),
        IcmpType::ParameterProblem => "Parameter Problem".to_string(),
        IcmpType::Redirect => "Redirect".to_string(),
        IcmpType::TimestampRequest => "Timestamp Request".to_string(),
        IcmpType::TimestampReply => "Timestamp Reply".to_string(),
        IcmpType::Unknown(t) => format!("Unknown ({})", t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_icmp_ping() {
        // ICMP Echo Request (ping)
        let data = vec![
            0x08, // Type = 8 (Echo Request)
            0x00, // Code = 0
            0x00, 0x00, // Checksum
            0x12, 0x34, // Identifier
            0x00, 0x01, // Sequence
            // Payload
            0x61, 0x62, 0x63, 0x64,
        ];

        let packet = decode_icmp(&data).unwrap();

        assert_eq!(packet.icmp_type, 8);
        assert_eq!(packet.icmp_code, 0);
        assert!(is_ping_request(&packet));
        assert!(!is_ping_reply(&packet));
        assert_eq!(packet.payload, vec![0x61, 0x62, 0x63, 0x64]);
    }

    #[test]
    fn test_decode_icmp_reply() {
        // ICMP Echo Reply
        let data = vec![
            0x00, // Type = 0 (Echo Reply)
            0x00, // Code = 0
            0x00, 0x00, // Checksum
            0x12, 0x34, // Identifier
            0x00, 0x01, // Sequence
        ];

        let packet = decode_icmp(&data).unwrap();

        assert_eq!(packet.icmp_type, 0);
        assert!(is_ping_reply(&packet));
        assert!(!is_ping_request(&packet));
    }

    #[test]
    fn test_icmp_type_conversion() {
        assert_eq!(IcmpType::from(8), IcmpType::EchoRequest);
        assert_eq!(IcmpType::from(0), IcmpType::EchoReply);
        assert_eq!(IcmpType::from(3), IcmpType::DestinationUnreachable);
    }

    #[test]
    fn test_format_icmp_type() {
        assert_eq!(format_icmp_type(8), "Echo Request (Ping)");
        assert_eq!(format_icmp_type(0), "Echo Reply");
        assert_eq!(format_icmp_type(99), "Unknown (99)");
    }

    #[test]
    fn test_short_packet() {
        let data = vec![0x08, 0x00]; // Too short
        assert!(decode_icmp(&data).is_err());
    }
}
