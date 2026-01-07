use crate::capture::packet::{TcpFlags, TcpSegment};
use crate::error::{KsError, Result};

/// Decode TCP segment
pub fn decode_tcp(data: &[u8]) -> Result<TcpSegment> {
    if data.len() < 20 {
        return Err(KsError::DecodeError(
            "Packet too short for TCP header".to_string(),
        ));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // Data offset is in the high 4 bits of byte 12, in 32-bit words
    let data_offset = ((data[12] >> 4) as usize) * 4;

    if data.len() < data_offset {
        return Err(KsError::DecodeError(
            "Packet too short for TCP data offset".to_string(),
        ));
    }

    // Flags are in byte 13
    let flags = TcpFlags::from_byte(data[13]);

    let window = u16::from_be_bytes([data[14], data[15]]);

    // Payload starts after header (includes options)
    let payload = data[data_offset..].to_vec();

    Ok(TcpSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
    })
}

/// Check if TCP segment has specific flags set
pub fn has_flags(segment: &TcpSegment, syn: bool, ack: bool, fin: bool, rst: bool) -> bool {
    (!syn || segment.flags.syn)
        && (!ack || segment.flags.ack)
        && (!fin || segment.flags.fin)
        && (!rst || segment.flags.rst)
}

/// Format TCP flags as string
pub fn format_flags(flags: &TcpFlags) -> String {
    let mut parts = Vec::new();
    if flags.syn {
        parts.push("SYN");
    }
    if flags.ack {
        parts.push("ACK");
    }
    if flags.fin {
        parts.push("FIN");
    }
    if flags.rst {
        parts.push("RST");
    }
    if flags.psh {
        parts.push("PSH");
    }
    if flags.urg {
        parts.push("URG");
    }

    if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_tcp() {
        // Sample TCP header (20 bytes minimum)
        let data = vec![
            0x04, 0xd2, // Source Port = 1234
            0x00, 0x50, // Dest Port = 80 (HTTP)
            0x00, 0x00, 0x00, 0x01, // Seq = 1
            0x00, 0x00, 0x00, 0x00, // Ack = 0
            0x50, 0x02, // Data Offset=5 (20 bytes), Flags=SYN
            0x20, 0x00, // Window = 8192
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent Pointer
            // Payload
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        ];

        let segment = decode_tcp(&data).unwrap();

        assert_eq!(segment.src_port, 1234);
        assert_eq!(segment.dst_port, 80);
        assert_eq!(segment.seq, 1);
        assert_eq!(segment.ack, 0);
        assert!(segment.flags.syn);
        assert!(!segment.flags.ack);
        assert_eq!(segment.payload, vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::from_byte(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);

        assert_eq!(flags.to_byte(), 0x12);
    }

    #[test]
    fn test_format_flags() {
        let flags = TcpFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
        };
        assert_eq!(format_flags(&flags), "SYN,ACK");
    }

    #[test]
    fn test_has_flags() {
        let segment = TcpSegment {
            src_port: 80,
            dst_port: 1234,
            seq: 0,
            ack: 0,
            flags: TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
            },
            window: 8192,
            payload: vec![],
        };

        assert!(has_flags(&segment, true, false, false, false)); // Has SYN
        assert!(!has_flags(&segment, false, true, false, false)); // Doesn't have ACK
    }

    #[test]
    fn test_short_packet() {
        let data = vec![0x04, 0xd2]; // Too short
        assert!(decode_tcp(&data).is_err());
    }
}
