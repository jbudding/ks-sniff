use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Raw packet with metadata from capture
#[derive(Clone, Debug)]
pub struct RawPacket {
    pub timestamp: DateTime<Utc>,
    pub data: Arc<[u8]>,
    pub length: usize,
    pub caplen: usize,
}

impl RawPacket {
    pub fn new(timestamp: DateTime<Utc>, data: Vec<u8>) -> Self {
        let length = data.len();
        Self {
            timestamp,
            caplen: length,
            length,
            data: data.into(),
        }
    }
}

/// Decoded packet with protocol layers
#[derive(Debug)]
pub struct DecodedPacket {
    pub raw: RawPacket,
    pub ethernet: Option<EthernetHeader>,
    pub ip: Option<IpLayer>,
    pub transport: Option<TransportLayer>,
    pub application: Option<ApplicationLayer>,
}

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub enum IpLayer {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src_addr: std::net::Ipv4Addr,
    pub dst_addr: std::net::Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub header_length: u8,
    pub total_length: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub src_addr: std::net::Ipv6Addr,
    pub dst_addr: std::net::Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload_length: u16,
}

#[derive(Debug, Clone)]
pub enum TransportLayer {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
    Icmp(IcmpPacket),
}

#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: (byte & 0x01) != 0,
            syn: (byte & 0x02) != 0,
            rst: (byte & 0x04) != 0,
            psh: (byte & 0x08) != 0,
            ack: (byte & 0x10) != 0,
            urg: (byte & 0x20) != 0,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.fin { byte |= 0x01; }
        if self.syn { byte |= 0x02; }
        if self.rst { byte |= 0x04; }
        if self.psh { byte |= 0x08; }
        if self.ack { byte |= 0x10; }
        if self.urg { byte |= 0x20; }
        byte
    }
}

#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ApplicationLayer {
    Http(HttpMessage),
    Dns(DnsMessage),
    Tls(TlsRecord),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct HttpMessage {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub queries: Vec<String>,
    pub answers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version: u16,
    pub is_client_hello: bool,
}
