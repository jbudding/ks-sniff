/// Snort-compatible rule structures
use std::fmt;
use std::net::IpAddr;

/// Rule action to take when a match occurs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// Generate an alert
    Alert,
    /// Log the packet
    Log,
    /// Pass the packet (allow)
    Pass,
    /// Drop the packet (inline mode)
    Drop,
    /// Reject the packet and send TCP RST or ICMP unreachable
    Reject,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleAction::Alert => write!(f, "alert"),
            RuleAction::Log => write!(f, "log"),
            RuleAction::Pass => write!(f, "pass"),
            RuleAction::Drop => write!(f, "drop"),
            RuleAction::Reject => write!(f, "reject"),
        }
    }
}

/// Protocol to match
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip, // Any IP protocol
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Ip => write!(f, "ip"),
        }
    }
}

/// IP address specification (single IP, CIDR, variable, negated, or any)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSpec {
    /// Any IP address
    Any,
    /// Specific IP address
    Addr(IpAddr),
    /// CIDR notation (e.g., 192.168.1.0/24)
    Cidr { addr: IpAddr, prefix_len: u8 },
    /// Variable reference (e.g., $HOME_NET)
    Variable(String),
    /// List of IP specifications
    List(Vec<IpSpec>),
    /// Negated IP specification
    Not(Box<IpSpec>),
}

impl fmt::Display for IpSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSpec::Any => write!(f, "any"),
            IpSpec::Addr(addr) => write!(f, "{}", addr),
            IpSpec::Cidr { addr, prefix_len } => write!(f, "{}/{}", addr, prefix_len),
            IpSpec::Variable(var) => write!(f, "${}", var),
            IpSpec::List(list) => {
                write!(f, "[")?;
                for (i, spec) in list.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", spec)?;
                }
                write!(f, "]")
            }
            IpSpec::Not(spec) => write!(f, "!{}", spec),
        }
    }
}

/// Port specification (single port, range, variable, or any)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// Any port
    Any,
    /// Specific port
    Port(u16),
    /// Port range (inclusive)
    Range(u16, u16),
    /// Variable reference (e.g., $HTTP_PORTS)
    Variable(String),
    /// List of port specifications
    List(Vec<PortSpec>),
    /// Negated port specification
    Not(Box<PortSpec>),
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortSpec::Any => write!(f, "any"),
            PortSpec::Port(port) => write!(f, "{}", port),
            PortSpec::Range(start, end) => write!(f, "{}:{}", start, end),
            PortSpec::Variable(var) => write!(f, "${}", var),
            PortSpec::List(list) => {
                write!(f, "[")?;
                for (i, spec) in list.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", spec)?;
                }
                write!(f, "]")
            }
            PortSpec::Not(spec) => write!(f, "!{}", spec),
        }
    }
}

/// Direction of traffic flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Unidirectional: source -> destination
    To,
    /// Bidirectional: source <> destination
    Either,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::To => write!(f, "->"),
            Direction::Either => write!(f, "<>"),
        }
    }
}

/// Flow direction for stateful inspection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    ToServer,
    ToClient,
    FromServer,
    FromClient,
    Either,
}

/// TCP flags to match
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: Option<bool>,
    pub ack: Option<bool>,
    pub fin: Option<bool>,
    pub rst: Option<bool>,
    pub psh: Option<bool>,
    pub urg: Option<bool>,
}

/// Content matching options
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMatch {
    /// Pattern to match
    pub pattern: Vec<u8>,
    /// Case-insensitive matching
    pub nocase: bool,
    /// Match relative to previous content match
    pub relative: bool,
    /// Offset from start of payload
    pub offset: Option<usize>,
    /// Search depth
    pub depth: Option<usize>,
    /// Distance from previous match
    pub distance: Option<isize>,
    /// Within bytes of previous match
    pub within: Option<usize>,
    /// HTTP-specific location
    pub http_location: Option<HttpLocation>,
}

/// HTTP-specific content location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpLocation {
    Method,
    Uri,
    Header,
    Cookie,
    Body,
    StatCode,
    StatMsg,
}

/// Rule options (Snort rule body)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleOptions {
    /// Rule message
    pub msg: Option<String>,
    /// Signature ID (required)
    pub sid: u32,
    /// Revision number
    pub rev: Option<u32>,
    /// Classification type
    pub classtype: Option<String>,
    /// Priority (1=high, 2=medium, 3=low)
    pub priority: Option<u8>,
    /// Reference URLs
    pub reference: Vec<String>,
    /// Metadata key-value pairs
    pub metadata: Vec<(String, String)>,
    /// Content patterns
    pub content: Vec<ContentMatch>,
    /// PCRE patterns
    pub pcre: Vec<String>,
    /// Flow state requirements
    pub flow: Option<FlowSpec>,
    /// TCP flags to match
    pub flags: Option<TcpFlags>,
    /// Threshold configuration
    pub threshold: Option<ThresholdSpec>,
}

/// Flow state specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSpec {
    /// Connection must be established
    pub established: bool,
    /// Connection must not be established
    pub not_established: bool,
    /// Direction of flow
    pub direction: Option<FlowDirection>,
}

/// Threshold specification for event suppression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdSpec {
    pub threshold_type: ThresholdType,
    pub track: TrackBy,
    pub count: u32,
    pub seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdType {
    Limit,    // Alert once per time period
    Threshold, // Alert after N events
    Both,     // Alert once after N events
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackBy {
    SrcIp,
    DstIp,
}

/// Complete Snort-compatible rule
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// Rule action
    pub action: RuleAction,
    /// Protocol to match
    pub protocol: Protocol,
    /// Source IP specification
    pub src_ip: IpSpec,
    /// Source port specification
    pub src_port: PortSpec,
    /// Traffic direction
    pub direction: Direction,
    /// Destination IP specification
    pub dst_ip: IpSpec,
    /// Destination port specification
    pub dst_port: PortSpec,
    /// Rule options
    pub options: RuleOptions,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} (sid:{}",
            self.action,
            self.protocol,
            self.src_ip,
            self.src_port,
            self.direction,
            self.dst_ip,
            self.dst_port,
            self.options.sid
        )?;

        if let Some(ref msg) = self.options.msg {
            write!(f, "; msg:\"{}\"", msg)?;
        }

        if let Some(rev) = self.options.rev {
            write!(f, "; rev:{}", rev)?;
        }

        write!(f, ";)")
    }
}

impl Rule {
    /// Create a new rule with the given parameters
    pub fn new(
        action: RuleAction,
        protocol: Protocol,
        src_ip: IpSpec,
        src_port: PortSpec,
        direction: Direction,
        dst_ip: IpSpec,
        dst_port: PortSpec,
        sid: u32,
    ) -> Self {
        Self {
            action,
            protocol,
            src_ip,
            src_port,
            direction,
            dst_ip,
            dst_port,
            options: RuleOptions {
                sid,
                ..Default::default()
            },
        }
    }

    /// Check if this rule matches the given protocol
    pub fn matches_protocol(&self, protocol: Protocol) -> bool {
        self.protocol == Protocol::Ip || self.protocol == protocol
    }

    /// Get the rule's signature ID
    pub fn sid(&self) -> u32 {
        self.options.sid
    }

    /// Get the rule's message
    pub fn message(&self) -> Option<&str> {
        self.options.msg.as_deref()
    }

    /// Get the rule's priority (default to 3 if not set)
    pub fn priority(&self) -> u8 {
        self.options.priority.unwrap_or(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rule_creation() {
        let rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Variable("EXTERNAL_NET".to_string()),
            PortSpec::Any,
            Direction::To,
            IpSpec::Variable("HOME_NET".to_string()),
            PortSpec::Port(80),
            1000001,
        );

        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.sid(), 1000001);
        assert_eq!(rule.priority(), 3); // Default priority
    }

    #[test]
    fn test_ip_spec_display() {
        assert_eq!(IpSpec::Any.to_string(), "any");
        assert_eq!(
            IpSpec::Addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            IpSpec::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefix_len: 24
            }
            .to_string(),
            "192.168.1.0/24"
        );
        assert_eq!(
            IpSpec::Variable("HOME_NET".to_string()).to_string(),
            "$HOME_NET"
        );
    }

    #[test]
    fn test_port_spec_display() {
        assert_eq!(PortSpec::Any.to_string(), "any");
        assert_eq!(PortSpec::Port(80).to_string(), "80");
        assert_eq!(PortSpec::Range(80, 443).to_string(), "80:443");
        assert_eq!(
            PortSpec::Variable("HTTP_PORTS".to_string()).to_string(),
            "$HTTP_PORTS"
        );
    }

    #[test]
    fn test_protocol_matching() {
        let tcp_rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Any,
            1,
        );

        assert!(tcp_rule.matches_protocol(Protocol::Tcp));
        assert!(!tcp_rule.matches_protocol(Protocol::Udp));

        let ip_rule = Rule::new(
            RuleAction::Alert,
            Protocol::Ip,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Any,
            2,
        );

        // IP protocol matches everything
        assert!(ip_rule.matches_protocol(Protocol::Tcp));
        assert!(ip_rule.matches_protocol(Protocol::Udp));
        assert!(ip_rule.matches_protocol(Protocol::Icmp));
    }
}
