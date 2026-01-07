/// Snort rule parser using nom combinators
use super::rule::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_until, take_while1},
    character::complete::{char, digit1, multispace0, space0, space1},
    combinator::{map, map_res, recognize, value},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, preceded, separated_pair, tuple},
    IResult,
};
use std::net::IpAddr;

/// Parse a complete Snort rule
/// Example: alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test"; sid:1;)
pub fn parse_rule(input: &str) -> IResult<&str, Rule> {
    let (input, _) = multispace0(input)?;

    // Parse action
    let (input, action) = parse_action(input)?;
    let (input, _) = space1(input)?;

    // Parse protocol
    let (input, protocol) = parse_protocol(input)?;
    let (input, _) = space1(input)?;

    // Parse source IP
    let (input, src_ip) = parse_ip_spec(input)?;
    let (input, _) = space1(input)?;

    // Parse source port
    let (input, src_port) = parse_port_spec(input)?;
    let (input, _) = space1(input)?;

    // Parse direction
    let (input, direction) = parse_direction(input)?;
    let (input, _) = space1(input)?;

    // Parse destination IP
    let (input, dst_ip) = parse_ip_spec(input)?;
    let (input, _) = space1(input)?;

    // Parse destination port
    let (input, dst_port) = parse_port_spec(input)?;
    let (input, _) = space0(input)?;

    // Parse options
    let (input, options) = parse_options(input)?;
    let (input, _) = multispace0(input)?;

    Ok((
        input,
        Rule {
            action,
            protocol,
            src_ip,
            src_port,
            direction,
            dst_ip,
            dst_port,
            options,
        },
    ))
}

/// Parse rule action (alert, log, pass, drop, reject)
fn parse_action(input: &str) -> IResult<&str, RuleAction> {
    alt((
        value(RuleAction::Alert, tag_no_case("alert")),
        value(RuleAction::Log, tag_no_case("log")),
        value(RuleAction::Pass, tag_no_case("pass")),
        value(RuleAction::Drop, tag_no_case("drop")),
        value(RuleAction::Reject, tag_no_case("reject")),
    ))(input)
}

/// Parse protocol (tcp, udp, icmp, ip)
fn parse_protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        value(Protocol::Tcp, tag_no_case("tcp")),
        value(Protocol::Udp, tag_no_case("udp")),
        value(Protocol::Icmp, tag_no_case("icmp")),
        value(Protocol::Ip, tag_no_case("ip")),
    ))(input)
}

/// Parse direction (-> or <>)
fn parse_direction(input: &str) -> IResult<&str, Direction> {
    alt((
        value(Direction::Either, tag("<>")),
        value(Direction::To, tag("->")),
    ))(input)
}

/// Parse IP specification
fn parse_ip_spec(input: &str) -> IResult<&str, IpSpec> {
    alt((
        // Negated IP
        map(
            preceded(char('!'), parse_ip_spec_inner),
            |spec| IpSpec::Not(Box::new(spec)),
        ),
        // List of IPs
        map(
            delimited(
                char('['),
                separated_list1(char(','), parse_ip_spec_inner),
                char(']'),
            ),
            IpSpec::List,
        ),
        // Single IP spec
        parse_ip_spec_inner,
    ))(input)
}

fn parse_ip_spec_inner(input: &str) -> IResult<&str, IpSpec> {
    alt((
        // "any"
        value(IpSpec::Any, tag_no_case("any")),
        // Variable: $HOME_NET
        map(
            preceded(char('$'), take_while1(is_variable_char)),
            |s: &str| IpSpec::Variable(s.to_string()),
        ),
        // CIDR: 192.168.1.0/24
        map(
            tuple((parse_ip_addr, char('/'), parse_u8)),
            |(addr, _, prefix_len)| IpSpec::Cidr { addr, prefix_len },
        ),
        // IP address
        map(parse_ip_addr, IpSpec::Addr),
    ))(input)
}

/// Parse IP address (IPv4 or IPv6)
fn parse_ip_addr(input: &str) -> IResult<&str, IpAddr> {
    map_res(
        recognize(alt((
            // IPv4: xxx.xxx.xxx.xxx
            recognize(tuple((
                digit1,
                char('.'),
                digit1,
                char('.'),
                digit1,
                char('.'),
                digit1,
            ))),
            // IPv6: simplified - just recognize hex and colons
            recognize(tuple((
                take_while1(|c: char| c.is_ascii_hexdigit() || c == ':'),
            ))),
        ))),
        |s: &str| s.parse::<IpAddr>(),
    )(input)
}

/// Parse port specification
fn parse_port_spec(input: &str) -> IResult<&str, PortSpec> {
    alt((
        // Negated port
        map(
            preceded(char('!'), parse_port_spec_inner),
            |spec| PortSpec::Not(Box::new(spec)),
        ),
        // List of ports
        map(
            delimited(
                char('['),
                separated_list1(char(','), parse_port_spec_inner),
                char(']'),
            ),
            PortSpec::List,
        ),
        // Single port spec
        parse_port_spec_inner,
    ))(input)
}

fn parse_port_spec_inner(input: &str) -> IResult<&str, PortSpec> {
    alt((
        // "any"
        value(PortSpec::Any, tag_no_case("any")),
        // Variable: $HTTP_PORTS
        map(
            preceded(char('$'), take_while1(is_variable_char)),
            |s: &str| PortSpec::Variable(s.to_string()),
        ),
        // Port range: 80:443
        map(
            separated_pair(parse_u16, char(':'), parse_u16),
            |(start, end)| PortSpec::Range(start, end),
        ),
        // Single port
        map(parse_u16, PortSpec::Port),
    ))(input)
}

/// Parse rule options in parentheses
fn parse_options(input: &str) -> IResult<&str, RuleOptions> {
    delimited(
        char('('),
        map(
            separated_list0(
                tuple((space0, char(';'), space0)),
                parse_option,
            ),
            |opts| {
                let mut options = RuleOptions::default();

                for opt in opts {
                    match opt {
                        ("msg", value) => options.msg = Some(value.to_string()),
                        ("sid", value) => {
                            options.sid = value.parse().unwrap_or(0);
                        }
                        ("rev", value) => {
                            options.rev = Some(value.parse().unwrap_or(1));
                        }
                        ("classtype", value) => {
                            options.classtype = Some(value.to_string());
                        }
                        ("priority", value) => {
                            options.priority = Some(value.parse().unwrap_or(3));
                        }
                        ("reference", value) => {
                            options.reference.push(value.to_string());
                        }
                        ("content", value) => {
                            // Parse content pattern
                            if let Ok(pattern) = parse_content_pattern(value) {
                                options.content.push(ContentMatch {
                                    pattern,
                                    nocase: false,
                                    relative: false,
                                    offset: None,
                                    depth: None,
                                    distance: None,
                                    within: None,
                                    http_location: None,
                                });
                            }
                        }
                        ("pcre", value) => {
                            options.pcre.push(value.to_string());
                        }
                        _ => {} // Ignore unknown options for now
                    }
                }

                options
            },
        ),
        tuple((space0, char(';'), space0, char(')'))),
    )(input)
}

/// Parse a single option (key:value or key:"value")
fn parse_option(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, _) = space0(input)?;
    let (input, key) = take_while1(is_option_key_char)(input)?;
    let (input, _) = space0(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = space0(input)?;

    // Value can be quoted or unquoted
    let (input, value) = alt((
        delimited(char('"'), take_until("\""), char('"')),
        take_while1(is_option_value_char),
    ))(input)?;

    let (input, _) = space0(input)?;

    Ok((input, (key, value)))
}

/// Parse content pattern (supports hex notation |XX XX| and escaped chars)
fn parse_content_pattern(input: &str) -> Result<Vec<u8>, ()> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '|' => {
                // Hex notation: |48 65 6C 6C 6F|
                let mut hex_str = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '|' {
                        chars.next();
                        break;
                    }
                    hex_str.push(chars.next().unwrap());
                }

                // Parse hex bytes
                for hex_byte in hex_str.split_whitespace() {
                    if let Ok(byte) = u8::from_str_radix(hex_byte, 16) {
                        result.push(byte);
                    }
                }
            }
            '\\' => {
                // Escaped character
                if let Some(next) = chars.next() {
                    match next {
                        'n' => result.push(b'\n'),
                        'r' => result.push(b'\r'),
                        't' => result.push(b'\t'),
                        '\\' => result.push(b'\\'),
                        '"' => result.push(b'"'),
                        _ => {
                            result.push(b'\\');
                            result.push(next as u8);
                        }
                    }
                }
            }
            _ => result.push(c as u8),
        }
    }

    Ok(result)
}

// Helper parsers

fn parse_u8(input: &str) -> IResult<&str, u8> {
    map_res(digit1, |s: &str| s.parse::<u8>())(input)
}

fn parse_u16(input: &str) -> IResult<&str, u16> {
    map_res(digit1, |s: &str| s.parse::<u16>())(input)
}

fn is_variable_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_option_key_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

fn is_option_value_char(c: char) -> bool {
    !c.is_whitespace() && c != ';' && c != ')'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_action() {
        assert_eq!(parse_action("alert"), Ok(("", RuleAction::Alert)));
        assert_eq!(parse_action("log"), Ok(("", RuleAction::Log)));
        assert_eq!(parse_action("pass"), Ok(("", RuleAction::Pass)));
        assert_eq!(parse_action("drop"), Ok(("", RuleAction::Drop)));
        assert_eq!(parse_action("ALERT"), Ok(("", RuleAction::Alert)));
    }

    #[test]
    fn test_parse_protocol() {
        assert_eq!(parse_protocol("tcp"), Ok(("", Protocol::Tcp)));
        assert_eq!(parse_protocol("udp"), Ok(("", Protocol::Udp)));
        assert_eq!(parse_protocol("icmp"), Ok(("", Protocol::Icmp)));
        assert_eq!(parse_protocol("TCP"), Ok(("", Protocol::Tcp)));
    }

    #[test]
    fn test_parse_direction() {
        assert_eq!(parse_direction("->"), Ok(("", Direction::To)));
        assert_eq!(parse_direction("<>"), Ok(("", Direction::Either)));
    }

    #[test]
    fn test_parse_ip_spec() {
        // Any
        assert_eq!(parse_ip_spec("any"), Ok(("", IpSpec::Any)));

        // Variable
        let (_, result) = parse_ip_spec("$HOME_NET").unwrap();
        assert_eq!(result, IpSpec::Variable("HOME_NET".to_string()));

        // IP address
        let (_, result) = parse_ip_spec("192.168.1.1").unwrap();
        if let IpSpec::Addr(addr) = result {
            assert_eq!(addr.to_string(), "192.168.1.1");
        } else {
            panic!("Expected IpSpec::Addr");
        }

        // CIDR
        let (_, result) = parse_ip_spec("192.168.1.0/24").unwrap();
        if let IpSpec::Cidr { addr, prefix_len } = result {
            assert_eq!(addr.to_string(), "192.168.1.0");
            assert_eq!(prefix_len, 24);
        } else {
            panic!("Expected IpSpec::Cidr");
        }
    }

    #[test]
    fn test_parse_port_spec() {
        // Any
        assert_eq!(parse_port_spec("any"), Ok(("", PortSpec::Any)));

        // Single port
        assert_eq!(parse_port_spec("80"), Ok(("", PortSpec::Port(80))));

        // Port range
        assert_eq!(
            parse_port_spec("80:443"),
            Ok(("", PortSpec::Range(80, 443)))
        );

        // Variable
        let (_, result) = parse_port_spec("$HTTP_PORTS").unwrap();
        assert_eq!(result, PortSpec::Variable("HTTP_PORTS".to_string()));
    }

    #[test]
    fn test_parse_simple_rule() {
        let input = "alert tcp any any -> any 80 (msg:\"Test\"; sid:1;)";
        let (_, rule) = parse_rule(input).unwrap();

        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.src_ip, IpSpec::Any);
        assert_eq!(rule.src_port, PortSpec::Any);
        assert_eq!(rule.direction, Direction::To);
        assert_eq!(rule.dst_ip, IpSpec::Any);
        assert_eq!(rule.dst_port, PortSpec::Port(80));
        assert_eq!(rule.options.sid, 1);
        assert_eq!(rule.options.msg, Some("Test".to_string()));
    }

    #[test]
    fn test_parse_complex_rule() {
        let input = r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; rev:1; priority:2;)"#;
        let (_, rule) = parse_rule(input).unwrap();

        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.src_ip, IpSpec::Variable("EXTERNAL_NET".to_string()));
        assert_eq!(rule.dst_ip, IpSpec::Variable("HOME_NET".to_string()));
        assert_eq!(rule.dst_port, PortSpec::Port(80));
        assert_eq!(rule.options.sid, 1000001);
        assert_eq!(rule.options.msg, Some("HTTP GET Request".to_string()));
        assert_eq!(rule.options.rev, Some(1));
        assert_eq!(rule.options.priority, Some(2));
    }

    #[test]
    fn test_parse_content_pattern() {
        // Simple text
        let pattern = parse_content_pattern("GET").unwrap();
        assert_eq!(pattern, b"GET");

        // Hex notation
        let pattern = parse_content_pattern("|48 65 6C 6C 6F|").unwrap();
        assert_eq!(pattern, b"Hello");

        // Mixed
        let pattern = parse_content_pattern("GET |0D 0A|").unwrap();
        assert_eq!(pattern, b"GET \r\n");
    }
}
