/// Variable expansion for Snort rules ($HOME_NET, $EXTERNAL_NET, etc.)
use super::rule::{IpSpec, PortSpec};
use std::collections::HashMap;
use std::net::IpAddr;

/// Variable storage for rule preprocessing
#[derive(Debug, Clone, Default)]
pub struct Variables {
    /// IP/CIDR variables
    ip_vars: HashMap<String, Vec<IpSpec>>,
    /// Port variables
    port_vars: HashMap<String, Vec<PortSpec>>,
}

impl Variables {
    /// Create a new variables instance with common defaults
    pub fn new() -> Self {
        let mut vars = Self::default();
        vars.set_defaults();
        vars
    }

    /// Set default variables (HOME_NET, EXTERNAL_NET, etc.)
    fn set_defaults(&mut self) {
        // Default HOME_NET to any (user should override)
        self.set_ip_var("HOME_NET", vec![IpSpec::Any]);

        // EXTERNAL_NET is typically !$HOME_NET
        self.set_ip_var(
            "EXTERNAL_NET",
            vec![IpSpec::Not(Box::new(IpSpec::Variable(
                "HOME_NET".to_string(),
            )))],
        );

        // Common service ports
        self.set_port_var("HTTP_PORTS", vec![PortSpec::Port(80)]);
        self.set_port_var(
            "HTTPS_PORTS",
            vec![PortSpec::Port(443), PortSpec::Port(8443)],
        );
        self.set_port_var("SSH_PORTS", vec![PortSpec::Port(22)]);
        self.set_port_var("SMTP_PORTS", vec![PortSpec::Port(25), PortSpec::Port(587)]);
        self.set_port_var("DNS_PORTS", vec![PortSpec::Port(53)]);
    }

    /// Set an IP variable
    pub fn set_ip_var(&mut self, name: &str, value: Vec<IpSpec>) {
        self.ip_vars.insert(name.to_uppercase(), value);
    }

    /// Set a port variable
    pub fn set_port_var(&mut self, name: &str, value: Vec<PortSpec>) {
        self.port_vars.insert(name.to_uppercase(), value);
    }

    /// Get an IP variable
    pub fn get_ip_var(&self, name: &str) -> Option<&Vec<IpSpec>> {
        self.ip_vars.get(&name.to_uppercase())
    }

    /// Get a port variable
    pub fn get_port_var(&self, name: &str) -> Option<&Vec<PortSpec>> {
        self.port_vars.get(&name.to_uppercase())
    }

    /// Expand an IP specification, resolving variables
    pub fn expand_ip(&self, spec: &IpSpec) -> Vec<IpSpec> {
        match spec {
            IpSpec::Variable(name) => {
                if let Some(expanded) = self.get_ip_var(name) {
                    expanded
                        .iter()
                        .flat_map(|s| self.expand_ip(s))
                        .collect()
                } else {
                    vec![spec.clone()]
                }
            }
            IpSpec::Not(inner) => {
                let expanded = self.expand_ip(inner);
                expanded
                    .into_iter()
                    .map(|s| IpSpec::Not(Box::new(s)))
                    .collect()
            }
            IpSpec::List(list) => {
                let expanded: Vec<IpSpec> = list
                    .iter()
                    .flat_map(|s| self.expand_ip(s))
                    .collect();
                if expanded.len() == 1 {
                    vec![expanded[0].clone()]
                } else {
                    vec![IpSpec::List(expanded)]
                }
            }
            _ => vec![spec.clone()],
        }
    }

    /// Expand a port specification, resolving variables
    pub fn expand_port(&self, spec: &PortSpec) -> Vec<PortSpec> {
        match spec {
            PortSpec::Variable(name) => {
                if let Some(expanded) = self.get_port_var(name) {
                    expanded
                        .iter()
                        .flat_map(|s| self.expand_port(s))
                        .collect()
                } else {
                    vec![spec.clone()]
                }
            }
            PortSpec::Not(inner) => {
                let expanded = self.expand_port(inner);
                expanded
                    .into_iter()
                    .map(|s| PortSpec::Not(Box::new(s)))
                    .collect()
            }
            PortSpec::List(list) => {
                let expanded: Vec<PortSpec> = list
                    .iter()
                    .flat_map(|s| self.expand_port(s))
                    .collect();
                if expanded.len() == 1 {
                    vec![expanded[0].clone()]
                } else {
                    vec![PortSpec::List(expanded)]
                }
            }
            _ => vec![spec.clone()],
        }
    }

    /// Parse and set variable from Snort config format
    /// Example: "var HOME_NET [192.168.1.0/24,10.0.0.0/8]"
    pub fn parse_var_line(&mut self, line: &str) -> Result<(), String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid variable definition".to_string());
        }

        if parts[0].eq_ignore_ascii_case("var") {
            let name = parts[1];
            let value = parts[2..].join(" ");

            // Try to parse as IP variable first
            if let Ok(ip_specs) = self.parse_ip_list(&value) {
                self.set_ip_var(name, ip_specs);
                Ok(())
            } else if let Ok(port_specs) = self.parse_port_list(&value) {
                self.set_port_var(name, port_specs);
                Ok(())
            } else {
                Err(format!("Failed to parse variable value: {}", value))
            }
        } else {
            Err("Not a variable definition".to_string())
        }
    }

    /// Parse IP list from string (e.g., "[192.168.1.0/24,10.0.0.0/8]")
    fn parse_ip_list(&self, value: &str) -> Result<Vec<IpSpec>, String> {
        let value = value.trim();

        // Remove brackets if present
        let value = if value.starts_with('[') && value.ends_with(']') {
            &value[1..value.len() - 1]
        } else {
            value
        };

        let mut specs = Vec::new();
        for item in value.split(',') {
            let item = item.trim();

            if item.eq_ignore_ascii_case("any") {
                specs.push(IpSpec::Any);
            } else if item.starts_with('$') {
                specs.push(IpSpec::Variable(item[1..].to_string()));
            } else if item.starts_with('!') {
                // Negated IP
                let inner = self.parse_ip_list(&item[1..])?;
                if inner.len() == 1 {
                    specs.push(IpSpec::Not(Box::new(inner[0].clone())));
                } else {
                    specs.push(IpSpec::Not(Box::new(IpSpec::List(inner))));
                }
            } else if item.contains('/') {
                // CIDR
                let parts: Vec<&str> = item.split('/').collect();
                if parts.len() == 2 {
                    let addr: IpAddr = parts[0]
                        .parse()
                        .map_err(|_| format!("Invalid IP address: {}", parts[0]))?;
                    let prefix_len: u8 = parts[1]
                        .parse()
                        .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;
                    specs.push(IpSpec::Cidr { addr, prefix_len });
                }
            } else {
                // Single IP
                let addr: IpAddr = item
                    .parse()
                    .map_err(|_| format!("Invalid IP address: {}", item))?;
                specs.push(IpSpec::Addr(addr));
            }
        }

        Ok(specs)
    }

    /// Parse port list from string (e.g., "[80,443,8080:8090]")
    fn parse_port_list(&self, value: &str) -> Result<Vec<PortSpec>, String> {
        let value = value.trim();

        // Remove brackets if present
        let value = if value.starts_with('[') && value.ends_with(']') {
            &value[1..value.len() - 1]
        } else {
            value
        };

        let mut specs = Vec::new();
        for item in value.split(',') {
            let item = item.trim();

            if item.eq_ignore_ascii_case("any") {
                specs.push(PortSpec::Any);
            } else if item.starts_with('$') {
                specs.push(PortSpec::Variable(item[1..].to_string()));
            } else if item.starts_with('!') {
                // Negated port
                let inner = self.parse_port_list(&item[1..])?;
                if inner.len() == 1 {
                    specs.push(PortSpec::Not(Box::new(inner[0].clone())));
                } else {
                    specs.push(PortSpec::Not(Box::new(PortSpec::List(inner))));
                }
            } else if item.contains(':') {
                // Port range
                let parts: Vec<&str> = item.split(':').collect();
                if parts.len() == 2 {
                    let start: u16 = parts[0]
                        .parse()
                        .map_err(|_| format!("Invalid port: {}", parts[0]))?;
                    let end: u16 = parts[1]
                        .parse()
                        .map_err(|_| format!("Invalid port: {}", parts[1]))?;
                    specs.push(PortSpec::Range(start, end));
                }
            } else {
                // Single port
                let port: u16 = item
                    .parse()
                    .map_err(|_| format!("Invalid port: {}", item))?;
                specs.push(PortSpec::Port(port));
            }
        }

        Ok(specs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_variables() {
        let vars = Variables::new();

        // Check default variables exist
        assert!(vars.get_ip_var("HOME_NET").is_some());
        assert!(vars.get_ip_var("EXTERNAL_NET").is_some());
        assert!(vars.get_port_var("HTTP_PORTS").is_some());
    }

    #[test]
    fn test_set_and_get_variables() {
        let mut vars = Variables::new();

        vars.set_ip_var(
            "TEST_NET",
            vec![IpSpec::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefix_len: 24,
            }],
        );

        assert!(vars.get_ip_var("TEST_NET").is_some());
        assert!(vars.get_ip_var("test_net").is_some()); // Case-insensitive
    }

    #[test]
    fn test_expand_ip_variable() {
        let mut vars = Variables::new();

        vars.set_ip_var(
            "HOME_NET",
            vec![IpSpec::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                prefix_len: 24,
            }],
        );

        let spec = IpSpec::Variable("HOME_NET".to_string());
        let expanded = vars.expand_ip(&spec);

        assert_eq!(expanded.len(), 1);
        if let IpSpec::Cidr { addr, prefix_len } = &expanded[0] {
            assert_eq!(addr.to_string(), "192.168.1.0");
            assert_eq!(*prefix_len, 24);
        } else {
            panic!("Expected CIDR");
        }
    }

    #[test]
    fn test_parse_ip_list() {
        let vars = Variables::new();

        let result = vars.parse_ip_list("[192.168.1.0/24,10.0.0.0/8]").unwrap();
        assert_eq!(result.len(), 2);

        let result = vars.parse_ip_list("any").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpSpec::Any);
    }

    #[test]
    fn test_parse_port_list() {
        let vars = Variables::new();

        let result = vars.parse_port_list("[80,443,8080:8090]").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], PortSpec::Port(80));
        assert_eq!(result[1], PortSpec::Port(443));
        assert_eq!(result[2], PortSpec::Range(8080, 8090));
    }

    #[test]
    fn test_parse_var_line() {
        let mut vars = Variables::new();

        vars.parse_var_line("var HOME_NET [192.168.1.0/24,10.0.0.0/8]")
            .unwrap();
        let home_net = vars.get_ip_var("HOME_NET").unwrap();
        assert_eq!(home_net.len(), 2);

        vars.parse_var_line("var HTTP_PORTS [80,8080,8000:8100]")
            .unwrap();
        let http_ports = vars.get_port_var("HTTP_PORTS").unwrap();
        assert_eq!(http_ports.len(), 3);
    }
}
