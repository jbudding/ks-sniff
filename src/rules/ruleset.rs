/// RuleSet for managing and indexing Snort rules for fast lookup
use super::parser::parse_rule;
use super::rule::{PortSpec, Protocol, Rule};
use super::variables::Variables;
use ahash::AHashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Index key for fast rule lookup
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuleKey {
    protocol: Protocol,
    dst_port: Option<u16>,
}

/// Collection of rules with indexing for fast lookup
#[derive(Debug, Clone)]
pub struct RuleSet {
    /// All rules (keyed by SID)
    rules: AHashMap<u32, Arc<Rule>>,
    /// Index by protocol and destination port for fast lookup
    index: AHashMap<RuleKey, Vec<Arc<Rule>>>,
    /// Variables for rule expansion
    variables: Variables,
    /// Statistics
    total_rules: usize,
    enabled_rules: usize,
}

impl RuleSet {
    /// Create a new empty rule set
    pub fn new() -> Self {
        Self {
            rules: AHashMap::new(),
            index: AHashMap::new(),
            variables: Variables::new(),
            total_rules: 0,
            enabled_rules: 0,
        }
    }

    /// Get the variables instance (for configuration)
    pub fn variables_mut(&mut self) -> &mut Variables {
        &mut self.variables
    }

    /// Get the variables instance (read-only)
    pub fn variables(&self) -> &Variables {
        &self.variables
    }

    /// Add a rule to the set
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), String> {
        let sid = rule.sid();

        // Check for duplicate SID
        if self.rules.contains_key(&sid) {
            return Err(format!("Duplicate SID: {}", sid));
        }

        let rule = Arc::new(rule);

        // Index by protocol and destination port
        self.index_rule(&rule);

        // Store by SID
        self.rules.insert(sid, rule);
        self.total_rules += 1;
        self.enabled_rules += 1;

        Ok(())
    }

    /// Index a rule for fast lookup
    fn index_rule(&mut self, rule: &Arc<Rule>) {
        // Extract destination ports for indexing
        let ports = self.extract_ports(&rule.dst_port);

        if ports.is_empty() {
            // No specific port - index under None (matches any)
            let key = RuleKey {
                protocol: rule.protocol,
                dst_port: None,
            };
            self.index
                .entry(key)
                .or_insert_with(Vec::new)
                .push(rule.clone());
        } else {
            // Index under each specific port
            for port in ports {
                let key = RuleKey {
                    protocol: rule.protocol,
                    dst_port: Some(port),
                };
                self.index
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push(rule.clone());
            }
        }
    }

    /// Extract concrete port numbers from a port spec
    fn extract_ports(&self, spec: &PortSpec) -> Vec<u16> {
        match spec {
            PortSpec::Any => Vec::new(), // Matches any port
            PortSpec::Port(p) => vec![*p],
            PortSpec::Range(start, end) => {
                // For ranges, we could index all ports, but that's expensive
                // Instead, we'll just return empty and match these during filtering
                // Optimization: For small ranges (< 10 ports), expand them
                if end - start < 10 {
                    (*start..=*end).collect()
                } else {
                    Vec::new()
                }
            }
            PortSpec::List(list) => list.iter().flat_map(|s| self.extract_ports(s)).collect(),
            PortSpec::Variable(name) => {
                // Try to expand variable
                if let Some(expanded) = self.variables.get_port_var(name) {
                    expanded
                        .iter()
                        .flat_map(|s| self.extract_ports(s))
                        .collect()
                } else {
                    Vec::new()
                }
            }
            PortSpec::Not(_) => Vec::new(), // Negated ports need full matching
        }
    }

    /// Get rules that might match the given protocol and port
    pub fn get_candidate_rules(&self, protocol: Protocol, dst_port: u16) -> Vec<Arc<Rule>> {
        let mut candidates = Vec::new();

        // Get rules for specific port
        let key = RuleKey {
            protocol,
            dst_port: Some(dst_port),
        };
        if let Some(rules) = self.index.get(&key) {
            candidates.extend(rules.iter().cloned());
        }

        // Get rules for "any" port
        let any_key = RuleKey {
            protocol,
            dst_port: None,
        };
        if let Some(rules) = self.index.get(&any_key) {
            candidates.extend(rules.iter().cloned());
        }

        // Also get IP protocol rules (match any protocol)
        if protocol != Protocol::Ip {
            let ip_key = RuleKey {
                protocol: Protocol::Ip,
                dst_port: Some(dst_port),
            };
            if let Some(rules) = self.index.get(&ip_key) {
                candidates.extend(rules.iter().cloned());
            }

            let ip_any_key = RuleKey {
                protocol: Protocol::Ip,
                dst_port: None,
            };
            if let Some(rules) = self.index.get(&ip_any_key) {
                candidates.extend(rules.iter().cloned());
            }
        }

        candidates
    }

    /// Get a rule by its SID
    pub fn get_rule(&self, sid: u32) -> Option<Arc<Rule>> {
        self.rules.get(&sid).cloned()
    }

    /// Get all rules
    pub fn all_rules(&self) -> Vec<Arc<Rule>> {
        self.rules.values().cloned().collect()
    }

    /// Get number of rules
    pub fn len(&self) -> usize {
        self.total_rules
    }

    /// Check if rule set is empty
    pub fn is_empty(&self) -> bool {
        self.total_rules == 0
    }

    /// Load rules from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, String> {
        let path = path.as_ref();
        info!("Loading rules from: {:?}", path);

        let file = File::open(path)
            .map_err(|e| format!("Failed to open rule file {:?}: {}", path, e))?;

        let reader = BufReader::new(file);
        let mut loaded = 0;
        let mut skipped = 0;

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("Failed to read line {}: {}", line_num + 1, e))?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for variable definition
            if line.starts_with("var ") {
                match self.variables.parse_var_line(line) {
                    Ok(_) => debug!("Loaded variable: {}", line),
                    Err(e) => warn!("Failed to parse variable on line {}: {}", line_num + 1, e),
                }
                continue;
            }

            // Parse rule
            match parse_rule(line) {
                Ok((_, rule)) => {
                    match self.add_rule(rule) {
                        Ok(_) => loaded += 1,
                        Err(e) => {
                            warn!("Failed to add rule on line {}: {}", line_num + 1, e);
                            skipped += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse rule on line {}: {:?}", line_num + 1, e);
                    skipped += 1;
                }
            }
        }

        info!(
            "Loaded {} rules from {:?} ({} skipped)",
            loaded, path, skipped
        );
        Ok(loaded)
    }

    /// Load rules from multiple files
    pub fn load_from_files<P: AsRef<Path>>(&mut self, paths: &[P]) -> Result<usize, String> {
        let mut total = 0;

        for path in paths {
            match self.load_from_file(path) {
                Ok(count) => total += count,
                Err(e) => warn!("Failed to load rules from {:?}: {}", path.as_ref(), e),
            }
        }

        Ok(total)
    }

    /// Get statistics about the rule set
    pub fn stats(&self) -> RuleSetStats {
        let mut by_protocol = AHashMap::new();
        let mut by_action = AHashMap::new();

        for rule in self.rules.values() {
            *by_protocol.entry(rule.protocol).or_insert(0) += 1;
            *by_action
                .entry(rule.action.to_string())
                .or_insert(0) += 1;
        }

        RuleSetStats {
            total_rules: self.total_rules,
            enabled_rules: self.enabled_rules,
            by_protocol,
            by_action,
        }
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about a rule set
#[derive(Debug, Clone)]
pub struct RuleSetStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub by_protocol: AHashMap<Protocol, usize>,
    pub by_action: AHashMap<String, usize>,
}

impl std::fmt::Display for RuleSetStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Rule Set Statistics:")?;
        writeln!(f, "  Total rules: {}", self.total_rules)?;
        writeln!(f, "  Enabled rules: {}", self.enabled_rules)?;
        writeln!(f, "  By protocol:")?;
        for (proto, count) in &self.by_protocol {
            writeln!(f, "    {}: {}", proto, count)?;
        }
        writeln!(f, "  By action:")?;
        for (action, count) in &self.by_action {
            writeln!(f, "    {}: {}", action, count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::{Direction, IpSpec, RuleAction};

    #[test]
    fn test_ruleset_add() {
        let mut ruleset = RuleSet::new();

        let rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        assert!(ruleset.add_rule(rule).is_ok());
        assert_eq!(ruleset.len(), 1);
    }

    #[test]
    fn test_ruleset_duplicate_sid() {
        let mut ruleset = RuleSet::new();

        let rule1 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        let rule2 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(443),
            1, // Same SID
        );

        assert!(ruleset.add_rule(rule1).is_ok());
        assert!(ruleset.add_rule(rule2).is_err());
    }

    #[test]
    fn test_ruleset_get_candidates() {
        let mut ruleset = RuleSet::new();

        // Rule for port 80
        let rule1 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        // Rule for any port
        let rule2 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Any,
            2,
        );

        ruleset.add_rule(rule1).unwrap();
        ruleset.add_rule(rule2).unwrap();

        // Should get both rules for port 80
        let candidates = ruleset.get_candidate_rules(Protocol::Tcp, 80);
        assert_eq!(candidates.len(), 2);

        // Should get only the "any" rule for port 443
        let candidates = ruleset.get_candidate_rules(Protocol::Tcp, 443);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sid(), 2);
    }

    #[test]
    fn test_ruleset_stats() {
        let mut ruleset = RuleSet::new();

        ruleset
            .add_rule(Rule::new(
                RuleAction::Alert,
                Protocol::Tcp,
                IpSpec::Any,
                PortSpec::Any,
                Direction::To,
                IpSpec::Any,
                PortSpec::Port(80),
                1,
            ))
            .unwrap();

        ruleset
            .add_rule(Rule::new(
                RuleAction::Log,
                Protocol::Udp,
                IpSpec::Any,
                PortSpec::Any,
                Direction::To,
                IpSpec::Any,
                PortSpec::Port(53),
                2,
            ))
            .unwrap();

        let stats = ruleset.stats();
        assert_eq!(stats.total_rules, 2);
        assert_eq!(*stats.by_protocol.get(&Protocol::Tcp).unwrap(), 1);
        assert_eq!(*stats.by_protocol.get(&Protocol::Udp).unwrap(), 1);
    }
}
