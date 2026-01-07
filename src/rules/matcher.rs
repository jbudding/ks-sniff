/// Pattern matching engine using Aho-Corasick for multi-pattern search
use super::rule::Rule;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// Pattern match result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// Pattern ID
    pub pattern_id: usize,
    /// Start position in payload
    pub start: usize,
    /// End position in payload
    pub end: usize,
    /// Matched bytes
    pub matched_bytes: Vec<u8>,
}

/// Content pattern with metadata
#[derive(Debug, Clone)]
struct ContentPattern {
    /// Pattern bytes
    pattern: Vec<u8>,
    /// Associated rule SID
    rule_sid: u32,
    /// Pattern index within the rule
    pattern_index: usize,
    /// Case-insensitive matching
    nocase: bool,
}

/// Multi-pattern matcher using Aho-Corasick algorithm
#[derive(Debug)]
pub struct PatternMatcher {
    /// Aho-Corasick automaton (case-sensitive)
    ac_sensitive: Option<AhoCorasick>,
    /// Aho-Corasick automaton (case-insensitive)
    ac_insensitive: Option<AhoCorasick>,
    /// Pattern metadata (indexed by pattern ID)
    patterns_sensitive: Vec<ContentPattern>,
    /// Pattern metadata for case-insensitive (indexed by pattern ID)
    patterns_insensitive: Vec<ContentPattern>,
    /// PCRE patterns by rule SID
    pcre_patterns: HashMap<u32, Vec<Regex>>,
    /// Statistics
    total_patterns: usize,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        Self {
            ac_sensitive: None,
            ac_insensitive: None,
            patterns_sensitive: Vec::new(),
            patterns_insensitive: Vec::new(),
            pcre_patterns: HashMap::new(),
            total_patterns: 0,
        }
    }

    /// Build matcher from a set of rules
    pub fn build_from_rules(&mut self, rules: &[Arc<Rule>]) -> Result<(), String> {
        debug!("Building pattern matcher from {} rules", rules.len());

        let mut sensitive_patterns = Vec::new();
        let mut insensitive_patterns = Vec::new();

        // Extract content patterns from rules
        for rule in rules {
            for (idx, content) in rule.options.content.iter().enumerate() {
                if content.pattern.is_empty() {
                    continue;
                }

                let pattern_meta = ContentPattern {
                    pattern: content.pattern.clone(),
                    rule_sid: rule.sid(),
                    pattern_index: idx,
                    nocase: content.nocase,
                };

                if content.nocase {
                    insensitive_patterns.push(pattern_meta);
                } else {
                    sensitive_patterns.push(pattern_meta);
                }
            }

            // Extract PCRE patterns
            if !rule.options.pcre.is_empty() {
                let mut regexes = Vec::new();
                for pcre_str in &rule.options.pcre {
                    match Self::parse_pcre(pcre_str) {
                        Ok(regex) => regexes.push(regex),
                        Err(e) => warn!(
                            "Failed to compile PCRE for rule {}: {}",
                            rule.sid(),
                            e
                        ),
                    }
                }
                if !regexes.is_empty() {
                    self.pcre_patterns.insert(rule.sid(), regexes);
                }
            }
        }

        self.total_patterns = sensitive_patterns.len() + insensitive_patterns.len();

        debug!(
            "Extracted {} patterns ({} case-sensitive, {} case-insensitive)",
            self.total_patterns,
            sensitive_patterns.len(),
            insensitive_patterns.len()
        );

        // Build Aho-Corasick automatons
        if !sensitive_patterns.is_empty() {
            let patterns: Vec<&[u8]> = sensitive_patterns
                .iter()
                .map(|p| p.pattern.as_slice())
                .collect();

            self.ac_sensitive = Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&patterns)
                    .map_err(|e| format!("Failed to build Aho-Corasick automaton: {}", e))?,
            );
            self.patterns_sensitive = sensitive_patterns;
        }

        if !insensitive_patterns.is_empty() {
            let patterns: Vec<&[u8]> = insensitive_patterns
                .iter()
                .map(|p| p.pattern.as_slice())
                .collect();

            self.ac_insensitive = Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .map_err(|e| format!("Failed to build case-insensitive automaton: {}", e))?,
            );
            self.patterns_insensitive = insensitive_patterns;
        }

        debug!("Pattern matcher built successfully");
        Ok(())
    }

    /// Search for patterns in payload and return matching rule SIDs
    pub fn find_matching_rules(&self, payload: &[u8]) -> Vec<u32> {
        let mut matching_sids = std::collections::HashSet::new();

        // Search case-sensitive patterns
        if let Some(ref ac) = self.ac_sensitive {
            for mat in ac.find_iter(payload) {
                let pattern = &self.patterns_sensitive[mat.pattern().as_usize()];
                matching_sids.insert(pattern.rule_sid);
            }
        }

        // Search case-insensitive patterns
        if let Some(ref ac) = self.ac_insensitive {
            for mat in ac.find_iter(payload) {
                let pattern = &self.patterns_insensitive[mat.pattern().as_usize()];
                matching_sids.insert(pattern.rule_sid);
            }
        }

        matching_sids.into_iter().collect()
    }

    /// Get detailed pattern matches
    pub fn find_patterns(&self, payload: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Search case-sensitive patterns
        if let Some(ref ac) = self.ac_sensitive {
            for mat in ac.find_iter(payload) {
                matches.push(PatternMatch {
                    pattern_id: mat.pattern().as_usize(),
                    start: mat.start(),
                    end: mat.end(),
                    matched_bytes: payload[mat.start()..mat.end()].to_vec(),
                });
            }
        }

        // Search case-insensitive patterns
        if let Some(ref ac) = self.ac_insensitive {
            for mat in ac.find_iter(payload) {
                matches.push(PatternMatch {
                    pattern_id: mat.pattern().as_usize() + self.patterns_sensitive.len(),
                    start: mat.start(),
                    end: mat.end(),
                    matched_bytes: payload[mat.start()..mat.end()].to_vec(),
                });
            }
        }

        matches
    }

    /// Check if payload matches PCRE patterns for a specific rule
    pub fn matches_pcre(&self, rule_sid: u32, payload: &[u8]) -> bool {
        if let Some(regexes) = self.pcre_patterns.get(&rule_sid) {
            for regex in regexes {
                if regex.is_match(payload) {
                    return true;
                }
            }
        }
        false
    }

    /// Parse Snort PCRE format: /pattern/modifiers
    fn parse_pcre(pcre_str: &str) -> Result<Regex, String> {
        let pcre_str = pcre_str.trim();

        // Remove quotes if present
        let pcre_str = pcre_str.trim_matches('"');

        // Parse /pattern/modifiers format
        if !pcre_str.starts_with('/') {
            return Err("PCRE must start with /".to_string());
        }

        let parts: Vec<&str> = pcre_str[1..].splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err("PCRE must be in /pattern/modifiers format".to_string());
        }

        let pattern = parts[0];
        let modifiers = parts[1];

        // Build regex with modifiers
        let mut regex_str = String::new();

        // Case-insensitive flag
        if modifiers.contains('i') {
            regex_str.push_str("(?i)");
        }

        // Multi-line flag
        if modifiers.contains('m') {
            regex_str.push_str("(?m)");
        }

        // Dot-all flag (. matches newline)
        if modifiers.contains('s') {
            regex_str.push_str("(?s)");
        }

        regex_str.push_str(pattern);

        Regex::new(&regex_str).map_err(|e| format!("Invalid regex: {}", e))
    }

    /// Get statistics
    pub fn stats(&self) -> MatcherStats {
        MatcherStats {
            total_patterns: self.total_patterns,
            sensitive_patterns: self.patterns_sensitive.len(),
            insensitive_patterns: self.patterns_insensitive.len(),
            pcre_patterns: self.pcre_patterns.values().map(|v| v.len()).sum(),
        }
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Pattern matcher statistics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatcherStats {
    pub total_patterns: usize,
    pub sensitive_patterns: usize,
    pub insensitive_patterns: usize,
    pub pcre_patterns: usize,
}

impl std::fmt::Display for MatcherStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Pattern Matcher Statistics:")?;
        writeln!(f, "  Total patterns: {}", self.total_patterns)?;
        writeln!(
            f,
            "  Case-sensitive patterns: {}",
            self.sensitive_patterns
        )?;
        writeln!(
            f,
            "  Case-insensitive patterns: {}",
            self.insensitive_patterns
        )?;
        writeln!(f, "  PCRE patterns: {}", self.pcre_patterns)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::{ContentMatch, Direction, IpSpec, PortSpec, Protocol, RuleAction, RuleOptions};

    #[test]
    fn test_pattern_matcher_simple() {
        let mut matcher = PatternMatcher::new();

        // Create a simple rule with content
        let mut rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        rule.options.content.push(ContentMatch {
            pattern: b"GET".to_vec(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        matcher.build_from_rules(&[Arc::new(rule)]).unwrap();

        // Test matching
        let payload = b"GET /index.html HTTP/1.1\r\n";
        let matching_sids = matcher.find_matching_rules(payload);
        assert_eq!(matching_sids.len(), 1);
        assert_eq!(matching_sids[0], 1);
    }

    #[test]
    fn test_pattern_matcher_case_insensitive() {
        let mut matcher = PatternMatcher::new();

        let mut rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        rule.options.content.push(ContentMatch {
            pattern: b"get".to_vec(),
            nocase: true, // Case-insensitive
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        matcher.build_from_rules(&[Arc::new(rule)]).unwrap();

        // Should match "GET" even though pattern is "get"
        let payload = b"GET /index.html HTTP/1.1\r\n";
        let matching_sids = matcher.find_matching_rules(payload);
        assert_eq!(matching_sids.len(), 1);
    }

    #[test]
    fn test_pattern_matcher_multiple_patterns() {
        let mut matcher = PatternMatcher::new();

        let mut rule1 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );
        rule1.options.content.push(ContentMatch {
            pattern: b"GET".to_vec(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        let mut rule2 = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            2,
        );
        rule2.options.content.push(ContentMatch {
            pattern: b"POST".to_vec(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        matcher
            .build_from_rules(&[Arc::new(rule1), Arc::new(rule2)])
            .unwrap();

        // Test GET
        let payload1 = b"GET /index.html HTTP/1.1\r\n";
        let matches = matcher.find_matching_rules(payload1);
        assert_eq!(matches.len(), 1);
        assert!(matches.contains(&1));

        // Test POST
        let payload2 = b"POST /login HTTP/1.1\r\n";
        let matches = matcher.find_matching_rules(payload2);
        assert_eq!(matches.len(), 1);
        assert!(matches.contains(&2));
    }

    #[test]
    fn test_pattern_details() {
        let mut matcher = PatternMatcher::new();

        let mut rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        rule.options.content.push(ContentMatch {
            pattern: b"Hello".to_vec(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        matcher.build_from_rules(&[Arc::new(rule)]).unwrap();

        let payload = b"Hello World";
        let matches = matcher.find_patterns(payload);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 0);
        assert_eq!(matches[0].end, 5);
        assert_eq!(matches[0].matched_bytes, b"Hello");
    }

    #[test]
    fn test_pcre_parsing() {
        // Simple pattern
        let regex = PatternMatcher::parse_pcre("/test/").unwrap();
        assert!(regex.is_match(b"this is a test"));

        // Case-insensitive
        let regex = PatternMatcher::parse_pcre("/TEST/i").unwrap();
        assert!(regex.is_match(b"this is a test"));

        // Multi-line
        let regex = PatternMatcher::parse_pcre("/^test/m").unwrap();
        assert!(regex.is_match(b"line1\ntest"));
    }

    #[test]
    fn test_matcher_stats() {
        let mut matcher = PatternMatcher::new();

        let mut rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            1,
        );

        rule.options.content.push(ContentMatch {
            pattern: b"GET".to_vec(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        rule.options.content.push(ContentMatch {
            pattern: b"post".to_vec(),
            nocase: true,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });

        matcher.build_from_rules(&[Arc::new(rule)]).unwrap();

        let stats = matcher.stats();
        assert_eq!(stats.total_patterns, 2);
        assert_eq!(stats.sensitive_patterns, 1);
        assert_eq!(stats.insensitive_patterns, 1);
    }
}
