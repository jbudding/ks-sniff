// Rule engine - Snort-compatible rule parsing and management
pub mod matcher;
pub mod parser;
pub mod rule;
pub mod ruleset;
pub mod variables;

pub use matcher::{MatcherStats, PatternMatch, PatternMatcher};
pub use parser::parse_rule;
pub use rule::{
    ContentMatch, Direction, FlowDirection, FlowSpec, HttpLocation, IpSpec, PortSpec, Protocol,
    Rule, RuleAction, RuleOptions, TcpFlags, ThresholdSpec, ThresholdType, TrackBy,
};
pub use ruleset::{RuleSet, RuleSetStats};
pub use variables::Variables;
